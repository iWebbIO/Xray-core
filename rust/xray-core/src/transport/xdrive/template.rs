//! HTTP-template object storage, compatible with Go's xdrive/template.go.

use std::{
    collections::{BTreeMap, HashSet},
    io,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use rand::Rng;
use regex::Regex;
use reqwest::{
    Client, Method, Response, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use tokio::{
    sync::{Mutex, Semaphore},
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;

use super::{Config, Entry, MAX_SEGMENT_BYTES, Storage, StorageFuture, wire};

const MAX_TEMPLATE_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 2 * MAX_SEGMENT_BYTES;
const ATTEMPTS: usize = 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Auth {
    #[serde(rename = "type")]
    kind: String,
    header: BTreeMap<String, String>,
    username: String,
    password: String,
    token_url: String,
    form: BTreeMap<String, String>,
    token_path: String,
    expiry_path: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Operation {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
    names_regex: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Retry {
    status: Vec<i64>,
    rate_reason: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Template {
    flatten: bool,
    concurrency: i64,
    auth: Auth,
    put: Operation,
    get: Operation,
    delete: Operation,
    list: Operation,
    retry: Retry,
}

struct Token {
    value: String,
    expiry: Instant,
}

/// Body limits are checked before allocation where Content-Length is present,
/// and again while streaming (including after gzip decoding). Oversize bodies
/// return an error; no truncation is presented as a successful operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateLimits {
    pub response_body_bytes: usize,
    pub token_body_bytes: usize,
    pub request_body_bytes: usize,
}

impl Default for TemplateLimits {
    fn default() -> Self {
        Self {
            response_body_bytes: MAX_SEGMENT_BYTES,
            token_body_bytes: MAX_TOKEN_BYTES,
            request_body_bytes: MAX_REQUEST_BYTES,
        }
    }
}

#[derive(Clone, Copy)]
struct Limits {
    body: TemplateLimits,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            body: TemplateLimits::default(),
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(8),
        }
    }
}

/// HTTP object storage using only endpoints and authentication supplied by the
/// caller's template. Drop an operation future to cancel it; `close` cancels all
/// pending requests, token fetches, semaphore waits, and retry delays.
///
/// Credentials are intentionally excluded from Debug implementations.
pub struct TemplateStorage {
    template: Template,
    names: Regex,
    client: Client,
    folder: String,
    secrets: Vec<String>,
    inflight: Semaphore,
    token: Mutex<Option<Token>>,
    cancel: CancellationToken,
    limits: Limits,
}

impl TemplateStorage {
    pub fn with_limits(mut self, limits: TemplateLimits) -> io::Result<Self> {
        if [
            limits.response_body_bytes,
            limits.token_body_bytes,
            limits.request_body_bytes,
        ]
        .iter()
        .any(|limit| *limit == 0 || *limit > isize::MAX as usize)
        {
            return Err(invalid(
                "XDRIVE template limits must be nonzero and fit memory address space",
            ));
        }
        self.limits.body = limits;
        Ok(self)
    }

    pub fn new(config: &Config) -> io::Result<Self> {
        // No ambient HTTP proxy or cookie credentials. Endpoint/userinfo,
        // template headers, Basic auth, and OAuth forms are explicit config.
        let client = Client::builder()
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(request_error)?;
        Self::with_client(config, client)
    }

    /// Inject a client with an explicitly selected TLS trust/redirect policy.
    /// Custom Xray TLS/REALITY fronting is not implemented by this adapter.
    pub fn with_client(config: &Config, client: Client) -> io::Result<Self> {
        let value = config
            .template
            .as_ref()
            .ok_or_else(|| invalid("XDRIVE template is missing"))?;
        let serialized =
            serde_json::to_vec(value).map_err(|_| invalid("invalid XDRIVE template"))?;
        if serialized.len() > MAX_TEMPLATE_BYTES {
            return Err(invalid("XDRIVE template exceeds 1 MiB"));
        }
        let template: Template = serde_json::from_slice(&serialized)
            .map_err(|_| invalid("invalid XDRIVE template fields"))?;
        for operation in [
            &template.put,
            &template.get,
            &template.delete,
            &template.list,
        ] {
            if operation.url.is_empty() {
                return Err(invalid(
                    "XDRIVE template requires put, get, delete and list URLs",
                ));
            }
            method(operation)?;
            for name in operation.headers.keys() {
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| invalid("invalid XDRIVE template header name"))?;
            }
        }
        if template.list.names_regex.is_empty() {
            return Err(invalid("XDRIVE template list requires namesRegex"));
        }
        let names = Regex::new(&template.list.names_regex)
            .map_err(|_| invalid("invalid XDRIVE namesRegex"))?;
        if names.captures_len() < 2 {
            return Err(invalid("XDRIVE namesRegex requires a capture group"));
        }
        match template.auth.kind.as_str() {
            "" | "none" | "static" | "basic" => {}
            "oauth2" => {
                endpoint(&template.auth.token_url)?;
            }
            _ => return Err(invalid("unsupported XDRIVE template auth type")),
        }
        for name in template.auth.header.keys() {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid("invalid XDRIVE auth header name"))?;
        }
        let concurrency = if template.concurrency <= 0 {
            32
        } else {
            template.concurrency.min(256) as usize
        };
        Ok(Self {
            template,
            names,
            client,
            folder: config.remote_folder.clone(),
            secrets: config.secrets.clone(),
            inflight: Semaphore::new(concurrency),
            token: Mutex::new(None),
            cancel: CancellationToken::new(),
            limits: Limits::default(),
        })
    }

    fn variables(&self) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::from([("folder".to_owned(), self.folder.clone())]);
        for (index, secret) in self.secrets.iter().enumerate() {
            vars.insert(format!("secret{index}"), secret.clone());
        }
        vars
    }

    fn named_variables(&self, name: &str, key: &str) -> BTreeMap<String, String> {
        let mut vars = self.variables();
        vars.insert(
            key.to_owned(),
            if self.template.flatten {
                wire::flatten(name)
            } else {
                name.to_owned()
            },
        );
        vars
    }

    async fn auth_headers(&self, vars: &mut BTreeMap<String, String>) -> io::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        match self.template.auth.kind.as_str() {
            "" | "none" => {}
            "static" | "oauth2" => {
                if self.template.auth.kind == "oauth2" {
                    vars.insert("token".to_owned(), self.access_token().await?);
                }
                insert_headers(&mut headers, &self.template.auth.header, vars)?;
            }
            "basic" => {
                let user = substitute(&self.template.auth.username, vars);
                let pass = substitute(&self.template.auth.password, vars);
                let value = format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")));
                let mut value = HeaderValue::from_str(&value)
                    .map_err(|_| invalid("invalid XDRIVE Basic credentials"))?;
                value.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
            _ => return Err(invalid("unsupported XDRIVE template auth type")),
        }
        Ok(headers)
    }

    async fn access_token(&self) -> io::Result<String> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|token| token.expiry > Instant::now())
        {
            return Ok(token.value.clone());
        }
        let vars = self.variables();
        // Go deliberately sends these user-supplied form values literally;
        // applying URL encoding here would change pre-escaped credentials.
        let body = self
            .template
            .auth
            .form
            .iter()
            .map(|(key, value)| format!("{key}={}", substitute(value, &vars)))
            .collect::<Vec<_>>()
            .join("&");
        if body.len() > self.limits.body.request_body_bytes {
            return Err(invalid("XDRIVE OAuth form exceeds request limit"));
        }
        let permit = self.inflight.acquire().await.map_err(|_| cancelled())?;
        let response = self
            .client
            .post(endpoint(&self.template.auth.token_url)?)
            .timeout(REQUEST_TIMEOUT)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(request_error)?;
        let status = response.status().as_u16();
        let payload = read_limited(response, self.limits.body.token_body_bytes).await?;
        drop(permit);
        if status != 200 {
            return Err(status_error("OAuth token", status));
        }
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| invalid_data("XDRIVE token response is not JSON"))?;
        let path = if self.template.auth.token_path.is_empty() {
            "access_token"
        } else {
            &self.template.auth.token_path
        };
        let token = json_at(&value, path)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_data("XDRIVE token response has no configured access token"))?
            .to_owned();
        let mut lifetime = json_at(&value, &self.template.auth.expiry_path)
            .and_then(serde_json::Value::as_f64)
            .filter(|value| *value >= 1.0 && value.is_finite())
            .map_or(3600, |value| value as u64);
        if lifetime > 60 {
            lifetime -= 60;
        }
        let expiry = Instant::now()
            .checked_add(Duration::from_secs(lifetime))
            .ok_or_else(|| invalid_data("XDRIVE token expiry exceeds clock range"))?;
        *cached = Some(Token {
            value: token.clone(),
            expiry,
        });
        Ok(token)
    }

    async fn invalidate_token(&self, used: Option<&String>) {
        let mut cached = self.token.lock().await;
        if cached
            .as_ref()
            .is_some_and(|token| Some(&token.value) == used)
        {
            *cached = None;
        }
    }

    fn retryable(&self, status: u16, payload: &[u8]) -> bool {
        self.template.retry.status.contains(&i64::from(status))
            || (status == 403
                && !self.template.retry.rate_reason.is_empty()
                && serde_json::from_slice::<serde_json::Value>(payload)
                    .ok()
                    .and_then(|value| {
                        json_at(&value, &self.template.retry.rate_reason)
                            .and_then(serde_json::Value::as_str)
                            .map(|value| !value.is_empty())
                    })
                    .unwrap_or(false))
    }

    async fn execute(
        &self,
        operation: &Operation,
        mut vars: BTreeMap<String, String>,
        body: Option<Vec<u8>>,
    ) -> io::Result<(u16, Vec<u8>)> {
        if body
            .as_ref()
            .is_some_and(|body| body.len() > self.limits.body.request_body_bytes)
        {
            return Err(invalid("XDRIVE request body exceeds limit"));
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(cancelled()),
            result = self.attempts(operation, &mut vars, body) => result,
        }
    }

    async fn attempts(
        &self,
        operation: &Operation,
        vars: &mut BTreeMap<String, String>,
        body: Option<Vec<u8>>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let mut backoff = self.limits.initial_backoff;
        let mut last_error = io::Error::other("XDRIVE template request failed");
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                let millis = backoff.as_millis().min(u128::from(u64::MAX)) as u64;
                let half = millis / 2;
                let delay = if half == 0 {
                    backoff
                } else {
                    Duration::from_millis(rand::thread_rng().gen_range(half..millis))
                };
                time::sleep(delay).await;
                backoff = backoff.saturating_mul(2).min(self.limits.max_backoff);
            }
            let mut headers = match self.auth_headers(vars).await {
                Ok(headers) => headers,
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidInput
                        || error.kind() == io::ErrorKind::InvalidData =>
                {
                    return Err(error);
                }
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            insert_headers(&mut headers, &operation.headers, vars)?;
            let url = endpoint(&substitute(&operation.url, vars))?;
            let mut request = self
                .client
                .request(method(operation)?, url)
                .headers(headers)
                .timeout(REQUEST_TIMEOUT);
            if let Some(body) = &body {
                request = request.body(body.clone());
            }
            // The concurrency permit covers the complete body, not merely the
            // headers. Cancelling the enclosing future drops both immediately.
            let permit = self.inflight.acquire().await.map_err(|_| cancelled())?;
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => {
                    last_error = request_error(error);
                    if last_error.kind() == io::ErrorKind::InvalidInput {
                        return Err(last_error);
                    }
                    continue;
                }
            };
            let status = response.status().as_u16();
            let payload = match read_limited(response, self.limits.body.response_body_bytes).await {
                Ok(payload) => payload,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            drop(permit);
            if status == 401 && self.template.auth.kind == "oauth2" {
                self.invalidate_token(vars.get("token")).await;
                last_error = io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "XDRIVE service rejected OAuth token",
                );
                continue;
            }
            if self.retryable(status, &payload) {
                last_error = status_error("request", status);
                continue;
            }
            return Ok((status, payload));
        }
        Err(last_error)
    }
}

impl Storage for TemplateStorage {
    fn put<'a>(&'a self, name: &'a str, data: Vec<u8>) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            if data.len() > MAX_SEGMENT_BYTES {
                return Err(invalid("XDRIVE object exceeds maximum segment size"));
            }
            let mut vars = self.named_variables(name, "name");
            let body = if self.template.put.body.is_empty() {
                data
            } else {
                vars.insert("data".to_owned(), STANDARD.encode(data));
                substitute(&self.template.put.body, &vars).into_bytes()
            };
            let (status, _) = self.execute(&self.template.put, vars, Some(body)).await?;
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(status_error("put", status))
            }
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> StorageFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let (status, payload) = self
                .execute(&self.template.get, self.named_variables(name, "name"), None)
                .await?;
            if (200..300).contains(&status) {
                Ok(payload)
            } else {
                Err(status_error("get", status))
            }
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            let (status, _) = self
                .execute(
                    &self.template.delete,
                    self.named_variables(name, "name"),
                    None,
                )
                .await?;
            if status == 404 || (200..300).contains(&status) {
                Ok(())
            } else {
                Err(status_error("delete", status))
            }
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> StorageFuture<'a, Vec<Entry>> {
        Box::pin(async move {
            let vars = self.named_variables(prefix, "prefix");
            let flat = vars["prefix"].clone();
            let (status, payload) = self.execute(&self.template.list, vars, None).await?;
            if status == 404 {
                return Ok(Vec::new());
            }
            if !(200..300).contains(&status) {
                return Err(status_error("list", status));
            }
            let payload = String::from_utf8_lossy(&payload);
            let want = format!("{flat}~");
            let mut seen = HashSet::new();
            let mut entries = Vec::new();
            for capture in self.names.captures_iter(&payload) {
                let name = capture.get(1).map_or("", |name| name.as_str());
                let name = if self.template.flatten {
                    let Some(rest) = name.strip_prefix(&want).filter(|rest| !rest.is_empty())
                    else {
                        continue;
                    };
                    let rest = rest.split('~').next().unwrap_or_default();
                    if !seen.insert(rest.to_owned()) {
                        continue;
                    }
                    rest
                } else {
                    name
                };
                entries.push(Entry {
                    name: name.to_owned(),
                    inline: None,
                });
            }
            Ok(entries)
        })
    }
    fn close(&self) -> StorageFuture<'_, ()> {
        self.cancel.cancel();
        self.inflight.close();
        Box::pin(async { Ok(()) })
    }
}

fn substitute(template: &str, vars: &BTreeMap<String, String>) -> String {
    // Go iterates a map here, so recursive substitutions were order-dependent.
    // BTreeMap gives a stable order while preserving raw replacement semantics.
    let mut value = template.to_owned();
    for (key, replacement) in vars {
        value = value.replace(&format!("{{{key}}}"), replacement);
    }
    value
}

fn insert_headers(
    target: &mut HeaderMap,
    headers: &BTreeMap<String, String>,
    vars: &BTreeMap<String, String>,
) -> io::Result<()> {
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("invalid XDRIVE header name"))?;
        let mut value = HeaderValue::from_str(&substitute(value, vars))
            .map_err(|_| invalid("invalid XDRIVE header value"))?;
        value.set_sensitive(true);
        target.insert(name, value);
    }
    Ok(())
}

fn method(operation: &Operation) -> io::Result<Method> {
    Method::from_bytes(if operation.method.is_empty() {
        b"GET"
    } else {
        operation.method.as_bytes()
    })
    .map_err(|_| invalid("invalid XDRIVE HTTP method"))
}

fn endpoint(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid("invalid XDRIVE HTTP URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(invalid("XDRIVE template requires an HTTP(S) URL"));
    }
    Ok(url)
}

fn json_at<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut node = value;
    for key in path.split('.') {
        node = node.as_object()?.get(key)?;
    }
    Some(node)
}

async fn read_limited(mut response: Response, limit: usize) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(invalid_data("XDRIVE HTTP response exceeds size limit"));
    }
    let mut output = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_error)? {
        if chunk.len() > limit.saturating_sub(output.len()) {
            return Err(invalid_data("XDRIVE HTTP response exceeds size limit"));
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

fn request_error(error: reqwest::Error) -> io::Error {
    let kind = if error.is_timeout() {
        io::ErrorKind::TimedOut
    } else if error.is_builder() {
        io::ErrorKind::InvalidInput
    } else {
        io::ErrorKind::Other
    };
    // Request URLs and response bodies may contain configured secrets.
    io::Error::new(kind, error.without_url())
}

fn status_error(operation: &str, status: u16) -> io::Error {
    let kind = match status {
        404 => io::ErrorKind::NotFound,
        401 | 403 => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("XDRIVE {operation} returned HTTP {status}"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "XDRIVE template storage closed")
}

#[cfg(test)]
mod tests;
