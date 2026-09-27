use std::{collections::BTreeMap, sync::Arc};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use super::*;

struct Reply {
    raw: Vec<u8>,
    wait_for_close: bool,
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    response: oneshot::Sender<Reply>,
    closed: oneshot::Receiver<()>,
}

impl Request {
    fn reply(self, status: u16, body: &[u8]) -> oneshot::Receiver<()> {
        let mut raw = format!(
            "HTTP/1.1 {status} Scripted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        self.raw(raw, false)
    }
    fn raw(self, raw: Vec<u8>, wait_for_close: bool) -> oneshot::Receiver<()> {
        self.response
            .send(Reply {
                raw,
                wait_for_close,
            })
            .unwrap_or_else(|_| panic!("HTTP request cancelled before scripted response"));
        self.closed
    }
}

struct Server {
    url: String,
    requests: mpsc::Receiver<Request>,
    task: JoinHandle<()>,
}

impl Server {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, requests) = mpsc::channel(32);
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        let tx = tx.clone();
                        handlers.spawn(async move {
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") {
                                if header.len() > 65536 { panic!("oversized request header"); }
                                let byte = match socket.read_u8().await { Ok(byte) => byte, Err(_) => return };
                                header.push(byte);
                            }
                            let header = String::from_utf8(header).unwrap();
                            let mut lines = header.split("\r\n");
                            let first: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                            let method = first[0].to_owned();
                            let target = first[1].to_owned();
                            let mut headers = BTreeMap::new();
                            for line in lines.filter(|line| !line.is_empty()) {
                                let (name, value) = line.split_once(':').unwrap();
                                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                            }
                            let length = headers.get("content-length").map_or(0, |value| value.parse::<usize>().unwrap());
                            let mut body = vec![0; length];
                            socket.read_exact(&mut body).await.unwrap();
                            let (response, rx) = oneshot::channel();
                            let (closed_tx, closed) = oneshot::channel();
                            if tx.send(Request { method, target, headers, body, response, closed }).await.is_err() { return; }
                            if let Ok(reply) = rx.await {
                                let _ = socket.write_all(&reply.raw).await;
                                if reply.wait_for_close { let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail).await; }
                            }
                            let _ = socket.shutdown().await;
                            let _ = closed_tx.send(());
                        });
                    },
                    result = handlers.join_next(), if !handlers.is_empty() => { result.unwrap().unwrap(); },
                }
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }
    async fn next(&mut self) -> Request {
        timeout(Duration::from_secs(3), self.requests.recv())
            .await
            .expect("no HTTP request arrived")
            .unwrap()
    }
    fn config(&self) -> Config {
        Config {
            service: "template".to_owned(),
            remote_folder: "bucket".to_owned(),
            secrets: vec!["given-secret".to_owned()],
            template: Some(json!({
                "put": {"method":"PUT", "url":format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "get": {"url":format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "delete": {"method":"DELETE", "url":format!("{}/objects/{{folder}}/{{name}}", self.url)},
                "list": {"url":format!("{}/list/{{folder}}/{{prefix}}", self.url), "namesRegex":"<name>([^<]+)</name>"}
            })),
            ..Config::default()
        }
    }
    fn storage(&self) -> TemplateStorage {
        self.storage_config(self.config())
    }
    fn storage_config(&self, config: Config) -> TemplateStorage {
        let mut storage = TemplateStorage::new(&config).unwrap();
        storage.limits.initial_backoff = Duration::from_millis(2);
        storage.limits.max_backoff = Duration::from_millis(2);
        storage
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn template_static_auth_headers_put_body_and_flattened_listing_match_go() {
    let mut server = Server::new().await;
    let mut config = server.config();
    let template = config.template.as_mut().unwrap();
    template["flatten"] = json!(true);
    template["auth"] = json!({"type":"static", "header":{"Authorization":"Bearer {secret0}", "X-Override":"auth"}});
    template["put"]["headers"] =
        json!({"X-Override":"operation", "Content-Type":"application/json"});
    template["put"]["body"] =
        json!("{\"name\":\"{name}\",\"data\":\"{data}\",\"unknown\":\"{unknown}\"}");
    let storage = Arc::new(server.storage_config(config));
    let put = {
        let storage = storage.clone();
        tokio::spawn(async move {
            storage
                .put("streams/abc/c2s/000000000.seg", vec![0, 255, 7])
                .await
        })
    };
    let request = server.next().await;
    assert_eq!(request.method, "PUT");
    assert_eq!(
        request.target,
        "/objects/bucket/streams~abc~c2s~000000000.seg"
    );
    assert_eq!(request.headers["authorization"], "Bearer given-secret");
    assert_eq!(request.headers["x-override"], "operation");
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        json!({"name":"streams~abc~c2s~000000000.seg","data":"AP8H","unknown":"{unknown}"})
    );
    drop(request.reply(201, b"created"));
    put.await.unwrap().unwrap();
    let list = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.list("streams/abc").await })
    };
    let request = server.next().await;
    assert_eq!(request.target, "/list/bucket/streams~abc");
    drop(request.reply(200, b"<name>streams~abc~c2s~000.seg</name><name>streams~abc~c2s~001.seg</name><name>streams~abc~s2c~000.end</name><name>other~abc~x</name><name>streams~abc~</name>"));
    let entries = list.await.unwrap().unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["c2s", "s2c"]
    );
    assert!(entries.iter().all(|entry| entry.inline.is_none()));
}

#[tokio::test]
async fn basic_auth_raw_upload_and_get_delete_list_error_mapping_match_go() {
    let mut server = Server::new().await;
    let mut config = server.config();
    let template = config.template.as_mut().unwrap();
    template["auth"] = json!({"type":"basic", "username":"user", "password":"{secret0}"});
    template["get"]["body"] = json!("ignored body");
    // Exercise the public Config factory as well as the provider itself.
    let storage = config.storage().await.unwrap();
    let put = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.put("file", b"raw bytes".to_vec()).await })
    };
    let request = server.next().await;
    assert_eq!(request.body, b"raw bytes");
    assert_eq!(
        request.headers["authorization"],
        format!("Basic {}", STANDARD.encode("user:given-secret"))
    );
    drop(request.reply(204, b""));
    put.await.unwrap().unwrap();
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("missing").await })
    };
    let request = server.next().await;
    assert_eq!(request.method, "GET");
    assert!(request.body.is_empty());
    drop(request.reply(404, b"sensitive service detail"));
    let error = get.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(!error.to_string().contains("sensitive"));
    let delete = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.delete("missing").await })
    };
    let request = server.next().await;
    assert_eq!(request.method, "DELETE");
    drop(request.reply(404, b""));
    delete.await.unwrap().unwrap();
    let list = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.list("missing").await })
    };
    drop(server.next().await.reply(404, b""));
    assert!(list.await.unwrap().unwrap().is_empty());
}

#[tokio::test]
async fn oauth_uses_explicit_raw_form_refreshes_rejected_token_and_caches_new_token() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.secrets[0] = "pre%2Bescaped".to_owned();
    config.template.as_mut().unwrap()["auth"] = json!({"type":"oauth2", "tokenUrl":format!("{}/token", server.url), "form":{"grant_type":"refresh_token","refresh_token":"{secret0}"}, "tokenPath":"result.token", "expiryPath":"result.expires", "header":{"Authorization":"Bearer {token}"}});
    let storage = Arc::new(server.storage_config(config));
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("item").await })
    };
    let request = server.next().await;
    assert_eq!(
        (request.method.as_str(), request.target.as_str()),
        ("POST", "/token")
    );
    assert_eq!(
        request.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        request.body,
        b"grant_type=refresh_token&refresh_token=pre%2Bescaped"
    );
    assert!(!request.headers.contains_key("authorization"));
    drop(request.reply(200, br#"{"result":{"token":"old","expires":3600}}"#));
    let request = server.next().await;
    assert_eq!(request.headers["authorization"], "Bearer old");
    drop(request.reply(401, b"expired"));
    let request = server.next().await;
    assert_eq!(request.target, "/token");
    drop(request.reply(200, br#"{"result":{"token":"new","expires":3600}}"#));
    let request = server.next().await;
    assert_eq!(request.headers["authorization"], "Bearer new");
    drop(request.reply(200, b"payload"));
    assert_eq!(get.await.unwrap().unwrap(), b"payload");
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("again").await })
    };
    let request = server.next().await;
    assert_eq!(request.target, "/objects/bucket/again");
    assert_eq!(request.headers["authorization"], "Bearer new");
    drop(request.reply(200, b"cached"));
    assert_eq!(get.await.unwrap().unwrap(), b"cached");
}

#[tokio::test]
async fn configured_status_and_dotted_rate_reason_retry_but_exhaust_at_eight_attempts() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["retry"] =
        json!({"status":[429,503],"rateReason":"error.reason"});
    let storage = Arc::new(server.storage_config(config));
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("eventual").await })
    };
    drop(server.next().await.reply(429, b""));
    drop(
        server
            .next()
            .await
            .reply(403, br#"{"error":{"reason":"quota"}}"#),
    );
    drop(server.next().await.reply(200, b"ok"));
    assert_eq!(get.await.unwrap().unwrap(), b"ok");
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("unavailable").await })
    };
    for _ in 0..ATTEMPTS {
        drop(server.next().await.reply(503, b""));
    }
    assert!(get.await.unwrap().unwrap_err().to_string().contains("503"));
    assert!(
        timeout(Duration::from_millis(15), server.requests.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bounded_content_length_chunked_and_request_bodies_fail_without_clipping() {
    let mut server = Server::new().await;
    let storage = Arc::new(
        server
            .storage()
            .with_limits(TemplateLimits {
                response_body_bytes: 4,
                request_body_bytes: 4,
                token_body_bytes: 16,
            })
            .unwrap(),
    );
    assert_eq!(
        storage
            .put("large", b"12345".to_vec())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    for raw in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\n123\r\n2\r\n45\r\n0\r\n\r\n".to_vec(),
    ] {
        let get = { let storage = storage.clone(); tokio::spawn(async move { storage.get("large").await }) };
        drop(server.next().await.raw(raw, false));
        let error = get.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("size limit"));
    }
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("fits").await })
    };
    drop(server.next().await.reply(200, b"1234"));
    assert_eq!(get.await.unwrap().unwrap(), b"1234");
}

#[tokio::test]
async fn token_body_limit_rejects_oversize_before_an_authenticated_operation() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["auth"] = json!({"type":"oauth2","tokenUrl":format!("{}/token", server.url),"header":{"Authorization":"Bearer {token}"}});
    let storage = Arc::new(
        server
            .storage_config(config)
            .with_limits(TemplateLimits {
                token_body_bytes: 4,
                ..TemplateLimits::default()
            })
            .unwrap(),
    );
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("item").await })
    };
    let request = server.next().await;
    assert_eq!(request.target, "/token");
    drop(request.reply(200, br#"{"access_token":"secret"}"#));
    assert_eq!(
        get.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(
        timeout(Duration::from_millis(15), server.requests.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn gzip_response_limit_counts_decoded_bytes() {
    let mut server = Server::new().await;
    let storage = Arc::new(
        server
            .storage()
            .with_limits(TemplateLimits {
                response_body_bytes: 64,
                ..TemplateLimits::default()
            })
            .unwrap(),
    );
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("compressed").await })
    };
    let request = server.next().await;
    // Gzip-compressed 1024 'x' bytes: small on the wire, over the decoded limit.
    let compressed = [
        31, 139, 8, 0, 0, 0, 0, 0, 2, 10, 171, 168, 24, 5, 163, 96, 20, 140, 84, 0, 0, 99, 240,
        215, 72, 0, 4, 0, 0,
    ];
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", compressed.len()).into_bytes();
    response.extend_from_slice(&compressed);
    drop(request.raw(response, false));
    assert_eq!(
        get.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn close_cancels_streaming_response_and_waiting_concurrency_slot() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["concurrency"] = json!(1);
    let storage = Arc::new(server.storage_config(config));
    let first = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("first").await })
    };
    let closed = server.next().await.raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx".to_vec(),
        true,
    );
    let second = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("second").await })
    };
    assert!(
        timeout(Duration::from_millis(20), server.requests.recv())
            .await
            .is_err()
    );
    storage.close().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    timeout(Duration::from_secs(1), closed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        storage.get("after-close").await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn dropping_operation_releases_concurrency_permit_and_closes_response() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["concurrency"] = json!(1);
    let storage = Arc::new(server.storage_config(config));
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("cancel").await })
    };
    let closed = server.next().await.raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx".to_vec(),
        true,
    );
    get.abort();
    assert!(get.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(1), closed)
        .await
        .unwrap()
        .unwrap();
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("next").await })
    };
    drop(server.next().await.reply(200, b"ok"));
    assert_eq!(get.await.unwrap().unwrap(), b"ok");
}

#[tokio::test]
async fn close_interrupts_retry_delay() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["retry"] = json!({"status":[503]});
    let mut storage = server.storage_config(config);
    storage.limits.initial_backoff = Duration::from_secs(30);
    let storage = Arc::new(storage);
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("retry").await })
    };
    drop(server.next().await.reply(503, b""));
    assert!(
        timeout(Duration::from_millis(20), server.requests.recv())
            .await
            .is_err()
    );
    storage.close().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), get)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn cancelling_oauth_body_releases_token_lock_for_the_next_request() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["auth"] = json!({"type":"oauth2", "tokenUrl":format!("{}/token", server.url), "header":{"Authorization":"Bearer {token}"}});
    let storage = Arc::new(server.storage_config(config));
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("cancel-token").await })
    };
    let request = server.next().await;
    assert_eq!(request.target, "/token");
    let closed = request.raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".to_vec(),
        true,
    );
    get.abort();
    assert!(get.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(1), closed)
        .await
        .unwrap()
        .unwrap();
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("retry-token").await })
    };
    let request = server.next().await;
    assert_eq!(request.target, "/token");
    drop(request.reply(200, br#"{"access_token":"usable"}"#));
    let request = server.next().await;
    assert_eq!(request.headers["authorization"], "Bearer usable");
    drop(request.reply(200, b"ok"));
    assert_eq!(get.await.unwrap().unwrap(), b"ok");
}

#[tokio::test]
async fn redirects_do_not_leak_sensitive_template_headers_to_other_hosts() {
    let mut source = Server::new().await;
    let mut destination = Server::new().await;
    let mut config = source.config();
    config.template.as_mut().unwrap()["auth"] = json!({"type":"static","header":{"Authorization":"Bearer given-secret","Cookie":"private=1"}});
    let storage = Arc::new(source.storage_config(config));
    let get = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.get("redirect").await })
    };
    let request = source.next().await;
    assert_eq!(request.headers["authorization"], "Bearer given-secret");
    let destination_url = destination.url.replace("127.0.0.1", "localhost");
    drop(request.raw(format!("HTTP/1.1 302 Found\r\nLocation: {destination_url}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(), false));
    let request = destination.next().await;
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("cookie"));
    drop(request.reply(200, b"redirected"));
    assert_eq!(get.await.unwrap().unwrap(), b"redirected");
}

#[tokio::test]
async fn invalid_template_auth_regex_headers_and_limits_are_rejected() {
    let server = Server::new().await;
    for (key, value) in [
        ("auth", json!({"type":"ambient"})),
        ("get", json!({"url":"", "method":"GET"})),
        (
            "get",
            json!({"url":"http://example.invalid/", "method":"bad method"}),
        ),
        (
            "list",
            json!({"url":"http://example.invalid/", "namesRegex":"no-capture"}),
        ),
    ] {
        let mut config = server.config();
        config.template.as_mut().unwrap()[key] = value;
        assert!(TemplateStorage::new(&config).is_err());
    }
    let mut config = server.config();
    config.template.as_mut().unwrap()["get"]["headers"] =
        json!({"X-Injected":"value\r\ninjected: yes"});
    let storage = server.storage_config(config);
    assert_eq!(
        storage.get("never-sent").await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(
        server
            .storage()
            .with_limits(TemplateLimits {
                response_body_bytes: 0,
                ..TemplateLimits::default()
            })
            .is_err()
    );
}

#[tokio::test]
async fn unflattened_list_preserves_capture_order_duplicates_and_empty_capture() {
    let mut server = Server::new().await;
    let mut config = server.config();
    config.template.as_mut().unwrap()["list"]["namesRegex"] = json!("<name>([^<]*)</name>");
    let storage = Arc::new(server.storage_config(config));
    let list = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.list("prefix").await })
    };
    drop(server.next().await.reply(
        200,
        b"<name>second</name><name>first</name><name>second</name><name></name>",
    ));
    assert_eq!(
        list.await
            .unwrap()
            .unwrap()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["second", "first", "second", ""]
    );
}
