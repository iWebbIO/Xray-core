# Ordinary observatory integration

The owned modules compile ordinary Go JSON and build a real observation provider
and scheduler. They do not modify the root configuration or private Dispatcher.
The lead should apply the following root wiring in `config.rs` and `runtime.rs`.

1. Add `pub mod observatory;` in `config.rs`, and add
   `pub observatory: Option<observatory::ObservatoryConfig>` to `Config`.
   Keep `deny_unknown_fields`; do not add a permissive `burstObservatory` field.
   Add `observatory: Option<observatory::CompiledObservatory>` to
   `ValidatedConfig`. During `Config::compile`, use
   `self.observatory.as_ref().map(observatory::ObservatoryConfig::compile).transpose()?`
   and store the result. Compilation validates the URL and TLS trust without
   dialing or resolving names. Only the source fields `subjectSelector`,
   `probeURL`, string `probeInterval`, and `enableConcurrency` are accepted.

2. Implement `features::observatory::runtime::RoutedProbeDialer` on a root-owned
   adapter holding `Arc<Dispatcher>`. Its exact signature is:

   ```rust,ignore
   #[tonic::async_trait]
   impl RoutedProbeDialer for ObservatoryDialer {
       async fn connect_outbound(
           &self,
           outbound_tag: &str,
           target: &Destination,
       ) -> anyhow::Result<BoxStream> {
           let dispatcher = &self.0;
           let index = dispatcher.outbound_tags.iter()
               .position(|tag| tag == outbound_tag)
               .context("unknown observatory outbound")?;
           let outbound = dispatcher.outbounds.get(index)
               .context("observatory outbound unavailable")?;
           if matches!(outbound, Outbound::Api | Outbound::Blackhole { .. }) {
               anyhow::bail!("selected outbound cannot carry observatory TCP probes");
           }
           let transport = dispatcher.transports.get(index)
               .context("observatory outbound transport unavailable")?;
           let resolved = if let Outbound::Freedom { redirect, final_rules } = outbound {
               // `observatory` is the internal request origin. Explicit final
               // rules apply; this is not an unauthenticated proxy-user origin.
               match final_rules.admit(
                   "observatory", redirect.as_ref().unwrap_or(target),
               ).await? {
                   protocol::freedom::Admission::Allowed(addresses) => addresses,
                   protocol::freedom::Admission::Blocked(_) => {
                       anyhow::bail!("freedom final rule blocked observatory target");
                   }
               }
           } else {
               None
           };
           let (stream, _) = establish(
               outbound, transport, target, resolved.as_deref(),
           ).await?;
           Ok(stream)
       }
   }
   ```

   Define `struct ObservatoryDialer(Arc<Dispatcher>);` and import `anyhow::Context`
   and `RoutedProbeDialer` in the root module. If the admission path evolves,
   share/refactor that routine instead of maintaining a second divergent policy
   branch; it must not be bypassed with `OutboundTransport::connect`. All proxy
   handshakes and transport security remain in `establish`. The observer itself
   adds HTTPS for the probe URL over the returned stream. Return a raw stream,
   not one already TLS-wrapped to the probe origin. Tag existence does not imply
   dial support: capability failures must remain errors and become failed real
   observations. Cancellation must drop pending network work; no detached dials.

3. After constructing the dispatcher, but before starting accept tasks, create
   the optional runtime (the current Dispatcher tag registry is immutable):

   ```rust,ignore
   let observatory = compiled_observatory
       .map(|compiled| {
           ObservatoryRuntime::new(
               compiled,
               dispatcher.outbound_tags.clone(),
               Arc::new(ObservatoryDialer(dispatcher.clone())),
           ).map(Arc::new)
       })
       .transpose()?;
   ```

   There is no default connector. Empty/untagged outbounds are omitted from the
   selector; duplicate named tags fail. Matching is literal Go `HasPrefix`, with
   sorted unique results. A selector containing `""` selects all named tags;
   an empty selector list disables the scheduler. Rebuild the runtime with its
   dispatcher if adding dynamic outbound replacement later.

4. If `ObservatoryService` is requested, require an actual configured ordinary
   observatory and register `ObservatoryService::new(observatory.provider())`
   with `api::observatory::add_observatory_routes`. Update `ApiConfig::validate`
   to admit this service only when the top-level compile has ensured that the
   provider exists. The observer and service share real completed measurements;
   initial, disabled, or cancelled-before-completion providers have no statuses.
   Do not fabricate `health_ping`, and do not use this provider to claim burst
   or least-load support.

   The current root builds `ApiServer` before `Dispatcher`. Separate channel /
   optional API-listener creation from route finalization: keep the API sender
   available for `Dispatcher`, then construct the observer and add its provider
   route before `ApiServer::from_routes` and before spawning any listener tasks.

5. When `observatory.is_enabled()`, move an `Arc` and the server cancellation
   token clone into the server's existing owned `JoinSet`:

   ```rust,ignore
   if let Some(observer) = observatory.filter(|observer| observer.is_enabled()) {
       let stop = stopping.clone();
       tasks.spawn(async move { observer.run(&stop).await });
   }
   ```

   Do not spawn a disabled observer: its immediate successful return must not
   make the server's `join_next` termination logic stop listeners. On server
   shutdown, cancel `stopping` and drain `tasks`, as the runtime already does.
   `run` interrupts probes and sleeps and joins its internal concurrent workers.
   No separate detached scheduler or cancellation handle is necessary.

Validation added in these owned modules covers defaults and Go-duration units;
negative/overflow/type/unknown/burst-field rejection; literal prefix selection;
exact tag and domain preservation; admission failure without fallback; empty
selectors; cancellation that drops a pending dial without publishing a failure;
and an injected proxy stream updating the registered provider after HTTP 503
headers (ordinary source semantics count any final HTTP response as alive).
The lead must still test root JSON/service registration, an actual proxy
outbound, final-rule blocking, and server shutdown after wiring.
