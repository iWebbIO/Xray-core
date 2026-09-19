use super::*;
use serde_json::json;

fn config(mode: &str) -> Config {
    Config::from_json(&json!({
        "mode": mode,
        "path": "/stream?token=fixture",
        "xPaddingBytes": 100,
        "scMaxEachPostBytes": 128,
        "scMaxBufferedPosts": 2
    }))
    .unwrap()
    .with_authority("example.test", false)
    .unwrap()
}

fn one_connection(stream: BoxStream) -> Connector {
    let stream = Arc::new(StdMutex::new(Some(stream)));
    Arc::new(move || {
        let stream = stream.clone();
        Box::pin(async move {
            stream
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| invalid("unexpected extra connection"))
        })
    })
}

#[tokio::test]
async fn stream_request_matches_go_metadata_grpc_and_chunked_framing() {
    for (mode, session, target) in [
        ("stream-up", "session", "/stream/session?token=fixture"),
        ("stream-one", "", "/stream/?token=fixture"),
    ] {
        let config = config(mode);
        let wire = config.stream_request(session).unwrap();
        let head = read_head(&mut BufReader::new(wire.as_slice()), true, 8192)
            .await
            .unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, target);
        assert_eq!(head.get("Content-Type"), "application/grpc");
        assert_eq!(head.get("Transfer-Encoding"), "chunked");
        assert_eq!(head.get("Content-Length"), "");
        assert_eq!(head.get("Connection"), "close");
        assert_eq!(
            config.metadata(&head).unwrap(),
            (session.to_owned(), String::new())
        );
        assert!(config.valid_padding(&head));
    }
    let config = Config::from_json(&json!({
        "mode":"stream-one", "noGRPCHeader":true,
        "headers":{"Content-Type":"application/octet-stream"},
        "sessionIDPlacement":"header", "seqPlacement":"header",
        "scStreamUpServerSecs":-1
    }))
    .unwrap()
    .with_authority("example.test", false)
    .unwrap();
    let wire = config.stream_request("").unwrap();
    let head = read_head(&mut BufReader::new(wire.as_slice()), true, 8192)
        .await
        .unwrap();
    assert_eq!(head.get("Content-Type"), "application/octet-stream");
    assert_eq!(head.get("X-Session"), "");
    assert!(
        !head
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("X-Session"))
    );
    assert!(config.stream_up_keepalive.is_none());
    assert!(
        stream_up_keepalive(Some(&json!("-2--1")))
            .unwrap()
            .is_none()
    );
    let interval = stream_up_keepalive(Some(&json!("80-20"))).unwrap().unwrap();
    assert_eq!((interval.from, interval.to), (20, 80));
    let interval = stream_up_keepalive(Some(&json!("-1-2"))).unwrap().unwrap();
    assert_eq!((interval.from, interval.to), (-1, 2));
}

#[tokio::test]
async fn stream_one_wire_preserves_coalesced_body_and_response_after_upload_eof() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = config("stream-one");
        let server = Server::new(config.clone());
        let (mut peer, socket) = tokio::io::duplex(8192);
        let mut request = config.stream_request("").unwrap();
        request.extend_from_slice(
            b"3;extension=value\r\na\x00b\r\n2\r\ncd\r\n0\r\nChecksum: fixture\r\n\r\n",
        );
        peer.write_all(&request).await.unwrap();
        let mut tunnel = server.accept(Box::new(socket)).await.unwrap().unwrap();
        let mut received = Vec::new();
        tunnel.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"a\x00bcd");
        tunnel.write_all(b"response after EOF").await.unwrap();
        // Successful shutdown must await the final HTTP chunk; dropping the
        // tunnel immediately after this may not discard buffered response bytes.
        tunnel.shutdown().await.unwrap();
        drop(tunnel);
        let mut peer = BufReader::new(peer);
        let head = read_head(&mut peer, false, 8192).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.get("Content-Type"), "text/event-stream");
        let bytes = body_bytes(&mut peer, &mut Body::from_head(&head, false).unwrap(), 64)
            .await
            .unwrap();
        assert_eq!(bytes, b"response after EOF");
        assert!(server.inner.sessions.lock().await.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stream_one_client_allows_peer_to_delay_headers_until_upload_eof() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, peer) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            let head = read_head(&mut peer, true, 8192).await.unwrap();
            assert_eq!(head.target, "/stream/?token=fixture");
            let body = body_bytes(&mut peer, &mut Body::from_head(&head, true).unwrap(), 64).await.unwrap();
            assert_eq!(body, b"hello");
            peer.get_mut().write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n").await.unwrap();
        });
        let mut client = tokio::time::timeout(Duration::from_secs(1), connect(config("stream-one"), one_connection(Box::new(client)))).await.unwrap().unwrap();
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"OK");
        peer.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn clean_upload_response_eof_preserves_download_and_wakes_blocked_writes() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (download, down_peer) = tokio::io::duplex(8192);
        let (upload, up_peer) = tokio::io::duplex(8192);
        let connections: Arc<StdMutex<std::collections::VecDeque<BoxStream>>> =
            Arc::new(StdMutex::new(std::collections::VecDeque::from([
                Box::new(download) as BoxStream,
                Box::new(upload) as BoxStream,
            ])));
        let connector: Connector = Arc::new(move || {
            let connections = connections.clone();
            Box::pin(async move {
                connections
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| invalid("unexpected connection"))
            })
        });
        let (upload_closed, upload_was_closed) = oneshot::channel();
        let up_peer = tokio::spawn(async move {
            let mut peer = BufReader::new(up_peer);
            let request = read_head(&mut peer, true, 8192).await.unwrap();
            let mut body = Body::from_head(&request, true).unwrap();
            let mut initial = [0; 1024];
            assert!(body.read(&mut peer, &mut initial).await.unwrap() > 0);
            // A complete, successful upload-only response is not an error in
            // the independent GET. The request body intentionally stays open.
            send_response(
                peer.get_mut(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            // Wait until the client cancels its remaining request write. This
            // makes the ordering deterministic without relying on sleeps.
            let _ = peer.read_to_end(&mut Vec::new()).await;
            let _ = upload_closed.send(());
        });
        let down_peer = tokio::spawn(async move {
            let mut peer = BufReader::new(down_peer);
            assert_eq!(
                read_head(&mut peer, true, 8192).await.unwrap().method,
                "GET"
            );
            send_response(
                peer.get_mut(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
            upload_was_closed.await.unwrap();
            write_chunk(peer.get_mut(), b"download survives upload EOF")
                .await
                .unwrap();
            finish_chunks(peer.get_mut(), true).await.unwrap();
        });
        let stream = connect(config("stream-up"), connector).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let writing = tokio::spawn(async move { writer.write_all(&vec![42; 1024 * 1024]).await });
        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"download survives upload EOF");
        assert!(writing.await.unwrap().is_err());
        up_peer.await.unwrap();
        down_peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stream_up_go_style_wire_splits_application_data_and_keepalive_padding() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = config("auto");
        let server = Server::new(config.clone());
        let (mut down, down_socket) = tokio::io::duplex(8192);
        down.write_all(&config.request("session", None, &[]).unwrap())
            .await
            .unwrap();
        let mut tunnel = server.accept(Box::new(down_socket)).await.unwrap().unwrap();
        let (mut upload, up_socket) = tokio::io::duplex(8192);
        let serving = server.clone();
        let upload_task = tokio::spawn(async move { serving.accept(Box::new(up_socket)).await });
        let mut request = String::from_utf8(config.stream_request("session").unwrap())
            .unwrap()
            .replace("Connection: close", "Connection: keep-alive")
            .into_bytes();
        request.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        upload.write_all(&request).await.unwrap();
        let mut upload = BufReader::new(upload);
        let head = read_head(&mut upload, false, 8192).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.get("Content-Type"), "");
        assert_eq!(head.get("X-Accel-Buffering"), "no");
        let mut upload_body = Body::from_head(&head, false).unwrap();
        let mut padding = [0; 100];
        let count = upload_body.read(&mut upload, &mut padding).await.unwrap();
        assert_eq!(&padding[..count], vec![b'X'; count]);
        assert!(count > 0);
        let mut received = Vec::new();
        tunnel.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"hello");
        tunnel.write_all(b"world").await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut down = BufReader::new(down);
        let head = read_head(&mut down, false, 8192).await.unwrap();
        let response = body_bytes(&mut down, &mut Body::from_head(&head, false).unwrap(), 64)
            .await
            .unwrap();
        assert_eq!(response, b"world");
        let tail = body_bytes(&mut upload, &mut upload_body, 1024)
            .await
            .unwrap();
        assert!(tail.iter().all(|byte| *byte == b'X'));
        assert!(upload_task.await.unwrap().unwrap().is_none());
        drop(tunnel);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_server_modes_reject_other_upload_modes() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for (mode, kind) in [
            ("packet-up", "stream-one"),
            ("packet-up", "stream-up"),
            ("stream-one", "packet-up"),
            ("stream-one", "stream-up"),
            ("stream-up", "packet-up"),
        ] {
            let config = config(mode);
            let server = Server::new(config.clone());
            let request = match kind {
                "stream-one" => config.stream_request("").unwrap(),
                "stream-up" => config.stream_request("s").unwrap(),
                _ => config.request("s", Some(0), b"x").unwrap(),
            };
            let (mut peer, socket) = tokio::io::duplex(8192);
            peer.write_all(&request).await.unwrap();
            assert!(
                server.accept(Box::new(socket)).await.unwrap().is_none(),
                "{mode}: {kind}"
            );
            let response = read_head(&mut BufReader::new(peer), false, 8192)
                .await
                .unwrap();
            assert_eq!(response.status, 400, "{mode}: {kind}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn duplicate_stream_upload_is_rejected_and_drop_cancels_upload() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = config("auto");
        let server = Server::new(config.clone());
        let (mut down, down_socket) = tokio::io::duplex(8192);
        down.write_all(&config.request("s", None, &[]).unwrap())
            .await
            .unwrap();
        let tunnel = server.accept(Box::new(down_socket)).await.unwrap().unwrap();
        let (mut upload, socket) = tokio::io::duplex(8192);
        let serving = server.clone();
        let upload_task = tokio::spawn(async move { serving.accept(Box::new(socket)).await });
        upload
            .write_all(&config.stream_request("s").unwrap())
            .await
            .unwrap();
        let mut upload = BufReader::new(upload);
        assert_eq!(
            read_head(&mut upload, false, 8192).await.unwrap().status,
            200
        );
        for request in [
            config.stream_request("s").unwrap(),
            config.request("s", Some(0), b"packet").unwrap(),
        ] {
            let (mut peer, socket) = tokio::io::duplex(8192);
            peer.write_all(&request).await.unwrap();
            assert!(server.accept(Box::new(socket)).await.unwrap().is_none());
            assert_eq!(
                read_head(&mut BufReader::new(peer), false, 8192)
                    .await
                    .unwrap()
                    .status,
                409
            );
        }
        drop(tunnel);
        assert!(upload_task.await.unwrap().unwrap().is_none());
        loop {
            if server.inner.sessions.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn streaming_client_server_large_payload_and_half_close() {
    for mode in ["stream-one", "stream-up"] {
        tokio::time::timeout(Duration::from_secs(8), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = Server::new(config("auto"));
            let acceptor = tokio::spawn(async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        socket = listener.accept() => {
                            let (socket, _) = socket.unwrap();
                            let server = server.clone();
                            children.spawn(async move {
                                if let Some(mut tunnel) = server.accept(Box::new(socket)).await.unwrap() {
                                    let mut payload = Vec::new();
                                    tunnel.read_to_end(&mut payload).await.unwrap();
                                    payload.reverse();
                                    tunnel.write_all(&payload).await.unwrap();
                                    tunnel.shutdown().await.unwrap();
                                }
                            });
                        },
                        result = children.join_next(), if !children.is_empty() => { result.unwrap().unwrap(); }
                    }
                }
            });
            let connector: Connector = Arc::new(move || Box::pin(async move {
                Ok(Box::new(tokio::net::TcpStream::connect(address).await?) as BoxStream)
            }));
            let mut tunnel = connect(config(mode), connector).await.unwrap();
            let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
            tunnel.write_all(&payload).await.unwrap();
            tunnel.shutdown().await.unwrap();
            let mut response = Vec::new();
            tunnel.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload.into_iter().rev().collect::<Vec<_>>(), "{mode}");
            drop(tunnel);
            acceptor.abort();
            let _ = acceptor.await;
        }).await.unwrap();
    }
}

#[tokio::test]
async fn stream_up_backpressure_is_bounded_and_cancellation_unblocks_writer() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = config("auto");
        let server = Server::new(config.clone());
        let (mut down, down_socket) = tokio::io::duplex(8192);
        down.write_all(&config.request("s", None, &[]).unwrap())
            .await
            .unwrap();
        let tunnel = server.accept(Box::new(down_socket)).await.unwrap().unwrap();
        let (mut upload, socket) = tokio::io::duplex(8192);
        let serving = server.clone();
        let serving = tokio::spawn(async move { serving.accept(Box::new(socket)).await });
        upload
            .write_all(&config.stream_request("s").unwrap())
            .await
            .unwrap();
        let mut upload = BufReader::new(upload);
        assert_eq!(
            read_head(&mut upload, false, 8192).await.unwrap().status,
            200
        );
        let (reader, mut writer) = tokio::io::split(upload);
        let mut writing =
            tokio::spawn(async move { write_chunk(&mut writer, &vec![42; 512 * 1024]).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut writing)
                .await
                .is_err()
        );
        drop(tunnel);
        assert!(writing.await.unwrap().is_err());
        assert!(serving.await.unwrap().unwrap().is_none());
        drop(reader);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn streaming_protocol_failures_reach_logical_reader() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = config("stream-one");
        let server = Server::new(config.clone());
        let (mut peer, socket) = tokio::io::duplex(8192);
        let mut wire = config.stream_request("").unwrap();
        wire.extend_from_slice(b"5\r\nabc");
        peer.write_all(&wire).await.unwrap();
        let mut tunnel = server.accept(Box::new(socket)).await.unwrap().unwrap();
        peer.shutdown().await.unwrap();
        let error = tunnel.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let (client, mut peer) = tokio::io::duplex(8192);
        peer.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut tunnel = connect(config, one_connection(Box::new(client)))
            .await
            .unwrap();
        let error = tunnel.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert!(error.to_string().contains("403"));
    })
    .await
    .unwrap();
}
