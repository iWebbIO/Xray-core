use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::{
    cache::{Cache, CacheKey, Cached},
    wire::{self, CLASS_IN, MAX_MESSAGE_SIZE, RecordData},
    *,
};

fn hex(input: &str) -> Vec<u8> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(input.len() % 2, 0);
    (0..input.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).unwrap())
        .collect()
}

fn answer(ips: Vec<IpAddr>, ttl: u32, response_code: u16) -> DnsAnswer {
    DnsAnswer {
        ips,
        ttl,
        response_code,
        from_cache: false,
        stale: false,
    }
}

fn resolver(upstream: Upstream) -> Resolver {
    Resolver::new(ResolverConfig {
        servers: vec![ServerLink::Classic(upstream)],
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    })
    .unwrap()
}

fn reply(query: &[u8], ips: &[IpAddr], ttl: u32, code: u16) -> Vec<u8> {
    let query = wire::decode(query).unwrap();
    wire::encode_response(
        query.header.id,
        &query.questions[0],
        ips,
        ttl,
        code,
        None,
        MAX_MESSAGE_SIZE,
    )
    .unwrap()
}

#[test]
fn golden_a_query_and_compressed_response() {
    let question = Question::new("example.com", RecordType::A).unwrap();
    let query = wire::encode_query(0x1234, &question, None).unwrap();
    assert_eq!(
        query,
        hex("1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001")
    );
    let response = wire::encode_response(
        0x1234,
        &question,
        &["192.0.2.1".parse().unwrap()],
        60,
        0,
        None,
        MAX_MESSAGE_SIZE,
    )
    .unwrap();
    assert_eq!(
        response,
        hex(
            "1234 8580 0001 0001 0000 0000 076578616d706c6503636f6d00 0001 0001 c00c 0001 0001 0000003c 0004 c0000201"
        )
    );
    let decoded = wire::decode(&response).unwrap();
    assert!(decoded.header.is_response());
    assert_eq!(decoded.answers[0].name, "example.com.");
    assert_eq!(
        decoded.answers[0].data,
        RecordData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(decoded.answers[0].ttl, 60);
}

#[test]
fn golden_aaaa_query_and_response() {
    let question = Question::new("example.com.", RecordType::AAAA).unwrap();
    let query = wire::encode_query(0xabcd, &question, None).unwrap();
    assert_eq!(
        query,
        hex("abcd 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 001c 0001")
    );
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let response = wire::encode_response(
        0xabcd,
        &question,
        &[ip.into()],
        300,
        0,
        None,
        MAX_MESSAGE_SIZE,
    )
    .unwrap();
    assert_eq!(&response[response.len() - 16..], &ip.octets());
    assert_eq!(
        wire::decode(&response).unwrap().answers[0].data,
        RecordData::Aaaa(ip)
    );
}

#[test]
fn xray_client_subnet_bytes_match_go_set_edns0() {
    let question = Question::new("example.com", RecordType::A).unwrap();
    let query = wire::encode_query(1, &question, Some("192.0.2.199".parse().unwrap())).unwrap();
    assert_eq!(
        &query[29..],
        hex("00 0029 0546 e0008000 000b 0008 0007 0001 18 00 c00002")
    );
    let decoded = wire::decode(&query).unwrap();
    assert_eq!(decoded.udp_payload_size(), 1350);
    let query = wire::encode_query(
        1,
        &question,
        Some("2001:db8:1234:5678:abcd:ef01:2222:3333".parse().unwrap()),
    )
    .unwrap();
    assert_eq!(
        &query[29..],
        hex("00 0029 0546 e0008000 0014 0008 0010 0002 60 00 20010db812345678abcdef01")
    );
}

#[test]
fn dns_names_have_exact_wire_boundaries() {
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let question = Question::new(&maximum, RecordType::A).unwrap();
    let bytes = wire::encode_query(1, &question, None).unwrap();
    assert_eq!(bytes.len(), 12 + 255 + 4);
    assert_eq!(wire::decode(&bytes).unwrap().questions[0], question);
    for name in [
        format!("{maximum}e"),
        "a".repeat(64),
        "a..b".into(),
        "".into(),
        "bücher.example".into(),
        "a\\.b".into(),
    ] {
        assert!(
            Question::new(&name, RecordType::A).is_err(),
            "accepted {name:?}"
        );
    }
    assert_eq!(
        Question::new("MiXeD.test", RecordType::A).unwrap().name,
        "MiXeD.test."
    );
    let root = Question::new(".", RecordType::A).unwrap();
    assert_eq!(
        wire::decode(&wire::encode_query(2, &root, None).unwrap())
            .unwrap()
            .questions[0],
        root
    );
}

#[test]
fn malformed_name_compression_and_section_counts_are_rejected() {
    let header = hex("0001 8180 0001 0000 0000 0000");
    for suffix in [
        hex("c00c00010001"),
        hex("c0ff00010001"),
        hex("c00000010001"),
        hex("4000010001"),
        hex("01ff0000010001"),
    ] {
        let mut bytes = header.clone();
        bytes.extend(suffix);
        assert!(wire::decode(&bytes).is_err());
    }
    let mut bytes = wire::encode_query(
        1,
        &Question::new("example.com", RecordType::A).unwrap(),
        None,
    )
    .unwrap();
    bytes[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(wire::decode(&bytes).is_err());
    let valid = wire::encode_query(
        1,
        &Question::new("example.com", RecordType::A).unwrap(),
        None,
    )
    .unwrap();
    for end in 0..valid.len() {
        assert!(wire::decode(&valid[..end]).is_err());
    }
    let mut extra = valid;
    extra.push(0);
    assert!(wire::decode(&extra).is_err());
}

#[test]
fn compressed_cname_rdata_has_exact_length_and_follows_target() {
    // www.example.com -> alias.example.com. Both target labels use a pointer
    // into the question, and the A owner points to the CNAME RDATA at offset 45.
    let bytes = hex("0001 8180 0001 0002 0000 0000
        03777777 076578616d706c65 03636f6d 00 0001 0001
        c00c 0005 0001 0000001e 0008 05616c696173 c010
        c02d 0001 0001 0000003c 0004 c0000209");
    let message = wire::decode(&bytes).unwrap();
    assert_eq!(
        message.answers[0].data,
        RecordData::Cname("alias.example.com.".into())
    );
    assert_eq!(message.answers[1].name, "alias.example.com.");
    let mut too_long = bytes.clone();
    too_long[43..45].copy_from_slice(&9u16.to_be_bytes());
    assert!(wire::decode(&too_long).is_err());
    let mut too_short = bytes;
    too_short[43..45].copy_from_slice(&7u16.to_be_bytes());
    assert!(wire::decode(&too_short).is_err());
}

#[test]
fn invalid_rdata_and_edns_options_are_rejected() {
    let query =
        wire::encode_query(1, &Question::new("x.test", RecordType::A).unwrap(), None).unwrap();
    let mut response = reply(&query, &[Ipv4Addr::LOCALHOST.into()], 1, 0);
    let length_offset = response.len() - 6;
    response[length_offset..length_offset + 2].copy_from_slice(&3u16.to_be_bytes());
    assert!(wire::decode(&response).is_err());
    let mut edns = wire::encode_query(
        1,
        &Question::new("x.test", RecordType::A).unwrap(),
        Some(Ipv4Addr::LOCALHOST.into()),
    )
    .unwrap();
    let option_length = edns.len() - 9;
    edns[option_length..option_length + 2].copy_from_slice(&100u16.to_be_bytes());
    assert!(wire::decode(&edns).is_err());
}

#[test]
fn truncation_keeps_complete_records_and_extended_rcode_needs_edns_zero() {
    let question = Question::new("example.com", RecordType::A).unwrap();
    let ips = vec![Ipv4Addr::LOCALHOST.into(); 80];
    let bytes = wire::encode_response(1, &question, &ips, 60, 0, None, 512).unwrap();
    assert!(bytes.len() <= 512);
    let message = wire::decode(&bytes).unwrap();
    assert!(message.header.is_truncated());
    assert!(!message.answers.is_empty());
    let mut bytes = wire::encode_response(1, &question, &[], 0, 16, Some(1350), 1350).unwrap();
    assert_eq!(wire::decode(&bytes).unwrap().response_code(), 16);
    let version = bytes.len() - 5;
    bytes[version] = 1;
    assert_eq!(wire::decode(&bytes).unwrap().response_code(), 0);
    assert!(wire::encode_response(1, &question, &[], 0, 16, None, 512).is_err());
}

#[test]
fn cache_ttl_ceil_expiry_negative_results_and_capacity() {
    let now = Instant::now();
    let config = CacheConfig {
        max_entries: 2,
        ..CacheConfig::default()
    };
    let a = CacheKey {
        name: "a.test.".into(),
        record_type: RecordType::A,
    };
    let aaaa = CacheKey {
        name: "a.test.".into(),
        record_type: RecordType::AAAA,
    };
    let mut cache = Cache::default();
    cache.insert(
        a.clone(),
        answer(vec![Ipv4Addr::LOCALHOST.into()], 2, 0),
        &config,
        now,
    );
    match cache.get(&a, &config, now + Duration::from_millis(1001)) {
        Some(Cached::Fresh(answer)) => {
            assert_eq!(answer.ttl, 1);
            assert!(answer.from_cache);
        }
        _ => panic!("entry should remain live"),
    }
    assert!(
        cache
            .get(&a, &config, now + Duration::from_secs(2))
            .is_none()
    );
    cache.insert(a.clone(), answer(Vec::new(), 300, 3), &config, now);
    cache.insert(
        aaaa.clone(),
        answer(Vec::new(), 300, 0),
        &config,
        now + Duration::from_millis(1),
    );
    match cache.get(&a, &config, now) {
        Some(Cached::Fresh(answer)) => assert_eq!(answer.response_code, 3),
        _ => panic!(),
    }
    match cache.get(&aaaa, &config, now) {
        Some(Cached::Fresh(answer)) => assert_eq!(answer.response_code, 0),
        _ => panic!(),
    }
    let third = CacheKey {
        name: "third.test.".into(),
        record_type: RecordType::A,
    };
    cache.insert(
        third,
        answer(Vec::new(), 300, 0),
        &config,
        now + Duration::from_millis(2),
    );
    assert_eq!(cache.len(), 2);
    assert!(cache.get(&a, &config, now).is_none());
}

#[test]
fn stale_cache_returns_one_second_until_explicit_age_limit() {
    let now = Instant::now();
    let config = CacheConfig {
        serve_stale: true,
        max_stale: Duration::from_secs(3),
        ..CacheConfig::default()
    };
    let key = CacheKey {
        name: "stale.test.".into(),
        record_type: RecordType::A,
    };
    let mut cache = Cache::default();
    cache.insert(key.clone(), answer(Vec::new(), 2, 3), &config, now);
    match cache.get(&key, &config, now + Duration::from_secs(3)) {
        Some(Cached::Stale(answer)) => {
            assert_eq!(answer.ttl, 1);
            assert!(answer.stale);
            assert_eq!(answer.response_code, 3);
        }
        _ => panic!("expected stale NXDOMAIN"),
    }
    assert!(
        cache
            .get(&key, &config, now + Duration::from_secs(5))
            .is_none()
    );
    let config = CacheConfig {
        enabled: false,
        ..config
    };
    cache.insert(key, answer(Vec::new(), 20, 0), &config, now);
    assert_eq!(cache.len(), 0);
}

#[test]
fn server_parsing_is_explicit_about_unsupported_transports() {
    assert_eq!(
        Upstream::parse("192.0.2.1").unwrap(),
        Upstream::udp("192.0.2.1:53".parse().unwrap())
    );
    assert_eq!(
        Upstream::parse("tcp://[::1]:5353").unwrap(),
        Upstream::tcp("[::1]:5353".parse().unwrap())
    );
    assert_eq!(Upstream::parse("2001:db8::1").unwrap().address.port(), 53);
    for unsupported in [
        "https://example.com/dns-query",
        "tls://192.0.2.1",
        "quic://192.0.2.1",
        "fakedns",
        "localhost",
        "dns.example:53",
        "tcp://127.0.0.1:0",
    ] {
        assert!(
            Upstream::parse(unsupported).is_err(),
            "accepted {unsupported}"
        );
    }
}

#[tokio::test]
async fn udp_resolves_both_families_and_caches_separately() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::udp(socket.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let mut types = Vec::new();
        let mut buffer = [0; 512];
        for _ in 0..2 {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = wire::decode(&buffer[..size]).unwrap();
            assert_eq!(query.header.flags, 0x0100);
            assert_eq!(query.questions[0].class, CLASS_IN);
            let kind = query.questions[0].record_type;
            types.push(kind.0);
            let ip: IpAddr = if kind == RecordType::A {
                "192.0.2.10"
            } else {
                "2001:db8::10"
            }
            .parse()
            .unwrap();
            socket
                .send_to(&reply(&buffer[..size], &[ip], 45, 0), peer)
                .await
                .unwrap();
        }
        types.sort_unstable();
        assert_eq!(types, vec![1, 28]);
    });
    let result = resolver
        .lookup_ip("Example.test", QueryOptions::BOTH)
        .await
        .unwrap();
    assert_eq!(
        result.ips,
        vec![
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse().unwrap()
        ]
    );
    assert_eq!(result.ttl, 45);
    server.await.unwrap();
    let cached = resolver
        .query("EXAMPLE.TEST.", RecordType::A)
        .await
        .unwrap();
    assert!(cached.from_cache);
    assert_eq!(resolver.cache_len(), 2);
}

#[tokio::test]
async fn udp_ignores_wrong_source_id_question_and_query_flags() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::udp(socket.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let valid = reply(&buffer[..size], &["192.0.2.42".parse().unwrap()], 1, 0);
        attacker
            .send_to(
                &reply(&buffer[..size], &["192.0.2.99".parse().unwrap()], 1, 0),
                peer,
            )
            .await
            .unwrap();
        let mut invalid = valid.clone();
        invalid[0] ^= 0xff;
        socket.send_to(&invalid, peer).await.unwrap();
        let mut invalid = valid.clone();
        invalid[13] ^= 1;
        socket.send_to(&invalid, peer).await.unwrap();
        let mut invalid = valid.clone();
        invalid[2] &= 0x7f;
        socket.send_to(&invalid, peer).await.unwrap();
        socket.send_to(&valid, peer).await.unwrap();
    });
    let result = resolver
        .lookup_ip("example.test", QueryOptions::IPV4)
        .await
        .unwrap();
    assert_eq!(result.ips, vec!["192.0.2.42".parse::<IpAddr>().unwrap()]);
    server.await.unwrap();
}

#[tokio::test]
async fn concurrent_queries_share_a_single_cached_exchange() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::udp(socket.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
        tokio::task::yield_now().await;
        socket
            .send_to(
                &reply(&buffer[..size], &[Ipv4Addr::LOCALHOST.into()], 120, 0),
                peer,
            )
            .await
            .unwrap();
    });
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let resolver = resolver.clone();
        let barrier = barrier.clone();
        callers.spawn(async move {
            barrier.wait().await;
            resolver
                .lookup_ip("shared.test", QueryOptions::IPV4)
                .await
                .unwrap()
        });
    }
    while let Some(result) = callers.join_next().await {
        assert_eq!(result.unwrap().ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
    server.await.unwrap();
    assert_eq!(resolver.cache_len(), 1);
}

#[tokio::test]
async fn cname_ttl_limits_the_resolved_address_ttl() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::udp(socket.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (_, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let mut response = hex("0001 8180 0001 0002 0000 0000
            03777777 076578616d706c65 03636f6d 00 0001 0001
            c00c 0005 0001 0000001e 0008 05616c696173 c010
            c02d 0001 0001 0000003c 0004 c0000209");
        response[..2].copy_from_slice(&buffer[..2]);
        socket.send_to(&response, peer).await.unwrap();
    });
    let result = resolver
        .lookup_ip("www.example.com", QueryOptions::IPV4)
        .await
        .unwrap();
    assert_eq!(result.ttl, 30);
    assert_eq!(result.ips, vec!["192.0.2.9".parse::<IpAddr>().unwrap()]);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_rejects_a_mismatched_transaction_id() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::tcp(listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_tcp_message(&mut stream).await.unwrap().unwrap();
        let mut response = reply(&request, &[Ipv4Addr::LOCALHOST.into()], 0, 0);
        response[0] ^= 0xff;
        write_tcp_message(&mut stream, &response).await.unwrap();
    });
    assert!(matches!(
        resolver.query("mismatch.test", RecordType::A).await,
        Err(DnsError::MismatchedResponse)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_query_uses_exact_length_framing_and_short_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::tcp(listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_tcp_message(&mut stream).await.unwrap().unwrap();
        let response = reply(&request, &[Ipv6Addr::LOCALHOST.into()], 0, 0);
        let prefix = (response.len() as u16).to_be_bytes();
        stream.write_all(&prefix[..1]).await.unwrap();
        stream.write_all(&prefix[1..]).await.unwrap();
        for part in response.chunks(3) {
            stream.write_all(part).await.unwrap();
        }
    });
    let result = resolver
        .lookup_ip("ipv6.test", QueryOptions::IPV6)
        .await
        .unwrap();
    assert_eq!(result.ips, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    assert_eq!(result.ttl, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn truncated_partial_udp_reply_can_retry_over_tcp() {
    // TCP and UDP ephemeral/excluded ranges can differ on Windows; only the
    // UDP allocator reliably avoids the UDP-excluded ranges, so pick the port
    // with a UDP bind first and then reserve TCP on the same port.
    let mut pair = None;
    for attempt in 0..64 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match TcpListener::bind(socket.local_addr().unwrap()).await {
            Ok(listener) => {
                pair = Some((listener, socket));
                break;
            }
            Err(error)
                if attempt < 63
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) => {}
            Err(error) => panic!("reserve TCP/UDP DNS fixture: {error}"),
        }
    }
    let (listener, socket) = pair.expect("dual protocol socket reservation");
    let address = listener.local_addr().unwrap();
    let resolver = Resolver::new(ResolverConfig {
        servers: vec![ServerLink::Classic(Upstream::udp(address))],
        tcp_fallback: true,
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    })
    .unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let response = reply(&buffer[..size], &["192.0.2.77".parse().unwrap()], 90, 0);
        let mut truncated = response[..response.len() - 2].to_vec();
        truncated[2] |= 0x02;
        assert!(wire::decode(&truncated).is_err());
        socket.send_to(&truncated, peer).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let tcp_query = read_tcp_message(&mut stream).await.unwrap().unwrap();
        assert_eq!(tcp_query, buffer[..size]);
        write_tcp_message(&mut stream, &response).await.unwrap();
    });
    let result = resolver
        .lookup_ip("truncated.test", QueryOptions::IPV4)
        .await
        .unwrap();
    assert_eq!(result.ips, vec!["192.0.2.77".parse::<IpAddr>().unwrap()]);
    server.await.unwrap();
}

#[tokio::test]
async fn nxdomain_and_nodata_are_distinct_cacheable_results() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = resolver(Upstream::udp(socket.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        for code in [3, 0] {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket
                .send_to(&reply(&buffer[..size], &[], 0, code), peer)
                .await
                .unwrap();
        }
    });
    assert!(matches!(
        resolver.lookup_ip("missing.test", QueryOptions::IPV4).await,
        Err(DnsError::ResponseCode(3))
    ));
    assert!(matches!(
        resolver.lookup_ip("empty.test", QueryOptions::IPV4).await,
        Err(DnsError::EmptyResponse)
    ));
    server.await.unwrap();
    let missing = resolver.query("missing.test", RecordType::A).await.unwrap();
    assert!(missing.from_cache);
    assert_eq!(missing.ttl, DEFAULT_TTL);
    assert_eq!(missing.response_code, 3);
    let empty = resolver.query("empty.test", RecordType::A).await.unwrap();
    assert!(empty.from_cache && empty.ips.is_empty());
    assert_eq!(empty.response_code, 0);
}

#[tokio::test]
async fn query_times_out_and_disabled_udp_fallback_is_explicit() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(ResolverConfig {
        servers: vec![ServerLink::Classic(Upstream::udp(
            socket.local_addr().unwrap(),
        ))],
        timeout: Duration::from_millis(40),
        ..ResolverConfig::default()
    })
    .unwrap();
    assert!(matches!(
        resolver.query("timeout.test", RecordType::A).await,
        Err(DnsError::Timeout)
    ));
    let truncated_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(ResolverConfig {
        servers: vec![ServerLink::Classic(Upstream::udp(
            truncated_socket.local_addr().unwrap(),
        ))],
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    })
    .unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        let (size, peer) = truncated_socket.recv_from(&mut buffer).await.unwrap();
        let mut response = reply(&buffer[..size], &[], 0, 0);
        response[2] |= 0x02;
        truncated_socket.send_to(&response, peer).await.unwrap();
    });
    assert!(matches!(
        resolver.query("truncated.test", RecordType::A).await,
        Err(DnsError::Truncated)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn static_hosts_aliases_families_errors_and_cycles() {
    let hosts = HashMap::from([
        (
            "target.test".into(),
            HostEntry::Addresses(vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]),
        ),
        ("alias.test".into(), HostEntry::Alias("target.test".into())),
        ("cycle.test".into(), HostEntry::Alias("CYCLE.test.".into())),
        ("blocked.test".into(), HostEntry::ResponseCode(3)),
    ]);
    let resolver = Resolver::new(ResolverConfig {
        hosts,
        ..ResolverConfig::default()
    })
    .unwrap();
    assert_eq!(
        resolver
            .lookup_ip("ALIAS.TEST", QueryOptions::IPV6)
            .await
            .unwrap()
            .ips,
        vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
    );
    assert!(matches!(
        resolver.query("cycle.test", RecordType::A).await,
        Err(DnsError::AliasLoop)
    ));
    assert!(matches!(
        resolver.lookup_ip("blocked.test", QueryOptions::IPV4).await,
        Err(DnsError::ResponseCode(3))
    ));
    assert!(matches!(
        resolver.lookup_ip("127.0.0.1", QueryOptions::IPV6).await,
        Err(DnsError::EmptyResponse)
    ));
    assert!(matches!(
        resolver
            .lookup_ip(
                "target.test",
                QueryOptions {
                    ipv4: false,
                    ipv6: false
                }
            )
            .await,
        Err(DnsError::InvalidConfig(_))
    ));
}

#[tokio::test]
async fn tcp_framing_distinguishes_clean_eof_partial_prefix_and_short_body() {
    for bytes in [vec![0], vec![0, 12, 0, 0], vec![0, 0]] {
        let (mut writer, mut reader) = duplex(128);
        writer.write_all(&bytes).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(read_tcp_message(&mut reader).await.is_err());
    }
    let (writer, mut reader) = duplex(128);
    drop(writer);
    assert!(read_tcp_message(&mut reader).await.unwrap().is_none());
}

fn static_service() -> Arc<DnsService> {
    let hosts = HashMap::from([(
        "service.test".into(),
        HostEntry::Addresses(vec!["192.0.2.123".parse().unwrap()]),
    )]);
    let resolver = Resolver::new(ResolverConfig {
        hosts,
        ..ResolverConfig::default()
    })
    .unwrap();
    Arc::new(DnsService::new(resolver, ServiceConfig::default()).unwrap())
}

#[tokio::test]
async fn service_udp_round_trip_survives_malformed_query_and_shuts_down() {
    let service = static_service();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(service.serve_udp(socket, shutdown.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(address).await.unwrap();
    let mut buffer = [0; 512];
    client.send(&[0x12, 0x34]).await.unwrap();
    let size = timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let error = wire::decode(&buffer[..size]).unwrap();
    assert_eq!(error.header.id, 0x1234);
    assert_eq!(error.response_code(), 1);
    let query = wire::encode_query(
        8,
        &Question::new("service.test", RecordType::A).unwrap(),
        None,
    )
    .unwrap();
    client.send(&query).await.unwrap();
    let size = timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        wire::decode(&buffer[..size]).unwrap().answers[0].data,
        RecordData::A("192.0.2.123".parse().unwrap())
    );
    shutdown.cancel();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn service_tcp_supports_multiple_frames_and_cancels_idle_connections() {
    let service = static_service();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(service.serve_tcp(listener, shutdown.clone()));
    let mut stream = TcpStream::connect(address).await.unwrap();
    for id in [10, 11] {
        let query = wire::encode_query(
            id,
            &Question::new("service.test", RecordType::A).unwrap(),
            None,
        )
        .unwrap();
        write_tcp_message(&mut stream, &query).await.unwrap();
    }
    for id in [10, 11] {
        let bytes = timeout(Duration::from_secs(2), read_tcp_message(&mut stream))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let response = wire::decode(&bytes).unwrap();
        assert_eq!(response.header.id, id);
        assert_eq!(response.answers.len(), 1);
    }
    shutdown.cancel();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_secs(2), read_tcp_message(&mut stream))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn service_default_non_ip_return_class_refusal_and_edns_badvers() {
    let service = static_service();
    let txt = Question::new("service.test", RecordType(16)).unwrap();
    let query = wire::encode_query(1, &txt, None).unwrap();
    let response = wire::decode(&service.handle_query(&query).await.unwrap()).unwrap();
    assert_eq!(response.response_code(), 0);
    assert!(response.answers.is_empty());
    assert_eq!(response.header.flags, 0x8580);
    let mut chaos = Question::new("service.test", RecordType::A).unwrap();
    chaos.class = 3;
    let query = wire::encode_query(2, &chaos, None).unwrap();
    assert_eq!(
        wire::decode(&service.handle_query(&query).await.unwrap())
            .unwrap()
            .response_code(),
        5
    );
    let query = Question::new("service.test", RecordType::A).unwrap();
    let mut bytes = wire::encode_query(3, &query, Some(Ipv4Addr::LOCALHOST.into())).unwrap();
    let opt_offset = wire::encode_query(3, &query, None).unwrap().len();
    bytes[opt_offset + 6] = 1;
    let response = wire::decode(&service.handle_query(&bytes).await.unwrap()).unwrap();
    assert_eq!(response.response_code(), 16);
    assert!(response.answers.is_empty());
}
