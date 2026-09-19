use super::*;

// Golden bytes were independently computed with Python's struct/ipaddress and
// a one's-complement checksum implementation, using Go icmp/packet_test.go's
// identifier, sequence and odd-length payload. No builder under test is used
// to generate these expected messages.
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn ipv4_echo_golden_preserves_id_sequence_payload_and_swaps_addresses() {
    let request = hex("4500001f0000000040018ea7c0000201c63364020800189712345678aabbcc");
    let packet = parse_ip(&request).unwrap();
    let echo = parse_echo_request(&packet).unwrap();
    assert_eq!(
        echo,
        EchoRequest {
            identifier: 0x1234,
            sequence: 0x5678,
            payload: &[0xaa, 0xbb, 0xcc]
        }
    );
    assert_eq!(
        build_echo_reply(&packet).unwrap(),
        hex("4500001f0000000040018ea7c6336402c00002010000209712345678aabbcc")
    );
    assert_eq!(request[20], 8, "request is not modified");
}

#[test]
fn ipv6_echo_golden_uses_pseudoheader_checksum() {
    let request = hex(
        "60000000000b3a4020010db800000000000000000000000120010db8000000000000000000000002800044dc12345678aabbcc",
    );
    let packet = parse_ip(&request).unwrap();
    assert_eq!(parse_echo_request(&packet).unwrap().sequence, 0x5678);
    assert_eq!(
        build_echo_reply(&packet).unwrap(),
        hex(
            "60000000000b3a4020010db800000000000000000000000220010db8000000000000000000000001810043dc12345678aabbcc"
        )
    );
    let mut corrupt = request.clone();
    corrupt[23] = 3; // Payload unchanged; changing pseudoheader source breaks ICMP.
    assert!(parse_echo_request(&parse_ip(&corrupt).unwrap()).is_err());
}

#[test]
fn udp_golden_ipv4_and_ipv6() {
    for (source, destination, expected) in [
        (
            "192.0.2.1:1234",
            "198.51.100.2:53",
            "4500001f0000000040118e97c0000201c633640204d20035000b4a37616263",
        ),
        (
            "[2001:db8::1]:1234",
            "[2001:db8::2]:53",
            "60000000000b114020010db800000000000000000000000120010db800000000000000000000000204d20035000bdaf9616263",
        ),
    ] {
        let source = source.parse().unwrap();
        let destination = destination.parse().unwrap();
        let expected = hex(expected);
        assert_eq!(build_udp(source, destination, b"abc").unwrap(), expected);
        let packet = parse_ip(&expected).unwrap();
        assert_eq!(
            parse_udp(&packet).unwrap(),
            UdpPacket {
                source,
                destination,
                payload: b"abc"
            }
        );
    }
}

#[test]
fn udp_zero_computed_checksum_is_encoded_as_ffff() {
    let packet = build_udp(
        "192.0.2.1:1234".parse().unwrap(),
        "198.51.100.2:53".parse().unwrap(),
        &[0x0e, 0x9c],
    )
    .unwrap();
    assert_eq!(&packet[26..28], &[0xff, 0xff]);
    parse_udp(&parse_ip(&packet).unwrap()).unwrap();
}

#[test]
fn missing_udp_checksum_is_only_permitted_for_ipv4() {
    let mut v4 = hex("4500001f0000000040118e97c0000201c633640204d20035000b4a37616263");
    v4[26..28].fill(0);
    assert!(parse_udp(&parse_ip(&v4).unwrap()).is_ok());
    let mut v6 = hex(
        "60000000000b114020010db800000000000000000000000120010db800000000000000000000000204d20035000bdaf9616263",
    );
    v6[46..48].fill(0);
    assert!(parse_udp(&parse_ip(&v6).unwrap()).is_err());
}

#[test]
fn all_truncations_and_bad_lengths_are_rejected_without_panicking() {
    let packet = hex("4500001f0000000040118e97c0000201c633640204d20035000b4a37616263");
    for end in 0..packet.len() {
        assert!(parse_ip(&packet[..end]).is_err(), "truncation {end}");
    }
    let mut corrupt = packet.clone();
    corrupt[20 + 4] = 0xff;
    assert!(parse_udp(&parse_ip(&corrupt).unwrap()).is_err());
    let mut corrupt = packet.clone();
    corrupt[30] ^= 1;
    assert!(parse_udp(&parse_ip(&corrupt).unwrap()).is_err());
    let mut corrupt = packet.clone();
    corrupt.push(0);
    assert!(parse_ip(&corrupt).is_err());
    let mut corrupt = packet;
    corrupt[0] = 0x4f;
    assert!(parse_ip(&corrupt).is_err());
}

#[test]
fn fragmentation_and_ipv6_extensions_are_explicitly_unsupported() {
    let mut v4 = hex("4500001f0000000040118e97c0000201c633640204d20035000b4a37616263");
    v4[6] = 0x20;
    v4[10..12].fill(0);
    let check = checksum(&v4[..20]);
    v4[10..12].copy_from_slice(&check.to_be_bytes());
    assert_eq!(
        parse_ip(&v4).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    let mut v6 = hex(
        "60000000000b114020010db800000000000000000000000120010db800000000000000000000000204d20035000bdaf9616263",
    );
    v6[6] = 44;
    assert_eq!(
        parse_ip(&v6).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn tcp_syn_golden_checksum_and_header_bounds() {
    let packet =
        hex("450000280000000040068e99c0000201c6336402303901bb10203040000000005002faf056660000");
    let ip = parse_ip(&packet).unwrap();
    assert_eq!(ip.hop_limit, 64);
    assert_eq!(ip.header.len(), 20);
    validate_tcp(&ip).unwrap();
    let mut corrupt = packet.clone();
    corrupt[32] = 0x40;
    assert!(validate_tcp(&parse_ip(&corrupt).unwrap()).is_err());
    let mut corrupt = packet;
    corrupt[27] ^= 1;
    assert!(validate_tcp(&parse_ip(&corrupt).unwrap()).is_err());
}

#[test]
fn size_and_family_limits_prevent_wire_length_wraparound() {
    let v4 = "192.0.2.1:1".parse().unwrap();
    let v6 = "[2001:db8::1]:1".parse().unwrap();
    assert!(build_udp(v4, v6, b"test").is_err());
    assert!(build_udp(v4, v4, &vec![0; 65_508]).is_err());
    assert!(build_udp(v6, v6, &vec![0; 65_528]).is_err());
    let max = build_udp(v4, v4, &vec![0; 65_507]).unwrap();
    assert_eq!(max.len(), 65_535);
    parse_udp(&parse_ip(&max).unwrap()).unwrap();
}
