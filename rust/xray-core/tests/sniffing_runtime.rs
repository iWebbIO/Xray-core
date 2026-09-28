//! Sniffer byte fixtures and the sniffing-related routing/config surfaces.
//! The runtime wiring itself (where sniffing runs inside the dispatch path)
//! is owned by `runtime.rs`; these tests exercise the sniffers, the compiled
//! sniffing request and the router/config surfaces directly, on the same
//! golden bytes Go's `common/protocol/*/sniff_test.go` uses, so the
//! integrator can lift the fixtures into runtime tests.

#[path = "../src/runtime/sniffing.rs"]
mod sniffing;

// The sniffing module lives inside the private `runtime` module tree, so the
// test compiles the file directly; the few `crate::` paths it uses are
// re-exported here from the real crate.
mod address {
    pub use xray_core::address::{Address, Destination};
}
mod config {
    pub use xray_core::config::SniffingConfig;
}
mod geodata {
    pub use xray_core::geodata::{DomainMatcher, GeoDataStore, IpMatcher, domain};
}

use std::time::Duration;

use sniffing::{
    Network, Outcome, Override, SniffFlow, SniffLimits, SniffResult, Sniffers, SniffingRequest,
    sniff, sniff_http, sniff_quic, sniff_tls,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_core::{
    Config,
    address::Destination,
    router::{RouteContext, Router},
};

fn decode_hex(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    clean
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn sniffed(protocol: &'static str, domain: &str) -> SniffResult {
    SniffResult {
        protocol,
        domain: domain.to_owned(),
    }
}

fn assert_matched(outcome: Outcome, protocol: &str, domain: &str) {
    match outcome {
        Outcome::Matched(result) => {
            assert_eq!(result.protocol, protocol, "protocol for {domain:?}");
            assert_eq!(result.domain, domain, "domain for {protocol}");
        }
        Outcome::NoClue => panic!("expected {protocol} {domain:?}, got NoClue"),
        Outcome::NeedMoreData => panic!("expected {protocol} {domain:?}, got NeedMoreData"),
        Outcome::Rejected => panic!("expected {protocol} {domain:?}, got Rejected"),
    }
}

/// Go common/protocol/tls/sniff_test.go, case 1 (c.s-microsoft.com).
const TLS_MICROSOFT: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03, 0x1a, 0xac, 0xb2, 0xa8, 0xfe,
    0xb4, 0x96, 0x04, 0x5b, 0xca, 0xf7, 0xc1, 0xf4, 0x2e, 0x53, 0x24, 0x6e, 0x34, 0x0c, 0x58, 0x36,
    0x71, 0x97, 0x59, 0xe9, 0x41, 0x66, 0xe2, 0x43, 0xa0, 0x13, 0xb6, 0x00, 0x00, 0x20, 0x1a, 0x1a,
    0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
    0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
    0x00, 0x7b, 0xba, 0xba, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
    0x14, 0x00, 0x00, 0x11, 0x63, 0x2e, 0x73, 0x2d, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
    0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
    0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70,
    0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
    0xaa, 0xaa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0xaa, 0xaa, 0x00, 0x01, 0x00,
];
/// Go common/protocol/tls/sniff_test.go, case 2 (www07.clicktale.net).
const TLS_CLICKTALE: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0xee, 0x01, 0x00, 0x00, 0xea, 0x03, 0x03, 0xe7, 0x91, 0x9e, 0x93, 0xca,
    0x78, 0x1b, 0x3c, 0xe0, 0x65, 0x25, 0x58, 0xb5, 0x93, 0xe1, 0x0f, 0x85, 0xec, 0x9a, 0x66, 0x8e,
    0x61, 0x82, 0x88, 0xc8, 0xfc, 0xae, 0x1e, 0xca, 0xd7, 0xa5, 0x63, 0x20, 0xbd, 0x1c, 0x00, 0x00,
    0x8b, 0xee, 0x09, 0xe3, 0x47, 0x6a, 0x0e, 0x74, 0xb0, 0xbc, 0xa3, 0x02, 0xa7, 0x35, 0xe8, 0x85,
    0x70, 0x7c, 0x7a, 0xf0, 0x00, 0xdf, 0x4a, 0xea, 0x87, 0x01, 0x14, 0x91, 0x00, 0x20, 0xea, 0xea,
    0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
    0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
    0x00, 0x81, 0x9a, 0x9a, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00,
    0x16, 0x00, 0x00, 0x13, 0x77, 0x77, 0x77, 0x30, 0x37, 0x2e, 0x63, 0x6c, 0x69, 0x63, 0x6b, 0x74,
    0x61, 0x6c, 0x65, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
    0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
    0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x9a, 0x9a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x8a, 0x8a,
    0x00, 0x01, 0x00,
];
/// Go common/protocol/tls/sniff_test.go, case 3 (dogfish, dotless SNI).
const TLS_DOGFISH: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0xe6, 0x01, 0x00, 0x00, 0xe2, 0x03, 0x03, 0x81, 0x47, 0xc1, 0x66, 0xd5,
    0x1b, 0xfa, 0x4b, 0xb5, 0xe0, 0x2a, 0xe1, 0xa7, 0x87, 0x13, 0x1d, 0x11, 0xaa, 0xc6, 0xce, 0xfc,
    0x7f, 0xab, 0x94, 0xc8, 0x62, 0xad, 0xc8, 0xab, 0x0c, 0xdd, 0xcb, 0x20, 0x6f, 0x9d, 0x07, 0xf1,
    0x95, 0x3e, 0x99, 0xd8, 0xf3, 0x6d, 0x97, 0xee, 0x19, 0x0b, 0x06, 0x1b, 0xf4, 0x84, 0x0b, 0xb6,
    0x8f, 0xcc, 0xde, 0xe2, 0xd0, 0x2d, 0x6b, 0x0c, 0x1f, 0x52, 0x53, 0x13, 0x00, 0x08, 0x13, 0x02,
    0x13, 0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a,
    0x00, 0x00, 0x07, 0x64, 0x6f, 0x67, 0x66, 0x69, 0x73, 0x68, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
    0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
    0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
    0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
    0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
    0x00, 0x2b, 0x00, 0x07, 0x06, 0x7f, 0x1c, 0x7f, 0x1b, 0x7f, 0x1a, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x2f, 0x35, 0x0c, 0xb6, 0x90,
    0x0a, 0xb7, 0xd5, 0xc4, 0x1b, 0x2f, 0x60, 0xaa, 0x56, 0x7b, 0x3f, 0x71, 0xc8, 0x01, 0x7e, 0x86,
    0xd3, 0xb7, 0x0c, 0x29, 0x1a, 0x9e, 0x5b, 0x38, 0x3f, 0x01, 0x72,
];
/// Go common/protocol/tls/sniff_test.go, case 4 (an IP SNI).
const TLS_IP_SNI: &[u8] = &[
    0x16, 0x03, 0x01, 0x01, 0x03, 0x01, 0x00, 0x00, 0xff, 0x03, 0x03, 0x3d, 0x89, 0x52, 0x9e, 0xee,
    0xbe, 0x17, 0x63, 0x75, 0xef, 0x29, 0xbd, 0x14, 0x6a, 0x49, 0xe0, 0x2c, 0x37, 0x57, 0x71, 0x62,
    0x82, 0x44, 0x94, 0x8f, 0x6e, 0x94, 0x08, 0x45, 0x7f, 0xdb, 0xc1, 0x00, 0x00, 0x3e, 0xc0, 0x2c,
    0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
    0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
    0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x13, 0x02, 0x13, 0x03,
    0x13, 0x01, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x98,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x31, 0x30, 0x2e, 0x34, 0x32, 0x2e, 0x30,
    0x2e, 0x32, 0x34, 0x33, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0a,
    0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d,
    0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
    0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02,
    0x06, 0x02, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x7f,
    0x14, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x03, 0x02, 0x01, 0x00, 0x00, 0x28,
    0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x13, 0x7c, 0x6e, 0x97, 0xc4, 0xfd, 0x09, 0x2e,
    0x70, 0x2f, 0x73, 0x5a, 0x9b, 0x57, 0x4d, 0x5f, 0x2b, 0x73, 0x2c, 0xa5, 0x4a, 0x98, 0x40, 0x3d,
    0x75, 0x6e, 0xb4, 0x76, 0xf9, 0x48, 0x8f, 0x36,
];

/// Go TestSniffQUIC: one QUIC v1 initial packet carrying a full client hello.
const QUIC_PKT: &str = "cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b";
/// Go's "NTP Packet Client" case: a short-header UDP payload, not QUIC.
const QUIC_NTP: &str = "23000000000000000000000000000000000000000000000000000000000000000000000000000000acb84a797d4044c9";
/// Go's "QUIC Chromebook Handshake[1]; packet 1": the client hello does not
/// complete within this packet.
const QUIC_CB1_P1: &str = "cb00000001088ca3be26059ca269000044d088950f316207d551c91c88d791557c440a19184322536d2c900034358c1b3964f2d2935337b8d044d35bf62b4eea9ceaac64121aa634c7cd28630722d169fa0f215b940d47d7996ca56f0d463dbf97a4a1b5818c5297a26fe58f5553dfb513ad589750a61682f229996555c7121c8bf48b06b68ab06427b01af485d832f9894099a20d3baadcff7b1cf07e2c059d3e7ba88d4ad35ef0ffea1fdc6ac3db271dfcca892a41ab25284936225c9bc593ce242b11b8abed4a8df902987eef0c6d90669e3606f47dd6ad05f44ba3a0cd356854261bbb1e2d8f6b83cc57cfa57eda3e5d7181b6ec418f6eeca81c259a33e4b0a913de720f2f8782764766ac9602a7f52a1082ec3da30dbefcf38c781a3e033810c4f2babf9b72adf7164159d98142181492e4468c0e10ab29013bf238e7360e09767ca49d59a9eb18f06a372bad711fefa90295f8e0839b1080570648212b321e5bd6f614bf0d3dc2817628b0c052a32820c16cb7f531c49244c48eb1429625246f9c164ae4ee1e83eaa8ff0eef1acf5a3d8ca88f1e4597db5ba5c0cb23d6100dd53da4f439ae64c4d3d43d1fbb5677f4fdc3bd2c2948dfc7e0be1a33c842033da15529cfd3cae00da68343d835db867f746854804410ba68f0dd7711b0fe55817b83f6ce1a12ad38acf2a3156f819f0dc68ea799c05583d9728f2856577811b260dba40d6c5e82c9e558c5b8f3f4599caf05ea591118e0b80ad621e0a76e4926047593a896752cb168420cb1b02d4211de5e5b7c891f319b5c0cf687e1d261a01f2acbade6bd73cd1ade0a02e240e9351384e1a6868c21a4878f39f0fa94ee1e36c5a46449241a3fe0147ff50176787eca7f3a936c901aeef56770bff74feecb985e6670d20dfd8ed17952dca5a5292213345c61db09bb5bcf5bf74565f61f9dccab51a289c3160ffe4a9b29cc76ea46778d9317a890efea2ad905f4219463a3baca3c02f5c3682634be7c2e86e366272a8263fec8e871644a79299d4aa74f1b1414b2f963cce6e059978faf813625af7869c1dec92035478c0e46dc66d938d4131aca27a59b2103b8cefa8e08aeb44b53b205b932902aea8d519faaaa12e354a6f532b4f716d7929e655dc2e98b494a99153854af5732a2659f2c21e4069896a1835ad05c5e53781cab16599cf4af47c196deeff9115c80d13f93aeb28b08023e6a1d3cf7da2a4457a9e443176bcdfef8f8de630c02bd0efdc5ddda56ad8f6b47edbda6353205e6e655f690092a48deb7f8a5254a7d778e07216cd97dfefcf740c1acd2977ef0fa17f798ea9752bae46e3aa3ec9b13f4c95c20a7839b8409000fa1f17e8dc46cc05c41bff696ee03c0371cae8638e8018ff4ebedd9f27d56443e534a72dd3d18a64790b676ddd060376759fa4a12ffc17f4be83492126ec1dc0fcd4aefef73a0b9c443ec3532b9a66b1a60daacf45e6557115edc0cc4d08758754a44beffedaa0d1265e50beed1a01752904ee3f7e706ed290b1a79071b142105b7c02e692ff318710e3ce9c3b9ec557cdecef173796417341ada414faa06b52adf645db454b56468ccf0da50a942ebc09487797cb45a085ec1e2e06fcd1f5b72eac291955a62e5aa379a374aea3a0dec3e4e0ba1dde350a94c72dbea7505922e26e99d62f751c2b301413a73fb6b20a36052151473ebecd04d0a771ec326957bc28c2020fdf6f01d9abed69b3c3e73168b404a1748b15310b167396da01c7d";
/// Go's "QUIC Chromebook Handshake[1]; packet 1 - 2": two packets whose
/// CRYPTO frames complete the client hello.
const QUIC_CB1_P12: &str = "cb00000001088ca3be26059ca269000044d088950f316207d551c91c88d791557c440a19184322536d2c900034358c1b3964f2d2935337b8d044d35bf62b4eea9ceaac64121aa634c7cd28630722d169fa0f215b940d47d7996ca56f0d463dbf97a4a1b5818c5297a26fe58f5553dfb513ad589750a61682f229996555c7121c8bf48b06b68ab06427b01af485d832f9894099a20d3baadcff7b1cf07e2c059d3e7ba88d4ad35ef0ffea1fdc6ac3db271dfcca892a41ab25284936225c9bc593ce242b11b8abed4a8df902987eef0c6d90669e3606f47dd6ad05f44ba3a0cd356854261bbb1e2d8f6b83cc57cfa57eda3e5d7181b6ec418f6eeca81c259a33e4b0a913de720f2f8782764766ac9602a7f52a1082ec3da30dbefcf38c781a3e033810c4f2babf9b72adf7164159d98142181492e4468c0e10ab29013bf238e7360e09767ca49d59a9eb18f06a372bad711fefa90295f8e0839b1080570648212b321e5bd6f614bf0d3dc2817628b0c052a32820c16cb7f531c49244c48eb1429625246f9c164ae4ee1e83eaa8ff0eef1acf5a3d8ca88f1e4597db5ba5c0cb23d6100dd53da4f439ae64c4d3d43d1fbb5677f4fdc3bd2c2948dfc7e0be1a33c842033da15529cfd3cae00da68343d835db867f746854804410ba68f0dd7711b0fe55817b83f6ce1a12ad38acf2a3156f819f0dc68ea799c05583d9728f2856577811b260dba40d6c5e82c9e558c5b8f3f4599caf05ea591118e0b80ad621e0a76e4926047593a896752cb168420cb1b02d4211de5e5b7c891f319b5c0cf687e1d261a01f2acbade6bd73cd1ade0a02e240e9351384e1a6868c21a4878f39f0fa94ee1e36c5a46449241a3fe0147ff50176787eca7f3a936c901aeef56770bff74feecb985e6670d20dfd8ed17952dca5a5292213345c61db09bb5bcf5bf74565f61f9dccab51a289c3160ffe4a9b29cc76ea46778d9317a890efea2ad905f4219463a3baca3c02f5c3682634be7c2e86e366272a8263fec8e871644a79299d4aa74f1b1414b2f963cce6e059978faf813625af7869c1dec92035478c0e46dc66d938d4131aca27a59b2103b8cefa8e08aeb44b53b205b932902aea8d519faaaa12e354a6f532b4f716d7929e655dc2e98b494a99153854af5732a2659f2c21e4069896a1835ad05c5e53781cab16599cf4af47c196deeff9115c80d13f93aeb28b08023e6a1d3cf7da2a4457a9e443176bcdfef8f8de630c02bd0efdc5ddda56ad8f6b47edbda6353205e6e655f690092a48deb7f8a5254a7d778e07216cd97dfefcf740c1acd2977ef0fa17f798ea9752bae46e3aa3ec9b13f4c95c20a7839b8409000fa1f17e8dc46cc05c41bff696ee03c0371cae8638e8018ff4ebedd9f27d56443e534a72dd3d18a64790b676ddd060376759fa4a12ffc17f4be83492126ec1dc0fcd4aefef73a0b9c443ec3532b9a66b1a60daacf45e6557115edc0cc4d08758754a44beffedaa0d1265e50beed1a01752904ee3f7e706ed290b1a79071b142105b7c02e692ff318710e3ce9c3b9ec557cdecef173796417341ada414faa06b52adf645db454b56468ccf0da50a942ebc09487797cb45a085ec1e2e06fcd1f5b72eac291955a62e5aa379a374aea3a0dec3e4e0ba1dde350a94c72dbea7505922e26e99d62f751c2b301413a73fb6b20a36052151473ebecd04d0a771ec326957bc28c2020fdf6f01d9abed69b3c3e73168b404a1748b15310b167396da01c7dc700000001088ca3be26059ca269000044d00a7e7a252620d0fdfb63c0c193d6a9fe6a36aa9ce1b29dfa5f11f2567850b88384a2cc682eca2e292749365b833e5f7540019cd4f3143ed078aec07990b0d6ece18310403e73e1fe2975a8f9cb05796fa6196faaba3ee12a22b63a28a624cf4f7bedd44de000dc5ea698c65664df995b7d5fade0aab1cf0ecc5afd5ecb8fb80deecae3a8c97c20171f00ac3b5dc9a9027ca9c25571c72bb32070f6e3fb583560b0da6041b72e0a9601b8ad17d3c45e9dcc059f9f4758e8c35a839a9f6f4c501cb64e32e886fc733bc51069fbe4406f04d908285974c387d5b3e5f0f674941d05993bf8bda0d5ffd8c4fb528e150ff4bf37e38bd9c6346816fe360d4a206da81e815c1f7905184b6146b33427c6e38f1179981c18b82a3544442dd997c182d956037ae8f106eaf67ba133e7f15f1550b257d431f01ba0472659c6a5c2e6ff5e4ce9e692f4ef9fb169a75df4eb13f0b20e1994f3f8687bdca300c7e749af7b7a3b6597a6b950fe378a68c77766fdabe95248ed41d37805756b7ffa9cee0898bd661f6657cbf1af9aa8c7e437d432ca854c95307e6a7dfb6504ee3f7852fb3c246d168a03810b6c3d4e3d40bdee3def579effb66563f5bac98cfa1b071cd6f33e425e016bb3514a183b72cb3a393e9e519ba60e2177c98f530835e3b6eab78cdcb8abdbc769bc07e10c8e38bea710d5de1bdb2fa8d0d9b19e8cc31d16725a696e55342c89b667497e3d7f90e48f8503d8ead2a32a1930c3b24a4a9dcf2d8ec781705dd97d7df6e26828712fe42114419d5b8346bd86c239bd02f34e55f71400cb10c1fac7d8efa1a2ab258c17ace4288c8576ab92447b648fd15f4e038ec1c81a135e3bbb6f581a994c6a4902aeb1b5588cb1b5b53c8540296d96b6d2eccd67bae9609233f36304b5186d4698b88bb3ce8b1191a62b990436cf10718fd5759cb2281ac122f49ccbef8a3206348c1a930e7fc4bb498a11d89374e1480c7b8725b5f65e8c8d6f58da17f9134abce77eb9a6fcda514e7d3ab2e3610f86945f0dca519a3844da1b3a4b0e03c80528a2f79be478d07ff26166e30294bf0e69bf07a5bbd6d879adf6d618a1ec8365023408980bf67f0525a2fdee97fccc38fe104d4f58ed15e3671dfedf684856a27fbe286adba40ff0336def93f0174e9e35d341f5de73190d330d72227db9a866b69418e17e8e19ec884c1ffe2f0ad6deec37c9d49d536d0242fab282b0cf86cc9b15341757e0d361bddcbe5cbb062b3148d7c3c62af5c5dd5922a49920f351647030f62ed16929a404aa514fcbc38e67ba4f275e02a04c486b1a8e5b5efda197fd63e6f41fdeffa652c690dd6b00ca65df3688672ead9744f7d631e42e3b42f3ed1bff51b30f89211a7467cde65eab3659af7690cf307420a5823f31999d8f63c6c6ba0296ed4a46d5df6404f8db33e7252cc6bfcf7f55fee1f1e3b0573b6c6615793ff0691b7cfd23c195f66eb333d7efb0cfb74cf159787f87ad01fc131c6763bb1117bbfb8c2e8197ffba6b8c747565b1332bdbd6553b840939c2f98aa8eb1c549491c640e012fc549852fa7a93f81e5db152c761fc7d01bce0325619965c09f6730a162e7be53af7d9ce4b5ac0f4eb487361d2ac231d4ce92e5d9a084bc7b609ccf60056ecc82cd0c06a088cfbcf7d764b3109331c42f989da82b05cfe4c134a6784e664fa67a89c0624e3cc73ccfdea3f292db28f7c7b1b109f680f6b537f135c62f764";

#[test]
fn http_sniffing_matches_go_fixtures() {
    // Go common/protocol/http/sniff_test.go, cases 1 and 2 (exact bytes).
    assert_matched(
        sniff_http(
            b"GET /tutorials/other/top-20-mysql-best-practices/ HTTP/1.1\n\
              Host: net.tutsplus.com\n\
              User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\n\
              Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n\
              Accept-Language: en-us,en;q=0.5\n\
              Accept-Encoding: gzip,deflate\n\
              Accept-Charset: ISO-8859-1,utf-8;q=0.7,*/*;q=0.7\n\
              Keep-Alive: 300\n\
              Connection: keep-alive\n\
              Cookie: PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120\n\
              Pragma: no-cache\n\
              Cache-Control: no-cache",
        ),
        "http1",
        "net.tutsplus.com",
    );
    assert_matched(
        sniff_http(
            b"POST /foo.php HTTP/1.1\n\
              Host: localhost\n\
              User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\n\
              Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n\
              Accept-Language: en-us,en;q=0.5\n\
              Accept-Encoding: gzip,deflate\n\
              Accept-Charset: ISO-8859-1,utf-8;q=0.7,*/*;q=0.7\n\
              Keep-Alive: 300\n\
              Connection: keep-alive\n\
              Referer: http://localhost/test.php\n\
              Content-Type: application/x-www-form-urlencoded\n\
              Content-Length: 43\n\
              \n\
              first_name=John&last_name=Doe&action=Submit",
        ),
        "http1",
        "localhost",
    );
    // Case 3: an unknown method is definitive (errNotHTTPMethod).
    assert!(matches!(
        sniff_http(
            b"X /foo.php HTTP/1.1\n\
              Host: localhost\n\
              Accept: text/html\n"
        ),
        Outcome::Rejected
    ));
    // Case 4: the Host header after the empty line ends the header scan —
    // no host is seen, so the sniffer stays inconclusive (ErrNoClue).
    assert!(matches!(
        sniff_http(
            b"GET /foo.php HTTP/1.1\n\
              User-Agent: Mozilla/5.0\n\
              Content-Length: 43\n\
              \n\
              Host: localhost\n\
              first_name=John&last_name=Doe&action=Submit",
        ),
        Outcome::NoClue
    ));
    // Case 5: a request line without any header.
    assert!(matches!(
        sniff_http(b"GET /tutorials/other/top-20-mysql-best-practices/ HTTP/1.1"),
        Outcome::NoClue
    ));
}

#[test]
fn http_host_parsing_follows_go_parse_host() {
    // CRLF headers; the Host port is validated then dropped; the domain
    // lowercases; an IP host canonicalizes through net.ParseAddress.
    assert_matched(
        sniff_http(b"GET / HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n"),
        "http1",
        "example.com",
    );
    assert_matched(
        sniff_http(b"GET / HTTP/1.1\r\nHost: 10.42.0.243\r\n\r\n"),
        "http1",
        "10.42.0.243",
    );
    assert_matched(
        sniff_http(b"GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"),
        "http1",
        "::1",
    );
    // Go's SplitHostPort "too many colons" drops the sniffer.
    assert!(matches!(
        sniff_http(b"GET / HTTP/1.1\r\nHost: ::1\r\n\r\n"),
        Outcome::Rejected
    ));
    // A non-numeric port is a ParseHost error.
    assert!(matches!(
        sniff_http(b"GET / HTTP/1.1\r\nHost: host:NaN\r\n\r\n"),
        Outcome::Rejected
    ));
    // A prefix shorter than "get" is inconclusive (ErrNoClue).
    assert!(matches!(sniff_http(b"GE"), Outcome::NoClue));
}

#[test]
fn tls_sniffing_matches_go_fixtures() {
    assert_matched(sniff_tls(TLS_MICROSOFT), "tls", "c.s-microsoft.com");
    assert_matched(sniff_tls(TLS_CLICKTALE), "tls", "www07.clicktale.net");
    assert_matched(sniff_tls(TLS_DOGFISH), "tls", "dogfish");
    assert_matched(sniff_tls(TLS_IP_SNI), "tls", "10.42.0.243");
}

#[test]
fn tls_sniffing_rejects_and_defers_like_go() {
    // Not a handshake record (errNotTLS).
    assert!(matches!(
        sniff_tls(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
        Outcome::Rejected
    ));
    // A wrong TLS major version.
    assert!(matches!(
        sniff_tls(&[0x16, 0x02, 0x03, 0x00, 0x10]),
        Outcome::Rejected
    ));
    // Truncated payloads stay inconclusive (ErrNoClue).
    assert!(matches!(sniff_tls(b""), Outcome::NoClue));
    assert!(matches!(sniff_tls(&[0x16, 0x03]), Outcome::NoClue));
    assert!(matches!(
        sniff_tls(&[0x16, 0x03, 0x01, 0x00, 0xff, 0x01]),
        Outcome::NoClue
    ));
}

#[test]
fn quic_sniffing_matches_go_fixture() {
    // Go TestSniffQUIC: initial packet, header protection, AES-128-GCM and
    // the SNI from the reassembled client hello.
    let mut packet = decode_hex(QUIC_PKT);
    assert_matched(sniff_quic(&mut packet), "quic", "www.google.com");
}

#[test]
fn quic_sniffing_rejects_non_quic_payloads() {
    // Go's "NTP Packet Client": a short header, so not an initial packet.
    let mut packet = decode_hex(QUIC_NTP);
    assert!(matches!(sniff_quic(&mut packet), Outcome::Rejected));
    // An empty payload is inconclusive.
    assert!(matches!(sniff_quic(&mut []), Outcome::NoClue));
}

#[test]
fn quic_crypto_data_spans_packets() {
    // Go's "QUIC Chromebook Handshake[1]; packet 1": the CRYPTO frames do
    // not complete the client hello — more packets are needed.
    let mut packet = decode_hex(QUIC_CB1_P1);
    assert!(matches!(sniff_quic(&mut packet), Outcome::NeedMoreData));
    // ...packets 1 - 2 complete it.
    let mut packets = decode_hex(QUIC_CB1_P12);
    assert_matched(sniff_quic(&mut packets), "quic", "dns.google");
}

#[test]
fn dispatcher_pipeline_selects_sniffers_by_network() {
    // TCP runs http before tls (Go's NewSniffer order); an HTTP request
    // matches through the pipeline.
    let mut sniffers = Sniffers::new(Network::Tcp);
    let mut request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let flow = sniffers.sniff(&mut request);
    assert!(matches!(&flow, SniffFlow::Matched(result) if result.protocol == "http1"));
    // A TLS client hello through the same TCP pipeline.
    let mut sniffers = Sniffers::new(Network::Tcp);
    let mut hello = TLS_CLICKTALE.to_vec();
    let flow = sniffers.sniff(&mut hello);
    assert!(matches!(&flow, SniffFlow::Matched(result) if result.protocol == "tls"));
    // An empty payload keeps every sniffer pending (ErrNoClue).
    let mut sniffers = Sniffers::new(Network::Tcp);
    assert!(matches!(sniffers.sniff(&mut []), SniffFlow::NoClue));
    // UDP runs only quic: an HTTP request is unknown content there.
    let mut sniffers = Sniffers::new(Network::Udp);
    assert!(matches!(
        sniffers.sniff(&mut request),
        SniffFlow::UnknownContent
    ));
}

#[tokio::test]
async fn async_sniff_replays_peeked_bytes_for_the_relay() {
    let (mut client, server) = tokio::io::duplex(8192);
    let request = b"GET /path HTTP/1.1\r\nHost: www.example.org\r\n\r\n";
    client.write_all(request).await.unwrap();
    client.flush().await.unwrap();
    let (mut sniffed, result) = tokio::time::timeout(
        Duration::from_secs(5),
        sniff(server, Network::Tcp, false, SniffLimits::default()),
    )
    .await
    .expect("sniffing is bounded by its deadline");
    let result = result.expect("the HTTP request is sniffed");
    assert_eq!(result.protocol, "http1");
    assert_eq!(result.domain, "www.example.org");
    // Every peeked byte is replayed in front of the relay (Go cachedReader).
    let mut relayed = vec![0u8; request.len()];
    sniffed.read_exact(&mut relayed).await.unwrap();
    assert_eq!(relayed, request);
    assert!(sniffed.pending().is_empty());
}

#[tokio::test]
async fn metadata_only_sniffs_nothing_and_consumes_no_bytes() {
    let (mut client, server) = tokio::io::duplex(8192);
    client
        .write_all(b"GET /path HTTP/1.1\r\nHost: www.example.org\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let (mut sniffed, result) = sniff(server, Network::Tcp, true, SniffLimits::default()).await;
    // Without the (unported) fakedns metadata sniffer, metadataOnly yields
    // no result — and the payload was not read at all.
    assert!(result.is_none());
    assert!(sniffed.pending().is_empty());
    let mut relayed = vec![0u8; 4];
    sniffed.read_exact(&mut relayed).await.unwrap();
    assert_eq!(&relayed, b"GET ");
}

#[tokio::test]
async fn inconclusive_streams_give_up_within_the_budget() {
    let (_client, server) = tokio::io::duplex(64);
    let limits = SniffLimits {
        payload_bytes: 1024,
        cache_deadline: Duration::from_millis(20),
        attempts: 2,
    };
    let (sniffed, result) = tokio::time::timeout(
        Duration::from_secs(5),
        sniff(server, Network::Tcp, false, limits),
    )
    .await
    .expect("sniffing is bounded by its deadline");
    // errSniffingTimeout: no result, no buffered bytes, no hang.
    assert!(result.is_none());
    assert!(sniffed.pending().is_empty());
}

fn compile_request(value: serde_json::Value) -> anyhow::Result<Option<SniffingRequest>> {
    let config: xray_core::config::SniffingConfig = serde_json::from_value(value).unwrap();
    let store = xray_core::geodata::GeoDataStore::from_env().unwrap();
    SniffingRequest::compile(Some(&config), &store)
}

#[test]
fn sniffing_request_compiles_dest_override_and_flags() {
    // Go's Build normalizes https/ssl to tls and lowercases entries.
    let request = compile_request(serde_json::json!({
        "enabled": true,
        "destOverride": ["https", "ssl", "TLS", "quic"],
    }))
    .unwrap()
    .unwrap();
    assert_eq!(request.dest_override, ["tls", "tls", "tls", "quic"]);
    assert!(!request.route_only);
    assert!(!request.metadata_only);

    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["http"], "routeOnly": true, "metadataOnly": true,
    }))
    .unwrap()
    .unwrap();
    assert!(request.route_only);
    assert!(request.metadata_only);

    // Disabled or absent sniffing compiles to None — after validation: Go's
    // Build validates destOverride regardless of enabled.
    assert!(
        compile_request(serde_json::json!({"enabled": false, "destOverride": ["fakedns"]}))
            .is_err()
    );
    assert!(
        compile_request(serde_json::json!({"enabled": false, "destOverride": ["http"]}))
            .unwrap()
            .is_none()
    );
    assert!(
        SniffingRequest::compile(None, &xray_core::geodata::GeoDataStore::from_env().unwrap())
            .unwrap()
            .is_none()
    );

    // fakedns and unknown protocols fail explicitly.
    let error =
        compile_request(serde_json::json!({"enabled": true, "destOverride": ["fakedns+others"]}))
            .unwrap_err();
    assert!(error.to_string().contains("fakedns"));
    assert!(
        compile_request(serde_json::json!({"enabled": true, "destOverride": ["smtp"]})).is_err()
    );
}

#[test]
fn override_decision_follows_go_should_override() {
    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["http", "tls"],
    }))
    .unwrap()
    .unwrap();
    let destination = Destination::new("192.0.2.1", 443).unwrap();
    assert!(request.should_override(&sniffed("tls", "www.example.org"), &destination));
    // Go's bidirectional prefix match: destOverride "http" matches the
    // sniffed "http1".
    assert!(request.should_override(&sniffed("http1", "a.example.org"), &destination));
    // No sniffed domain, no override.
    assert!(!request.should_override(&sniffed("tls", ""), &destination));
    // A protocol outside destOverride never overrides.
    assert!(!request.should_override(&sniffed("quic", "dns.example.org"), &destination));

    // destination_override carries routeOnly (Go's Dispatch block).
    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["tls"], "routeOnly": true,
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        request.destination_override(&sniffed("tls", "x.example.org"), &destination),
        Some(Override {
            domain: "x.example.org".to_owned(),
            route_only: true,
        })
    );
    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["tls"],
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        request
            .destination_override(&sniffed("tls", "x.example.org"), &destination)
            .map(|overridden| overridden.route_only),
        Some(false)
    );
}

#[test]
fn override_exclusions_follow_go_rules() {
    // domainsExcluded are Go's Domain_Substr rules, matched lowercased.
    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["http"], "domainsExcluded": ["google.com"],
    }))
    .unwrap()
    .unwrap();
    let destination = Destination::new("192.0.2.1", 80).unwrap();
    assert!(!request.should_override(&sniffed("http1", "www.google.com"), &destination));
    assert!(request.should_override(&sniffed("http1", "example.org"), &destination));
    // ipsExcluded applies only when the original destination is an IP.
    let request = compile_request(serde_json::json!({
        "enabled": true, "destOverride": ["http"], "ipsExcluded": ["10.0.0.0/8"],
    }))
    .unwrap()
    .unwrap();
    let in_range = Destination::new("10.1.2.3", 80).unwrap();
    let outside = Destination::new("192.0.2.1", 80).unwrap();
    let domain = Destination::new("example.org", 80).unwrap();
    assert!(!request.should_override(&sniffed("http1", "internal.example.org"), &in_range));
    assert!(request.should_override(&sniffed("http1", "www.example.org"), &outside));
    assert!(request.should_override(&sniffed("http1", "www.example.org"), &domain));
}

fn routing_config(rules: serde_json::Value) -> Config {
    serde_json::from_value(serde_json::json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {"rules": rules},
    }))
    .unwrap()
}

fn route_context(destination: &Destination) -> RouteContext<'_> {
    RouteContext {
        destination,
        source: "127.0.0.1:5000".parse().unwrap(),
        inbound_tag: "edge",
        user: "",
        network: "tcp",
    }
}

#[test]
fn protocol_rules_match_sniffed_protocols_only() {
    let config = routing_config(serde_json::json!([
        {"protocol": ["tls"], "outboundTag": "blocked"},
    ]));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    let destination = Destination::new("192.0.2.1", 443).unwrap();
    let context = route_context(&destination);
    // Without a sniffed protocol the rule never matches (Go's empty
    // GetProtocol) — the default outbound stays selected.
    assert_eq!(router.select_with_route_sniffed(&context, None), (0, false));
    assert_eq!(
        router.select_with_route_sniffed(&context, Some("tls")),
        (1, true)
    );
    assert_eq!(
        router.select_with_route_sniffed(&context, Some("quic")),
        (0, false)
    );
    // The pre-sniffing API keeps today's behavior.
    assert_eq!(router.select_with_route(&context), (0, false));
}

#[test]
fn protocol_rules_use_go_prefix_semantics() {
    let config = routing_config(serde_json::json!([
        {"protocol": ["http"], "outboundTag": "blocked"},
    ]));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    let destination = Destination::new("192.0.2.1", 443).unwrap();
    let context = route_context(&destination);
    // "http" matches the sniffed "http1"/"http2" by prefix.
    for protocol in ["http1", "http2"] {
        assert_eq!(
            router.select_with_route_sniffed(&context, Some(protocol)),
            (1, true),
            "{protocol}"
        );
    }
    assert_eq!(
        router.select_with_route_sniffed(&context, Some("tls")),
        (0, false)
    );
    // "bittorrent" is a valid rule name (nothing sniffs it yet).
    let config = routing_config(serde_json::json!([
        {"protocol": ["bittorrent"], "outboundTag": "blocked"},
    ]));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    assert_eq!(
        router.select_with_route_sniffed(&context, Some("bittorrent")),
        (1, true)
    );
    assert_eq!(
        router.select_with_route_sniffed(&context, Some("tls")),
        (0, false)
    );
}

#[test]
fn protocol_rules_are_conjunctive_with_other_conditions() {
    let config = routing_config(serde_json::json!([
        {"protocol": ["tls"], "domain": ["keyword:example"], "outboundTag": "blocked"},
    ]));
    let router = Router::compile(&config.routing, &config.outbounds).unwrap();
    let matching = Destination::new("www.example.org", 443).unwrap();
    let other = Destination::new("www.other.org", 443).unwrap();
    assert_eq!(
        router.select_with_route_sniffed(&route_context(&matching), Some("tls")),
        (1, true)
    );
    assert_eq!(
        router.select_with_route_sniffed(&route_context(&other), Some("tls")),
        (0, false)
    );
    assert_eq!(
        router.select_with_route_sniffed(&route_context(&matching), None),
        (0, false)
    );
}

#[test]
fn unknown_rule_protocols_are_rejected_explicitly() {
    for protocol in ["smtp", "http1", ""] {
        let config = routing_config(serde_json::json!([
            {"protocol": [protocol], "outboundTag": "blocked"},
        ]));
        let error = Router::compile(&config.routing, &config.outbounds)
            .unwrap_err()
            .to_string();
        assert!(error.contains("protocol"), "{protocol}: {error}");
    }
}

#[test]
fn inbound_sniffing_parses_with_go_shape() {
    let config = Config::from_json(
        r#"{
        "inbounds": [{
            "tag": "edge", "port": 1080, "protocol": "http",
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "https"],
                "domainsExcluded": ["cdn.example"],
                "ipsExcluded": ["10.0.0.0/8"],
                "metadataOnly": false,
                "routeOnly": true
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    }"#,
    )
    .unwrap();
    let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
    assert!(sniffing.enabled);
    assert!(sniffing.route_only);
    assert!(!sniffing.metadata_only);
    assert_eq!(sniffing.dest_override, ["http", "https"]);
    assert_eq!(sniffing.domains_excluded, ["cdn.example"]);
    assert_eq!(sniffing.ips_excluded, ["10.0.0.0/8"]);
    assert!(config.validate().is_ok());

    // Defaults are Go's zero values; a single string is a valid list.
    let config = Config::from_json(
        r#"{"inbounds": [{"port": 1080, "protocol": "http",
             "sniffing": {"enabled": true, "destOverride": "tls"}}],
             "outbounds": [{"protocol": "freedom"}]}"#,
    )
    .unwrap();
    let sniffing = config.inbounds[0].sniffing.as_ref().unwrap();
    assert_eq!(sniffing.dest_override, ["tls"]);
    assert!(sniffing.domains_excluded.is_empty());
    assert!(sniffing.ips_excluded.is_empty());
    assert!(!sniffing.route_only);
    assert!(!sniffing.metadata_only);
}

#[test]
fn inbound_sniffing_rejects_unknown_keys_and_values() {
    // Unknown keys are rejected with serde's deny_unknown_fields (the serde
    // message rides the error chain under the config context).
    let error = Config::from_json(
        r#"{"inbounds": [{"port": 1080, "protocol": "http",
             "sniffing": {"enabled": true, "destOveride": ["http"]}}],
             "outbounds": [{"protocol": "freedom"}]}"#,
    )
    .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("destOveride"), "{error}");

    // fakedns fails explicitly, even when sniffing is disabled (Go's Build
    // validates destOverride regardless of enabled).
    let config = Config::from_json(
        r#"{"inbounds": [{"port": 1080, "protocol": "http",
             "sniffing": {"enabled": false, "destOverride": ["fakedns+others"]}}],
             "outbounds": [{"protocol": "freedom"}]}"#,
    )
    .unwrap();
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("fakedns"), "{error}");

    // Unknown protocols and illegal exclusion rules fail validation.
    let config = Config::from_json(
        r#"{"inbounds": [{"port": 1080, "protocol": "http",
             "sniffing": {"enabled": true, "destOverride": ["smtp"]}}],
             "outbounds": [{"protocol": "freedom"}]}"#,
    )
    .unwrap();
    let error = format!("{:#}", config.validate().unwrap_err());
    assert!(error.contains("unknown sniffing protocol"), "{error}");
    let config = Config::from_json(
        r#"{"inbounds": [{"port": 1080, "protocol": "http",
             "sniffing": {"enabled": true, "domainsExcluded": ["geosite:missing"]}}],
             "outbounds": [{"protocol": "freedom"}]}"#,
    )
    .unwrap();
    assert!(config.validate().is_err());
}
