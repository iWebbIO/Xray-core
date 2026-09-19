# Independent wire fixtures

These fixed hexadecimal files are actual protobuf `GeoIPList` and `GeoSiteList`
wire payloads for `common/geodata/geodat.proto`. They were assembled directly
from protobuf field keys, unsigned varints, and length-delimited bytes, without
using the Rust reader, Prost, or Go serialization. Tests decode the hex and write
ordinary `.dat` files, so the complete filesystem/cache/protobuf path is exercised.
They are small synthetic datasets, not claims about countries or public addresses.

`geoip.hex` contains PRIVATE (10.0.0.0/8 and fd00::/8), V4 (192.0.2.0/24,
with the legacy on-disk reverse flag set), EMPTY, and BROKEN (one invalid byte
length, one invalid prefix, and valid 198.51.100.0/24).

`geosite.hex` contains SITES with domain EXAMPLE.COM (ads=false, flag=7, !cn=true),
full EXACT.example (ads=true), regex `^re[0-9]+\\.example$` (flag=true), substring
needle (ads=true), invalid regex `[`, and unknown type 99. ALT contains full
old.example. The false/int attributes check presence rather than truthiness.
