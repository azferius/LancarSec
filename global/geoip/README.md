# GeoLite2 ASN database

Download `GeoLite2-ASN.mmdb` (free) from:
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Place the file here as `GeoLite2-ASN.mmdb`. LancarSec will pick it up at
startup and on every config reload. Without it, ASN-typed blocklist
entries are silently skipped and the `proxy-client-asn` header stays
empty.

The file is not bundled with LancarSec because MaxMind's license requires
each operator to register and accept terms.
