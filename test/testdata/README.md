# Test Data

Shared fixtures for unit tests and the in-process E2E suite (`test/e2e`).
All data is offline: no network, cloud credentials, or real hardware needed.

- `mmdb/` — MaxMind GeoLite2 test databases (City/ASN) reused from
  `pkg/firewall/ipgeo/test-data`.
- `keys/` — RSA key pair (PEM) for signing/verifying test JWTs; matches the
  public key embedded in `pkg/caddypaw/testdata` and `pkg/authn/testdata`.
- `configs/` — sample authn gateway config and the full authn server sample.
