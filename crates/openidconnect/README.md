# [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) Library for Rust

This is Kunobi's companion package for upstream openidconnect 4.0.1
(commit b639b5d39eac6903238867aeb2b29326502e6b26). It uses P-256/P-384 0.14
with crypto-bigint 0.7.6 or newer, Ed25519-dalek 3 and HMAC 0.13. The HMAC
adapter uses the new digest API; RSA retains its compatible SHA-2/RNG families.
Upstream authorship and MIT licensing are retained. The package is named
kunobi-openidconnect; the library name remains openidconnect.

This library provides extensible, strongly-typed interfaces for the OpenID
Connect protocol, which can be used to authenticate users via
[Google](https://developers.google.com/identity/openid-connect/openid-connect),
[GitLab](https://docs.gitlab.com/ee/integration/openid_connect_provider.html),
[Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
and [many other providers](https://openid.net/certification/#OPENID-OP-P).

Upstream API documentation and examples are available on [docs.rs](https://docs.rs/openidconnect).

## Minimum Supported Rust Version (MSRV)

This companion package requires Rust **1.95**, matching kunobi-auth. Upstream *3.3* through *4.0.1* releases support Rust **1.65**.

The MSRV for upstream *3.0* to *3.2* releases is Rust **1.57**.

The MSRV for upstream *2.x* releases is Rust 1.45.

Since the 3.0.0 release, upstream maintains a policy of supporting
Rust releases going back at least 6 months. Changes that break compatibility with Rust releases
older than 6 months will no longer be considered SemVer breaking changes and will not result in a
new major version number for the upstream crate. MSRV changes coincide with minor version updates
and will not happen in patch releases.

## Standards

* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  * Supported features:
    * Relying Party flows: code, implicit, hybrid
    * Standard claims
    * UserInfo endpoint
    * RSA, HMAC, ECDSA (P-256/P-384 curves) and EdDSA (Ed25519 curve) ID token verification
  * Unsupported features:
    * Aggregated and distributed claims
    * Passing request parameters as JWTs
    * Verification of the `azp` claim (see [discussion](https://bitbucket.org/openid/connect/issues/973/))
    * ECDSA-based ID token verification using the P-521 curve
    * JSON Web Encryption (JWE)
* [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  * Supported features:
    * Provider Metadata
  * Unsupported features:
    * WebFinger
* [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
  * Supported features:
    * Client Metadata
    * Client Registration endpoint
  * Unsupported features:
    * Client Configuration endpoint
* [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
* [OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
* [OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
