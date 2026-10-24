# Upstream source

Based on [ssh-agent-client-rs 1.1.4](https://crates.io/crates/ssh-agent-client-rs/1.1.4)
by Noa Resare. Published source commit:
[`565c3560`](https://github.com/nresare/ssh-agent-client-rs/commit/565c3560ac2cdaec28c2d8efbb9adbed5412d837).
Archive SHA256: `4d22c5f4ab58452cce2806ef98abec5012c078aeb07936ea13d8a39928b3af2b`.
The MIT and Apache-2.0 licenses are retained in this directory.

The three production Rust files are unchanged. The normal SSH key features
are `std` and the structural `ecdsa` parser. Tests enable Ed25519 signing.
The `crypto` aggregate is not enabled. Existing wire-format tests remain;
a mixed Ed25519, RSA and ECDSA identity-list fixture covers the parser features.

The original example verified RSA and ECDSA locally. This package's example
explicitly accepts Ed25519 only; agent forwarding is unaffected.
