# PIC Protocol — Rust Implementation

A Rust implementation of the **PIC Protocol** (Provenance Identity Continuity).

**Status:** Experimental

---

## About

This repository contains a reference implementation of the PIC Protocol as defined in the [PIC Specification](https://github.com/pic-protocol/pic-spec).

The **PIC Model** is original theoretical work created by **Nicola Gallo**.

This implementation is developed and maintained by **Nitro Agility S.r.l.**

---

## Crates

| Crate                                                       | Description                                                    |
|-------------------------------------------------------------|----------------------------------------------------------------|
| [`pic-protocol`](https://crates.io/crates/pic-protocol)     | The facade crate. Import this one; use it as `pic::continuity` |
| [`pic-continuity`](https://crates.io/crates/pic-continuity) | PIC Profile 0.2: continuity artifacts, Prover, and Verifier    |

```toml
[dependencies]
pic-protocol = "0.2"
```

```rust
use pic::continuity::verifier::{issue_settled, verify_settled};
```

Feature flags: `ed25519` (default), `p256`, `p384`, `full`. The protocol core is crypto-agnostic and
builds with no features enabled; signing and verification enter through traits.

See the [docs.rs documentation](https://docs.rs/pic-protocol) for a complete issue-and-verify example.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## References

- [PIC Specification](https://github.com/pic-protocol/pic-spec)
