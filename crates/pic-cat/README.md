# pic-cat

CAT (Causal Authority Transition) for the PIC Protocol.

**Status:** Experimental

---

## About

This crate is part of the reference implementation of the PIC Protocol as defined in the [PIC Specification](https://github.com/pic-protocol/pic-spec).

The **PIC Model** is original theoretical work created by **Nicola Gallo**.

This implementation is developed and maintained by **Nitro Agility S.r.l.**

---

## Overview

This crate provides the CAT (Causal Authority Transition) enforcement mechanism that validates PIC invariants:

- Issues PIC Causal Challenges (PCC)
- Verifies Proofs of Continuity (PoC)
- Derives successor authority states (PCA)
- Enforces monotonicity (`ops_{i+1} ⊆ ops_i`)

---

## Usage
```toml
[dependencies]
pic-cat = "0.1"
```
```rust
use pic_cat::*;
```

---

## Part of PIC Protocol

This crate is part of the [PIC Protocol](https://github.com/pic-protocol/pic-rust) Rust implementation.

---

## License

Licensed under the [Apache License 2.0](../../LICENSE).
