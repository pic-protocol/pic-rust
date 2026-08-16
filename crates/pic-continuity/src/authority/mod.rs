/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Authority: logical form, canonical indexed form, attenuation.
//!
//! - [`logical`] — the application-facing **Logical Context of Authority**:
//!   optional `identity_context` and `execution { invariants, contract }`;
//! - [`indexed`] — the deterministic canonicalization into the
//!   **Indexed Authority Map**, which removal bitmaps and additions address
//!   by section-local numeric index;
//! - [`bitmap`] — canonical LSB-first removal bitmaps;
//! - [`attenuation`] — materialization of accepted attenuations and the
//!   non-expansion order.

pub mod attenuation;
pub mod bitmap;
pub mod indexed;
pub mod logical;

pub use attenuation::{AttenuationOrder, Attenuations, ReferenceProfile, materialize};
pub use bitmap::RemoveBitmap;
pub use indexed::{IndexedAuthorityMap, InvariantTuple, KvTuple, TupleValue};
pub use logical::{AuthorityValue, Invariant, LogicalAuthority, LogicalExecution};
