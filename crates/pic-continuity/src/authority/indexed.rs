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

//! The canonical Indexed Authority Map (Profile 0.2).
//!
//! Sections are `identity_context`, `invariants`, and `execution_contract`.
//! Entries are compact tuples addressed by section-local numeric indexes
//! starting at `0`; JSON/CBOR member order carries no protocol meaning.
//!
//! Initial index assignment is deterministic:
//! - `identity_context` / `execution_contract`: collection memberships are
//!   denormalized into `[key:member, true]` tuples, candidates are sorted
//!   lexicographically by canonical key (Unicode code point order), then
//!   indexed `0, 1, 2, …`;
//! - `invariants`: candidates are sorted by `scope`, `operation`,
//!   `resourceType`, `resourceId`, then indexed.

use super::{AuthorityValue, Invariant, LogicalAuthority};
use crate::error::RejectReason;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A canonical tuple value: a string, or the boolean `true` used as the
/// canonical denormalized membership representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TupleValue {
    /// A plain string value.
    Text(String),
    /// The boolean `true`: the canonical denormalized membership marker.
    Membership(bool),
}

impl TupleValue {
    /// Only `true` is a valid membership value; Profile 0.2 defines no
    /// false-valued membership semantics.
    pub fn validate(&self, key: &str) -> Result<(), RejectReason> {
        match self {
            TupleValue::Text(s) if !s.is_empty() => Ok(()),
            TupleValue::Membership(true) => Ok(()),
            _ => Err(RejectReason::InvalidAuthorityValue(key.to_string())),
        }
    }
}

/// A `[key, value]` tuple for `identity_context` / `execution_contract`.
pub type KvTuple = (String, TupleValue);

/// A `[scope, operation, resourceType, resourceId]` tuple. Element order is
/// normative.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvariantTuple(pub String, pub String, pub String, pub String);

impl From<&Invariant> for InvariantTuple {
    fn from(i: &Invariant) -> Self {
        InvariantTuple(
            i.scope.clone(),
            i.operation.clone(),
            i.resource_type.clone(),
            i.resource_id.clone(),
        )
    }
}

/// The canonical Indexed Authority Map carried by `context_of_authority`
/// inside the PIC PCA COSE payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndexedAuthorityMap {
    /// Descriptive identity data; grants no execution authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_context: Option<BTreeMap<u32, KvTuple>>,
    /// Executable PIC authority; removal-only across transitions.
    pub invariants: BTreeMap<u32, InvariantTuple>,
    /// Execution constraints; additions-only across transitions, never empty.
    pub execution_contract: BTreeMap<u32, KvTuple>,
}

/// Denormalizes a logical key/value map into sorted, indexed canonical tuples.
fn denormalize_and_index(
    map: &BTreeMap<String, AuthorityValue>,
) -> Result<BTreeMap<u32, KvTuple>, RejectReason> {
    let mut candidates: Vec<KvTuple> = Vec::new();
    for (key, value) in map {
        value.validate(key)?;
        match value {
            AuthorityValue::One(s) => candidates.push((key.clone(), TupleValue::Text(s.clone()))),
            AuthorityValue::Many(members) => {
                for m in members {
                    candidates.push((format!("{key}:{m}"), TupleValue::Membership(true)));
                }
            }
        }
    }
    // Sort lexicographically by canonical key. Rust's byte-wise `str` order
    // coincides with Unicode code point order for UTF-8.
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    // Determinism requires unique canonical keys.
    for pair in candidates.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(RejectReason::DuplicateAdditionKey(pair[0].0.clone()));
        }
    }
    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(i, t)| (i as u32, t))
        .collect())
}

impl IndexedAuthorityMap {
    /// Deterministic canonicalization of a Logical Context of Authority.
    pub fn from_logical(logical: &LogicalAuthority) -> Result<Self, RejectReason> {
        logical.validate()?;

        let identity_context = match &logical.identity_context {
            Some(map) if !map.is_empty() => Some(denormalize_and_index(map)?),
            _ => None,
        };

        let mut invariants: Vec<InvariantTuple> = logical
            .execution
            .invariants
            .iter()
            .map(InvariantTuple::from)
            .collect();
        invariants.sort();
        let invariants = invariants
            .into_iter()
            .enumerate()
            .map(|(i, t)| (i as u32, t))
            .collect();

        let execution_contract = denormalize_and_index(&logical.execution.contract)?;

        Ok(Self {
            identity_context,
            invariants,
            execution_contract,
        })
    }

    /// Number of entries in a section (indexes are contiguous from 0).
    pub fn invariant_count(&self) -> u32 {
        self.invariants.len() as u32
    }

    /// Returns true when the given invariant tuple is present.
    pub fn contains_invariant(&self, tuple: &InvariantTuple) -> bool {
        self.invariants.values().any(|t| t == tuple)
    }

    /// Returns true when the given contract entry is present.
    pub fn contains_contract_entry(&self, entry: &KvTuple) -> bool {
        self.execution_contract.values().any(|t| t == entry)
    }

    /// Validates that this Indexed Authority Map is a Profile 0.2 canonical
    /// materialized authority map suitable for signing inside a PCA
    /// checkpoint.
    pub fn validate(&self) -> Result<(), RejectReason> {
        validate_contiguous_indexes(&self.invariants, "invariants")?;
        validate_contiguous_indexes(&self.execution_contract, "execution_contract")?;

        if let Some(identity_context) = &self.identity_context {
            if identity_context.is_empty() {
                return Err(RejectReason::Malformed(
                    "identity_context must be omitted when empty".into(),
                ));
            }
            validate_contiguous_indexes(identity_context, "identity_context")?;
            validate_kv_section(identity_context)?;
        }

        if self.execution_contract.is_empty() {
            return Err(RejectReason::EmptyExecutionContract);
        }
        validate_kv_section(&self.execution_contract)?;

        for tuple in self.invariants.values() {
            if tuple.0.is_empty() || tuple.1.is_empty() || tuple.2.is_empty() || tuple.3.is_empty()
            {
                return Err(RejectReason::Malformed(
                    "invariant tuple members must be non-empty".into(),
                ));
            }
        }

        Ok(())
    }
}

fn validate_contiguous_indexes<T>(
    section: &BTreeMap<u32, T>,
    section_name: &'static str,
) -> Result<(), RejectReason> {
    for (expected, actual) in section.keys().enumerate() {
        if *actual != expected as u32 {
            return Err(RejectReason::Malformed(format!(
                "{section_name} indexes must be contiguous from 0"
            )));
        }
    }
    Ok(())
}

fn validate_kv_section(section: &BTreeMap<u32, KvTuple>) -> Result<(), RejectReason> {
    for (key, value) in section.values() {
        if key.is_empty() {
            return Err(RejectReason::InvalidAuthorityValue(key.clone()));
        }
        value.validate(key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityValue;

    /// The payments example of the token/artifact article: canonical
    /// identity_context indexes must come out sorted by canonical key.
    #[test]
    fn canonicalization_matches_reference_example() {
        let mut identity = BTreeMap::new();
        identity.insert("type".into(), AuthorityValue::One("user".into()));
        identity.insert("id".into(), AuthorityValue::One("user-123".into()));
        identity.insert(
            "roles".into(),
            AuthorityValue::Many(vec!["payment-approver".into()]),
        );
        identity.insert(
            "groups".into(),
            AuthorityValue::Many(vec!["finance".into()]),
        );
        identity.insert(
            "securityDomain".into(),
            AuthorityValue::One("tenant-a".into()),
        );

        let mut contract = BTreeMap::new();
        contract.insert(
            "purpose".into(),
            AuthorityValue::One("payment-approval".into()),
        );
        contract.insert("currency".into(), AuthorityValue::One("EUR".into()));

        let logical = LogicalAuthority::new(
            Some(identity),
            vec![Invariant::new(
                "payments:approve",
                "approve",
                "payments",
                "*",
            )],
            contract,
        );

        let map = IndexedAuthorityMap::from_logical(&logical).unwrap();
        let id = map.identity_context.unwrap();

        assert_eq!(id[&0].0, "groups:finance");
        assert_eq!(id[&0].1, TupleValue::Membership(true));
        assert_eq!(id[&1].0, "id");
        assert_eq!(id[&2].0, "roles:payment-approver");
        assert_eq!(id[&3].0, "securityDomain");
        assert_eq!(id[&4].0, "type");

        assert_eq!(
            map.invariants[&0],
            InvariantTuple(
                "payments:approve".into(),
                "approve".into(),
                "payments".into(),
                "*".into()
            )
        );

        // corporation-style sorting: currency < purpose
        assert_eq!(map.execution_contract[&0].0, "currency");
        assert_eq!(map.execution_contract[&1].0, "purpose");
    }

    #[test]
    fn invariants_sorted_by_tuple_elements() {
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));

        let logical = LogicalAuthority::new(
            None,
            vec![
                Invariant::new("storage:save", "save", "storage", "*"),
                Invariant::new(
                    "documents:read:document-42",
                    "read",
                    "documents",
                    "document-42",
                ),
            ],
            contract,
        );

        let map = IndexedAuthorityMap::from_logical(&logical).unwrap();
        assert_eq!(map.invariants[&0].0, "documents:read:document-42");
        assert_eq!(map.invariants[&1].0, "storage:save");
    }

    #[test]
    fn rejects_empty_contract_and_invalid_values() {
        let logical = LogicalAuthority::default();
        assert_eq!(
            logical.validate().unwrap_err(),
            RejectReason::EmptyExecutionContract
        );

        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("".into()));
        let logical = LogicalAuthority::new(None, vec![], contract);
        assert!(matches!(
            logical.validate().unwrap_err(),
            RejectReason::InvalidAuthorityValue(_)
        ));

        let mut contract = BTreeMap::new();
        contract.insert("departments".into(), AuthorityValue::Many(vec![]));
        let logical = LogicalAuthority::new(None, vec![], contract);
        assert!(matches!(
            logical.validate().unwrap_err(),
            RejectReason::InvalidAuthorityValue(_)
        ));
    }

    #[test]
    fn cbor_roundtrip() {
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
        let logical = LogicalAuthority::new(
            None,
            vec![Invariant::new("storage:save", "save", "storage", "*")],
            contract,
        );
        let map = IndexedAuthorityMap::from_logical(&logical).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        let decoded: IndexedAuthorityMap = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(map, decoded);
    }
}
