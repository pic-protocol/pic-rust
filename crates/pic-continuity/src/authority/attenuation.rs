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

//! Attenuation and materialization (Profile 0.2).
//!
//! - Removal attenuation applies only to `identity_context` and
//!   `invariants`, by section-local removal bitmap. A removed entry cannot
//!   reappear later in the same continuity.
//! - Execution-contract restriction is addition-only: proposed `[key, value]`
//!   tuples are validated, deduplicated by canonical key, sorted by canonical
//!   key (Unicode code point order), and appended with the **next**
//!   section-local indexes assigned by the settlement verifier — never by the
//!   workload. Constraints accumulate with logical AND.
//!
//! [`materialize`] produces the successor Indexed Authority Map; sections
//! subject to removal are re-materialized with fresh contiguous indexes, so
//! the same wire bitmap can address different entries at different
//! checkpoints (as in the reference walkthrough).

use super::bitmap::RemoveBitmap;
use super::indexed::{IndexedAuthorityMap, KvTuple};
use crate::error::RejectReason;
use std::collections::BTreeMap;

/// Parsed attenuations of one transition.
#[derive(Debug, Clone, Default)]
pub struct Attenuations {
    /// Removal bitmap over the `identity_context` section, if any.
    pub identity_context: Option<RemoveBitmap>,
    /// Removal bitmap over the `invariants` section, if any.
    pub invariants: Option<RemoveBitmap>,
    /// Proposed execution-contract additions, as canonical `[key, value]`
    /// tuples (unindexed: the verifier assigns indexes).
    pub execution_contract_additions: Vec<KvTuple>,
}

impl Attenuations {
    /// `true` when the transition proposes no authority change.
    pub fn is_empty(&self) -> bool {
        self.identity_context.is_none()
            && self.invariants.is_none()
            && self.execution_contract_additions.is_empty()
    }
}

/// Applies a removal bitmap to an indexed section, re-materializing the
/// survivors with fresh contiguous indexes in their canonical relative order.
fn apply_removal<T: Clone>(
    section: &BTreeMap<u32, T>,
    bitmap: Option<&RemoveBitmap>,
    section_name: &'static str,
) -> Result<BTreeMap<u32, T>, RejectReason> {
    match bitmap {
        None => Ok(section.clone()),
        Some(bm) => {
            bm.validate_against(section.len() as u32, section_name)?;
            let removed = bm.indices();
            let survivors = section
                .iter()
                .filter(|(i, _)| !removed.contains(i))
                .map(|(_, t)| t.clone());
            Ok(survivors.enumerate().map(|(i, t)| (i as u32, t)).collect())
        }
    }
}

/// Validates, deduplicates, and sorts proposed execution-contract additions,
/// then appends them to the section with the next section-local indexes.
fn apply_additions(
    section: &BTreeMap<u32, KvTuple>,
    additions: &[KvTuple],
) -> Result<BTreeMap<u32, KvTuple>, RejectReason> {
    let mut out = section.clone();
    if additions.is_empty() {
        return Ok(out);
    }

    let mut accepted: Vec<KvTuple> = Vec::with_capacity(additions.len());
    for (key, value) in additions {
        value.validate(key)?;
        accepted.push((key.clone(), value.clone()));
    }
    // Sort by canonical key; input array order never determines indexes.
    accepted.sort_by(|a, b| a.0.cmp(&b.0));
    // More than one accepted addition with the same canonical key is invalid.
    for pair in accepted.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(RejectReason::DuplicateAdditionKey(pair[0].0.clone()));
        }
    }

    let base = out.len() as u32;
    for (offset, tuple) in accepted.into_iter().enumerate() {
        out.insert(base + offset as u32, tuple);
    }
    Ok(out)
}

/// Materializes the successor authority: predecessor map plus the accepted
/// attenuations of one transition. Removal never adds authority; contract
/// entries are never removed, replaced, or weakened.
pub fn materialize(
    predecessor: &IndexedAuthorityMap,
    attenuations: &Attenuations,
) -> Result<IndexedAuthorityMap, RejectReason> {
    let identity_context = match &predecessor.identity_context {
        None => {
            if attenuations.identity_context.is_some() {
                return Err(RejectReason::BitmapIndexOutOfRange("identity_context"));
            }
            None
        }
        Some(section) => {
            let applied = apply_removal(
                section,
                attenuations.identity_context.as_ref(),
                "identity_context",
            )?;
            if applied.is_empty() {
                None
            } else {
                Some(applied)
            }
        }
    };

    let invariants = apply_removal(
        &predecessor.invariants,
        attenuations.invariants.as_ref(),
        "invariants",
    )?;

    let execution_contract = apply_additions(
        &predecessor.execution_contract,
        &attenuations.execution_contract_additions,
    )?;

    Ok(IndexedAuthorityMap {
        identity_context,
        invariants,
        execution_contract,
    })
}

/// The profile-defined attenuation order `≤` used for non-expansion
/// validation. A Verifier rejects a state whose order it cannot evaluate
/// deterministically.
pub trait AttenuationOrder {
    /// Returns true when `current` is equal to or more restrictive than
    /// `predecessor`.
    fn attenuates(&self, current: &IndexedAuthorityMap, predecessor: &IndexedAuthorityMap) -> bool;
}

/// The reference attenuation profile: invariants and identity entries use
/// subset inclusion; execution-contract constraints may only be preserved or
/// extended (accumulating with AND).
#[derive(Debug, Clone, Copy, Default)]
pub struct ReferenceProfile;

impl AttenuationOrder for ReferenceProfile {
    fn attenuates(&self, current: &IndexedAuthorityMap, predecessor: &IndexedAuthorityMap) -> bool {
        // invariants(current) ⊆ invariants(predecessor)
        let invariants_ok = current
            .invariants
            .values()
            .all(|t| predecessor.contains_invariant(t));

        // identity entries(current) ⊆ identity entries(predecessor)
        let identity_ok = match (&current.identity_context, &predecessor.identity_context) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(cur), Some(pred)) => cur.values().all(|t| pred.values().any(|p| p == t)),
        };

        // every predecessor contract entry is preserved in current
        let contract_ok = predecessor
            .execution_contract
            .values()
            .all(|t| current.contains_contract_entry(t));

        invariants_ok && identity_ok && contract_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::indexed::{InvariantTuple, TupleValue};
    use crate::authority::{AuthorityValue, Invariant, LogicalAuthority};

    fn walkthrough_pca0() -> IndexedAuthorityMap {
        let mut contract = std::collections::BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
        contract.insert(
            "department".into(),
            AuthorityValue::One("sensitive-documents".into()),
        );
        let logical = LogicalAuthority::new(
            None,
            vec![
                Invariant::new(
                    "documents:read:document-42",
                    "read",
                    "documents",
                    "document-42",
                ),
                Invariant::new("storage:save", "save", "storage", "*"),
            ],
            contract,
        );
        IndexedAuthorityMap::from_logical(&logical).unwrap()
    }

    /// The centralized-exchange walkthrough: two hops, both `h'01'`, because
    /// every checkpoint re-materializes its section-local indexes.
    #[test]
    fn walkthrough_two_hops_reindex() {
        let pca0 = walkthrough_pca0();
        assert_eq!(pca0.invariants[&0].0, "documents:read:document-42");
        assert_eq!(pca0.invariants[&1].0, "storage:save");

        // Worker 1: remove index 0 (the read invariant).
        let att1 = Attenuations {
            invariants: RemoveBitmap::from_indices(&[0]),
            ..Default::default()
        };
        assert_eq!(att1.invariants.as_ref().unwrap().bytes(), &[0x01]);
        let pca1 = materialize(&pca0, &att1).unwrap();
        assert_eq!(pca1.invariants.len(), 1);
        assert_eq!(pca1.invariants[&0].0, "storage:save"); // re-indexed to 0

        // Worker 2: the bitmap is h'01' again because storage:save is now
        // section-local index 0.
        let att2 = Attenuations {
            invariants: RemoveBitmap::from_indices(&[0]),
            ..Default::default()
        };
        let pca2 = materialize(&pca1, &att2).unwrap();
        assert!(pca2.invariants.is_empty());
        // The execution contract remains.
        assert_eq!(pca2.execution_contract.len(), 2);
    }

    #[test]
    fn dropped_authority_cannot_reappear() {
        let pca0 = walkthrough_pca0();
        let att = Attenuations {
            invariants: RemoveBitmap::from_indices(&[0]),
            ..Default::default()
        };
        let pca1 = materialize(&pca0, &att).unwrap();

        let dropped = InvariantTuple(
            "documents:read:document-42".into(),
            "read".into(),
            "documents".into(),
            "document-42".into(),
        );
        assert!(!pca1.contains_invariant(&dropped));
        // Removal is the only invariant mechanism: there is no encoding that
        // adds an invariant, so reappearance is unrepresentable by grammar.
    }

    #[test]
    fn contract_additions_sorted_appended_and_deduplicated() {
        let pca0 = walkthrough_pca0();
        let att = Attenuations {
            execution_contract_additions: vec![
                ("region".into(), TupleValue::Text("EU".into())),
                ("audit".into(), TupleValue::Text("required".into())),
            ],
            ..Default::default()
        };
        let next = materialize(&pca0, &att).unwrap();
        // Existing entries keep their indexes; additions are appended in
        // canonical key order with the next indexes.
        assert_eq!(next.execution_contract[&0].0, "corporation");
        assert_eq!(next.execution_contract[&1].0, "department");
        assert_eq!(next.execution_contract[&2].0, "audit");
        assert_eq!(next.execution_contract[&3].0, "region");

        let dup = Attenuations {
            execution_contract_additions: vec![
                ("region".into(), TupleValue::Text("EU".into())),
                ("region".into(), TupleValue::Text("US".into())),
            ],
            ..Default::default()
        };
        assert_eq!(
            materialize(&pca0, &dup).unwrap_err(),
            RejectReason::DuplicateAdditionKey("region".into())
        );
    }

    #[test]
    fn bitmap_out_of_range_rejected() {
        let pca0 = walkthrough_pca0();
        let att = Attenuations {
            invariants: RemoveBitmap::from_indices(&[2]),
            ..Default::default()
        };
        assert_eq!(
            materialize(&pca0, &att).unwrap_err(),
            RejectReason::BitmapIndexOutOfRange("invariants")
        );
    }

    #[test]
    fn reference_profile_non_expansion() {
        let pca0 = walkthrough_pca0();
        let att = Attenuations {
            invariants: RemoveBitmap::from_indices(&[0]),
            ..Default::default()
        };
        let pca1 = materialize(&pca0, &att).unwrap();

        let order = ReferenceProfile;
        assert!(order.attenuates(&pca1, &pca0));
        // The reverse direction expands authority.
        assert!(!order.attenuates(&pca0, &pca1));
    }
}
