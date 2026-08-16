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

//! The Logical Context of Authority: the application-facing JSON form.
//!
//! It is never embedded in a signed artifact directly;
//! [`super::indexed::IndexedAuthorityMap::from_logical`] canonicalizes it
//! into the Indexed Authority Map signed inside the PIC PCA COSE.

use crate::error::RejectReason;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A logical authority value: a non-empty string or a non-empty array of
/// non-empty strings. Profile 0.2 rejects numbers, booleans, objects, null,
/// empty strings, and empty arrays in the logical input domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorityValue {
    /// A single string value.
    One(String),
    /// A collection value; canonicalization denormalizes each member into a
    /// `[key:member, true]` tuple.
    Many(Vec<String>),
}

impl AuthorityValue {
    /// Validates the Profile 0.2 logical value rules.
    pub fn validate(&self, key: &str) -> Result<(), RejectReason> {
        let ok = match self {
            AuthorityValue::One(s) => !s.is_empty(),
            AuthorityValue::Many(v) => !v.is_empty() && v.iter().all(|s| !s.is_empty()),
        };
        if ok {
            Ok(())
        } else {
            Err(RejectReason::InvalidAuthorityValue(key.to_string()))
        }
    }
}

/// One executable authority invariant: `(scope, operation, resourceType, resourceId)`.
///
/// The logical JSON form uses camelCase member names (`resourceType`,
/// `resourceId`), matching the application-facing Context of Authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invariant {
    /// The authority scope, e.g. `documents:read:document-42`.
    pub scope: String,
    /// The operation the invariant permits.
    pub operation: String,
    /// The resource type the operation applies to.
    pub resource_type: String,
    /// The resource identifier, or `"*"` for the whole type.
    pub resource_id: String,
}

impl Invariant {
    /// An invariant from its four normative elements, in normative order.
    pub fn new(
        scope: impl Into<String>,
        operation: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            scope: scope.into(),
            operation: operation.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }
    }
}

/// The `execution` member of the Logical Context of Authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LogicalExecution {
    /// Executable PIC authority: what may be preserved or attenuated across
    /// continuity.
    pub invariants: Vec<Invariant>,
    /// Execution constraints. Constrains execution; grants no authority.
    pub contract: BTreeMap<String, AuthorityValue>,
}

/// The Logical Context of Authority: the application-facing JSON form
/// `{ identity_context?, execution: { invariants, contract } }`.
///
/// It is never embedded in a signed artifact directly.
/// [`super::indexed::IndexedAuthorityMap::from_logical`] produces the
/// canonical form that is signed inside the PIC PCA COSE; in that flattened
/// canonical representation, logical `execution.contract` maps to the
/// `execution_contract` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LogicalAuthority {
    /// Descriptive or contextual identity data. Optional; it does not grant
    /// execution authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_context: Option<BTreeMap<String, AuthorityValue>>,
    /// Executable authority and its execution constraints.
    pub execution: LogicalExecution,
}

impl LogicalAuthority {
    /// A Logical Context of Authority from its three parts.
    pub fn new(
        identity_context: Option<BTreeMap<String, AuthorityValue>>,
        invariants: Vec<Invariant>,
        contract: BTreeMap<String, AuthorityValue>,
    ) -> Self {
        Self {
            identity_context,
            execution: LogicalExecution {
                invariants,
                contract,
            },
        }
    }

    /// Validates the Profile 0.2 logical input rules: the execution contract
    /// contains at least one attribute, and every value (identity and
    /// contract) is a non-empty string or a non-empty array of non-empty
    /// strings.
    pub fn validate(&self) -> Result<(), RejectReason> {
        if self.execution.contract.is_empty() {
            return Err(RejectReason::EmptyExecutionContract);
        }
        for (k, v) in &self.execution.contract {
            v.validate(k)?;
        }
        if let Some(identity) = &self.identity_context {
            for (k, v) in identity {
                v.validate(k)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::indexed::{IndexedAuthorityMap, InvariantTuple, TupleValue};

    /// The logical PCA 0 JSON of the centralized-exchange walkthrough,
    /// verbatim: nested `execution`, camelCase invariant members. It must
    /// parse as a Logical Context of Authority and canonicalize into the
    /// walkthrough's Indexed Authority Map.
    #[test]
    fn logical_json_matches_reference_walkthrough() {
        let json = r#"{
          "execution": {
            "invariants": [
              {
                "scope": "documents:read:document-42",
                "operation": "read",
                "resourceType": "documents",
                "resourceId": "document-42"
              },
              {
                "scope": "storage:save",
                "operation": "save",
                "resourceType": "storage",
                "resourceId": "*"
              }
            ],
            "contract": {
              "corporation": "ACME",
              "department": "sensitive-documents"
            }
          }
        }"#;

        let logical: LogicalAuthority = serde_json::from_str(json).unwrap();
        assert!(logical.identity_context.is_none());

        let map = IndexedAuthorityMap::from_logical(&logical).unwrap();
        assert_eq!(
            map.invariants[&0],
            InvariantTuple(
                "documents:read:document-42".into(),
                "read".into(),
                "documents".into(),
                "document-42".into()
            )
        );
        assert_eq!(
            map.invariants[&1],
            InvariantTuple(
                "storage:save".into(),
                "save".into(),
                "storage".into(),
                "*".into()
            )
        );
        // corporation sorts before department.
        assert_eq!(
            map.execution_contract[&0],
            ("corporation".into(), TupleValue::Text("ACME".into()))
        );
        assert_eq!(
            map.execution_contract[&1],
            (
                "department".into(),
                TupleValue::Text("sensitive-documents".into())
            )
        );

        // Round-trip: serialization keeps the article's member names.
        let back = serde_json::to_value(&logical).unwrap();
        assert_eq!(
            back["execution"]["invariants"][0]["resourceType"],
            "documents"
        );
        assert_eq!(
            back["execution"]["invariants"][0]["resourceId"],
            "document-42"
        );
        assert_eq!(back["execution"]["contract"]["corporation"], "ACME");
    }
}
