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

//! Removal bitmaps (Profile 0.2).
//!
//! For section-local index `i`: `byte_index = floor(i / 8)`,
//! `bit_index = i mod 8`, `mask = 1 << bit_index` — least-significant-bit
//! first. Index `0` is `h'01'`, index `7` is `h'80'`, index `8` is `h'0001'`.
//!
//! Canonical form: non-empty, no trailing zero bytes. A no-op bitmap is
//! omitted together with its attenuation member, never encoded.

use crate::error::RejectReason;

/// A canonical removal bitmap over the section-local indexes of one
/// Indexed Authority Map section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveBitmap(Vec<u8>);

impl RemoveBitmap {
    /// Builds a canonical bitmap from a set of section-local indexes.
    /// Returns `None` for an empty set: a no-op bitmap must be omitted.
    pub fn from_indices(indices: &[u32]) -> Option<Self> {
        if indices.is_empty() {
            return None;
        }
        let max = *indices.iter().max().unwrap();
        let mut bytes = vec![0u8; (max / 8) as usize + 1];
        for &i in indices {
            bytes[(i / 8) as usize] |= 1u8 << (i % 8);
        }
        Some(Self(bytes))
    }

    /// Parses wire bytes, rejecting the non-canonical forms the profile
    /// forbids: an empty bitmap and trailing zero bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RejectReason> {
        if bytes.is_empty() || bytes.last() == Some(&0) {
            return Err(RejectReason::BitmapNotCanonical);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The set of section-local indexes this bitmap removes.
    pub fn indices(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for (byte_index, byte) in self.0.iter().enumerate() {
            for bit_index in 0..8u32 {
                if byte & (1u8 << bit_index) != 0 {
                    out.push(byte_index as u32 * 8 + bit_index);
                }
            }
        }
        out
    }

    /// The highest index a set bit refers to.
    pub fn max_index(&self) -> u32 {
        // Canonical form guarantees the last byte is non-zero.
        *self
            .indices()
            .last()
            .expect("canonical bitmap is non-empty")
    }

    /// Validates that every set bit refers to an existing predecessor index
    /// in a section with `entry_count` entries (indexes `0..entry_count`).
    pub fn validate_against(
        &self,
        entry_count: u32,
        section: &'static str,
    ) -> Result<(), RejectReason> {
        if entry_count == 0 || self.max_index() >= entry_count {
            return Err(RejectReason::BitmapIndexOutOfRange(section));
        }
        Ok(())
    }

    /// The exact wire bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples() {
        assert_eq!(RemoveBitmap::from_indices(&[0]).unwrap().bytes(), &[0x01]);
        assert_eq!(RemoveBitmap::from_indices(&[1]).unwrap().bytes(), &[0x02]);
        assert_eq!(RemoveBitmap::from_indices(&[2]).unwrap().bytes(), &[0x04]);
        assert_eq!(RemoveBitmap::from_indices(&[7]).unwrap().bytes(), &[0x80]);
        assert_eq!(
            RemoveBitmap::from_indices(&[8]).unwrap().bytes(),
            &[0x00, 0x01]
        );
    }

    #[test]
    fn noop_is_omitted() {
        assert!(RemoveBitmap::from_indices(&[]).is_none());
    }

    #[test]
    fn roundtrip_indices() {
        let bm = RemoveBitmap::from_indices(&[0, 3, 9]).unwrap();
        assert_eq!(bm.indices(), vec![0, 3, 9]);
        let parsed = RemoveBitmap::from_bytes(bm.bytes()).unwrap();
        assert_eq!(parsed, bm);
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(
            RemoveBitmap::from_bytes(&[]).unwrap_err(),
            RejectReason::BitmapNotCanonical
        );
        assert_eq!(
            RemoveBitmap::from_bytes(&[0x01, 0x00]).unwrap_err(),
            RejectReason::BitmapNotCanonical
        );
        assert_eq!(
            RemoveBitmap::from_bytes(&[0x00]).unwrap_err(),
            RejectReason::BitmapNotCanonical
        );
    }

    #[test]
    fn rejects_out_of_range() {
        let bm = RemoveBitmap::from_indices(&[1]).unwrap();
        assert!(bm.validate_against(2, "invariants").is_ok());
        assert_eq!(
            bm.validate_against(1, "invariants").unwrap_err(),
            RejectReason::BitmapIndexOutOfRange("invariants")
        );
    }
}
