// use alloy_sol_types::sol_data::Address;
// use primitive_types::H256;

// use crate::BoxError;

// use super::hashstore::CircularHashStore;
// use super::{keccak256, keccak256_add, EthAddress};
// use super::{NODE_WIDTH, SEGMENT_SIZE, CHUNK_SIZE};

// #[derive(Debug, Clone)]
// pub struct Proof {
//     pub(crate) value: H256,
//     pub(crate) root_hash: H256,
//     pub(crate) segment_proof: Vec<H256>,
//     pub(crate) merkle_proof: Vec<H256>,
// }

// impl Proof {
//     pub fn verify(&self, root_history: Option<&CircularHashStore>) -> Result<bool,BoxError> {
//         let mut proof_index = 0;
        
//         let chunk_values = self.segment_proof[..CHUNK_SIZE-1].to_vec();
//         let chunk_hash = Self::verify_chunk(
//             self.value,
//             &chunk_values
//         );
//         proof_index += CHUNK_SIZE - 1;
        
//         let segment_hashes = self.segment_proof[proof_index..proof_index + SEGMENT_SIZE/CHUNK_SIZE-1].to_vec();
//         let segment_root = Self::verify_segment(
//             chunk_hash,
//             &segment_hashes
//         );
//         proof_index += SEGMENT_SIZE/CHUNK_SIZE - 1;
        
//         let mut current_hash = segment_root;
        
//         while proof_index < self.merkle_proof.len() {
//             let end = std::cmp::min(proof_index + NODE_WIDTH - 1, self.merkle_proof.len());
//             let siblings = &self.merkle_proof[proof_index..end];
//             current_hash = Self::verify_node(current_hash, siblings);
//             proof_index = end;
//         }

//         if current_hash != self.root_hash {
//             return Ok(false);
//         }
        
//         if let Some(root_history) = root_history {
//             Ok(root_history.hash_exists(current_hash))
//         }else{
//              Ok(true)
//         }
//     }

//     fn verify_chunk(value: H256, other_values: &[H256]) -> H256 {
//         let mut chunk_values = Vec::new();
//         chunk_values.push(value);
//         chunk_values.extend_from_slice(other_values);
//         H256::from_slice(&keccak256(&chunk_values.iter().flat_map(|h| h.as_fixed_bytes().iter().copied()).collect::<Vec<_>>()))
//     }

//     fn verify_segment(chunk_hash: H256, other_hashes: &[H256]) -> H256 {
//         let mut segment_hashes = Vec::new();
//         segment_hashes.push(chunk_hash);
//         segment_hashes.extend_from_slice(other_hashes);
//         H256::from_slice(&keccak256(&segment_hashes.iter().flat_map(|h| h.as_fixed_bytes().iter().copied()).collect::<Vec<_>>()))
//     }

//     fn verify_node(hash: H256, siblings: &[H256]) -> H256 {
//         let mut node_hashes = Vec::new();
//         node_hashes.push(hash);
//         node_hashes.extend_from_slice(siblings);
//         H256::from_slice(&keccak256(&node_hashes.iter().flat_map(|h| h.as_fixed_bytes().iter().copied()).collect::<Vec<_>>()))
//     }
// }

// #[derive(Debug)]
// pub struct ProxySettlementProof {
//     pub proxy: EthAddress,
//     pub settle_hash: H256,
//     pub history_proof: Vec<H256>,
//     pub segment_proof: Proof,
// }

// impl ProxySettlementProof {
//     pub fn verify(&self) -> bool {
//         let mut current_hash = self.settle_hash;
//         for proof_hash in &self.history_proof {
//             let result = keccak256_add(&current_hash, proof_hash.as_bytes());
//             current_hash = H256::from_slice(&result);
//         }

//         if self.segment_proof.value != current_hash {
//             return false;
//         }
       
//         self.segment_proof.verify(None)
//             .unwrap_or(false)
//     }

//     pub fn verify_batch(proofs: &[ProxySettlementProof]) -> bool {
//         if proofs.is_empty() {
//             return false;
//         }

//         let reference_value = proofs[0].segment_proof.value;

//         for proof in proofs {
//             if !proof.verify() {
//                 return false;
//             }

//             if proof.segment_proof.value != reference_value {
//                 return false;
//             }
//         }

//         true
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use super::super::segment_vc::SegmentVC;

//     #[test]
//     fn test_proof_verification() -> Result<(),BoxError> {
//         let mut vc = SegmentVC::new(128);
        
//         let key = H256::repeat_byte(1);
//         let value = H256::repeat_byte(2);
//         vc.insert(key, value)?;
        
//         let proof = vc.generate_proof(key)?;
        
//         assert!(proof.verify(Some(&vc.get_root_history()))?);
        
//         let mut invalid_proof = proof.clone();
//         invalid_proof.value = H256::from_low_u64_be(1);
//         assert!(!invalid_proof.verify(None)?);
        
//         Ok(())
//     }

//     #[test]
//     fn test_proof_with_updates() -> Result<(),BoxError> {
//         let mut vc = SegmentVC::new(128);
        
//         let key = H256::repeat_byte(1);
//         let value1 = H256::repeat_byte(2);
//         vc.insert(key, value1)?;
        
//         let proof1 = vc.generate_proof(key)?;
//         assert!(proof1.verify(Some(&vc.get_root_history()))?);
        
//         let value2 = H256::repeat_byte(3);
//         vc.update(key, value2)?;
        
//         let proof2 = vc.generate_proof(key)?;
        
//         assert!(proof1.verify(Some(&vc.get_root_history()))?);
//         assert!(proof2.verify(None)?);

//         Ok(())
//     }
// }