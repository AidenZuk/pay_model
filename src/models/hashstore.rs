use alloy_primitives::B256;
use super::{keccak256,keccak256_add};
/// CircularHashStore - 简化版本
#[derive(Debug,Clone)]
pub struct CircularHashStore {
    hashes: Vec<B256>,         // 当前存储的哈希
    history_hash: B256,        // 历史哈希累积值
    total_added: usize,        // 总共添加的哈希数量
    capacity: usize,           // 存储容量
}

impl CircularHashStore {
    pub const STORE_SIZE: usize = 128;
    pub const EMPTY_HASH: B256 = B256::ZERO;

    /// 创建新的实例
    pub fn new(capacity:usize) -> Self {
        Self {
            hashes: Vec::new(),
            history_hash: B256::ZERO,
            total_added: 0,
            capacity,
        }
    }
pub fn current_size(&self) -> usize {
        self.hashes.len()
    }
    pub fn total_added(&self) -> usize {
        self.total_added
    }
    pub fn hash_exists(&self, hash: B256) -> bool {
        self.hashes.contains(&hash)
    }
    /// 添加新哈希
    pub fn add_hash(&mut self, hash: B256) -> Result<usize, &'static str> {
        if hash == Self::EMPTY_HASH {
            return Err("Invalid hash");
        }

        // 如果达到最大容量,需要更新history_hash
        if self.hashes.len() == self.capacity {
            let old_hash = self.hashes.remove(0);
            if self.history_hash == B256::default() {
                self.history_hash = old_hash;
            } else {
                self.history_hash = keccak256_add(
                    &self.history_hash, old_hash.as_slice()
                ).into();
            }
        }

        let position = self.hashes.len();
        self.hashes.push(hash);
        self.total_added += 1;

        Ok(position)
    }

    /// 检查哈希是否存在
    pub fn check_hash(&self, hash: B256, history_proof: &[B256]) -> bool {
        // 检查当前存储
        if self.hashes.contains(&hash) {
            return true;
        }

        // 检查历史记录
        if !history_proof.is_empty() {
            let mut current_hash = hash;
            for &proof_hash in history_proof {
                current_hash = keccak256_add(
                    &current_hash, proof_hash.as_slice()
                ).into();
            }
            return current_hash == self.history_hash;
        }

        false
    }

    /// 获取存储的完整状态
    pub fn get_full_state(&self) -> (bool, u8, B256, Vec<B256>, usize) {
        (
            !self.hashes.is_empty(),
            self.hashes.len() as u8,
            self.history_hash,
            self.hashes.clone(),
            self.total_added,
        )
    }

    /// 获取存储的统计信息
    pub fn get_store_stats(&self) -> (u8, usize, bool) {
        (
            self.hashes.len() as u8,
            self.total_added,
            self.history_hash != Self::EMPTY_HASH,
        )
    }

    /// 获取当前哈希
    pub fn get_current_hash(&self) -> Option<B256> {
        self.hashes.first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let store = CircularHashStore::new(CircularHashStore::STORE_SIZE);
        let (initialized, size, history_hash, hashes, total_added) = store.get_full_state();
        assert!(!initialized);
        assert_eq!(size, 0);
        assert_eq!(history_hash, B256::default());
        assert!(hashes.is_empty());
        assert_eq!(total_added, 0);
    }

    #[test]
    fn test_add_hash() {
        let mut store = CircularHashStore::new(CircularHashStore::STORE_SIZE);
        let hash = B256::from_slice(&[2u8;32]);
        
        let result = store.add_hash(hash);
        assert!(result.is_ok());
        
        let (initialized, size, _, hashes, total_added) = store.get_full_state();
        assert!(initialized);
        assert_eq!(size, 1);
        assert_eq!(hashes[0], hash);
        assert_eq!(total_added, 1);
    }

    #[test]
    fn test_circular_behavior() {
        let mut store = CircularHashStore::new(CircularHashStore::STORE_SIZE);
        let hashes: Vec<B256> = (0..130).map(|i|  B256::repeat_byte(i as u8)).collect();
        
        // Add more hashes than the store size
        for hash in hashes.iter() {
            store.add_hash(*hash).unwrap();
        }
        
        let (_, size, _, current_hashes, total_added) = store.get_full_state();
        assert_eq!(size as usize, CircularHashStore::STORE_SIZE);
        assert_eq!(total_added, 130);
        
        // Check that only the most recent STORE_SIZE hashes are kept
        for hash in hashes.iter().skip(130 - CircularHashStore::STORE_SIZE) {
            assert!(store.check_hash(*hash, &[]));
        }

        // Check that older hashes are not in current storage
        for hash in hashes.iter().take(2) {
            assert!(!current_hashes.contains(hash));
        }
    }

    #[test]
    fn test_history_hash() {
        let mut store = CircularHashStore::new(CircularHashStore::STORE_SIZE);
        
        // Add more than STORE_SIZE hashes to generate history
        let hashes: Vec<B256> = (0..130).map(|i|  B256::repeat_byte(i as u8)).collect();
        for hash in hashes.iter() {
            store.add_hash(*hash).unwrap();
        }

        // The first two hashes should now be in history
        assert!(store.history_hash != B256::default());
        
        // Current storage should only contain the most recent hashes
        let (_, _, _, current_hashes, _) = store.get_full_state();
        assert_eq!(current_hashes.len(), CircularHashStore::STORE_SIZE);
    }
}