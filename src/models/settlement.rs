use primitive_types::{H256, U256};
use crate::{BoxError, EthAddress as Address, keccak256};
use super::{hashstore::CircularHashStore, segment_vc::{MerkleProof, SegmentVC}};
use std::collections::HashMap;

#[derive(Debug)]
pub enum Error {
    KeyNotFound,
    ProofGenerationFailed,
    NoLatestHash,
    InvalidProof,
    LockError,
    // Add new error variants
    UpdateError(String),
    HashStoreError(String),
    InvalidInput,
    CapacityExceeded,
    HistoryNotFound,
    VerificationFailed,
    DatabaseError(String),
    SerializationError,
    InvalidRootHash,
    InvalidMerkleProof,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyNotFound => write!(f, "Key not found"),
            Error::ProofGenerationFailed => write!(f, "Failed to generate proof"),
            Error::NoLatestHash => write!(f, "No latest hash available"),
            Error::InvalidProof => write!(f, "Invalid proof"),
            Error::LockError => write!(f, "Failed to acquire lock"),
            Error::UpdateError(msg) => write!(f, "Update error: {}", msg),
            Error::HashStoreError(msg) => write!(f, "Hash store error: {}", msg),
            Error::InvalidInput => write!(f, "Invalid input parameters"),
            Error::CapacityExceeded => write!(f, "Storage capacity exceeded"),
            Error::HistoryNotFound => write!(f, "History data not found"),
            Error::VerificationFailed => write!(f, "Verification failed"),
            Error::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Error::SerializationError => write!(f, "Serialization error"),
            Error::InvalidRootHash => write!(f, "Invalid root hash"),
            Error::InvalidMerkleProof => write!(f, "Invalid Merkle proof"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxySettlement {
    pub id: U256,
    pub pay_id_hash: H256,
    pub serv_id_hash: H256,
    pub proxy: Address,
    pub proxy_reward: U256,
    pub system_reward: U256,
    pub timestamp: U256,
}

#[derive(Debug, Clone)]
pub struct ReceiverSettlement {
    pub id: U256,
    pub proxy_hash_root: H256,
    pub receiver: Address,
    pub receiver_reward: U256,
    pub timestamp: U256,
}

#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub total_size: U256,
    pub current_root: H256,
    pub history_size: u8,
    pub total_history: U256,
    pub has_history: bool,
}

#[derive(Debug, Clone)]
pub struct ReceiverStats {
    pub current_size: u8,
    pub total_added: U256,
    pub has_history: bool,
}

pub struct SettlementManager {
    settle_of_proxy: SegmentVC,
    proxy_settle_history: HashMap<Address, CircularHashStore>,
    receiver_stores: HashMap<Address, CircularHashStore>,
    proxy_last_settle: HashMap<Address, U256>,
}

impl SettlementManager {
    pub fn new() -> Self {
        Self {
            settle_of_proxy: SegmentVC::new(),
            proxy_settle_history: HashMap::new(),
            receiver_stores: HashMap::new(),
            proxy_last_settle: HashMap::new(),
        }
    }

    fn calculate_proxy_settlement_hash(&self, settlement: &ProxySettlement) -> H256 {
        let mut data = Vec::new();
        data.extend_from_slice(&settlement.id.to_big_endian());
        data.extend_from_slice(settlement.pay_id_hash.as_bytes());
        data.extend_from_slice(settlement.serv_id_hash.as_bytes());
        data.extend_from_slice(&settlement.proxy);
        data.extend_from_slice(&settlement.proxy_reward.to_big_endian());
        data.extend_from_slice(&settlement.system_reward.to_big_endian());
        data.extend_from_slice(&settlement.timestamp.to_big_endian());
        
        H256::from_slice(&keccak256(&data))
    }

    fn calculate_receiver_settlement_hash(&self, settlement: &ReceiverSettlement) -> H256 {
        let mut data = Vec::new();
        data.extend_from_slice(&settlement.id.to_big_endian());
        data.extend_from_slice(settlement.proxy_hash_root.as_bytes());
        data.extend_from_slice(&settlement.receiver);
        data.extend_from_slice(&settlement.receiver_reward.to_big_endian());
        data.extend_from_slice(&settlement.timestamp.to_big_endian());
        
        H256::from_slice(&keccak256(&data))
    }

    pub fn add_proxy_settlement(
        &mut self,
        id: U256,
        pay_id_hash: H256,
        serv_id_hash: H256,
        proxy: Address,
        proxy_reward: U256,
        system_reward: U256,
        timestamp: U256,
    ) -> Result<H256, BoxError> {
        let settlement = ProxySettlement {
            id,
            pay_id_hash,
            serv_id_hash,
            proxy,
            proxy_reward,
            system_reward,
            timestamp,
        };

        let settlement_hash = self.calculate_proxy_settlement_hash(&settlement);
        let proxy_key = H256::from_slice(&proxy);

        // 更新历史存储
        self.proxy_settle_history
            .entry(proxy)
            .or_insert_with(|| CircularHashStore::new(128))
            .add_hash(settlement_hash)
            .map_err(|e| Box::new(Error::UpdateError(e.to_string())))?;

        // 使用新的 upsert 方法更新 SegmentVC
        self.settle_of_proxy.upsert(proxy_key, settlement_hash)?;
        
        self.proxy_last_settle.insert(proxy, id);
        
        // 获取新的根哈希
        self.settle_of_proxy.get_root_hash()
    }


    pub fn add_receiver_settlement(
        &mut self,
        id: U256,
        proxy_hash_root: H256,
        receiver: Address,
        receiver_reward: U256,
        timestamp: U256,
    ) -> Result<(), BoxError> {
        // 验证代理哈希根是否在历史记录中
        let root_valid = self.settle_of_proxy
            .verify_historical_root(proxy_hash_root, &[])?;
            
        if !root_valid {
            return Err(Box::new(Error::InvalidProof));
        }

        let settlement = ReceiverSettlement {
            id,
            proxy_hash_root,
            receiver,
            receiver_reward,
            timestamp,
        };

        let settlement_hash = self.calculate_receiver_settlement_hash(&settlement);
        
        self.receiver_stores
            .entry(receiver)
            .or_insert_with(|| CircularHashStore::new(128))
            .add_hash(settlement_hash)
            .map_err(|e| Box::new(Error::UpdateError(e.to_string())))?;

        Ok(())
    }
    pub fn verify_proxy_settlement(
        &self,
        proxy: Address,
        proof: &MerkleProof,
    ) -> Result<bool, BoxError> {
        let proxy_key = H256::from_slice(&proxy);
        self.settle_of_proxy.verify(proof)
    }

    pub fn verify_receiver_settlement(
        &self,
        receiver: Address,
        hash: H256,
        history_proof: &[H256],
    ) -> Result<bool, BoxError> {
        self.receiver_stores
            .get(&receiver)
            .map_or(Ok(false), |store| Ok(store.check_hash(hash, history_proof)))
    }

    pub fn get_current_proxy_root(&self) -> Result<H256, BoxError> {
        self.settle_of_proxy.get_root_hash()
    }

    pub fn get_current_receiver_hash(&self, receiver: &Address) -> Option<H256> {
        self.receiver_stores
            .get(receiver)
            .and_then(|store| store.get_current_hash())
    }

    pub fn generate_proxy_settlement_proof(
        &self,
        proxy: Address,
        settle_hash: H256,
    ) -> Result<MerkleProof, BoxError> {  // 返回新的证明格式
        let proxy_key = H256::from_slice(&proxy);
        self.settle_of_proxy.generate_proof(proxy_key)
    }

    pub fn get_proxy_stats(&self, proxy: Address) -> Result<ProxyStats, BoxError> {
        let total_size = self.settle_of_proxy.len()?;
        let current_root = self.settle_of_proxy.get_root_hash()?;
        let (_, history_size, has_history) = self.settle_of_proxy.get_history_stats()?;
        
        let proxy_history = self.proxy_settle_history.get(&proxy);
        
        Ok(ProxyStats {
            total_size: U256::from(total_size),
            current_root,
            history_size: history_size as u8,
            total_history: proxy_history.map_or(U256::zero(), |s| U256::from(s.total_added())),
            has_history: proxy_history.is_some(),
        })
    }
  
    pub fn get_receiver_stats(&self, receiver: Address) -> ReceiverStats {
        let store = self.receiver_stores.get(&receiver);
        
        ReceiverStats {
            current_size: store.map_or(0, |s| s.current_size() as u8),
            total_added: store.map_or(U256::zero(), |s| U256::from(s.total_added())),
            has_history: store.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_address() -> Address {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes);
        bytes
    }

    #[test]
    fn test_settlement_flow() -> Result<(), BoxError> {
        let mut manager = SettlementManager::new();
        let proxy = random_address();
        let receiver = random_address();

        // Add proxy settlement
        let root_hash = manager.add_proxy_settlement(
            U256::from(1),
            H256::random(),
            H256::random(),
            proxy,
            U256::from(100),
            U256::from(10),
            U256::from(1000),
        )?;

        // Generate and verify proxy proof
        let proof = manager.generate_proxy_settlement_proof(proxy, root_hash)?;
        assert!(manager.verify_proxy_settlement(proxy, &proof)?);  // 修改这里的调用
    
        // Add receiver settlement
        manager.add_receiver_settlement(
            U256::from(1),
            root_hash,
            receiver,
            U256::from(90),
            U256::from(1001),
        )?;

        // Verify stats
        let proxy_stats = manager.get_proxy_stats(proxy)?;
        assert!(proxy_stats.has_history);
        
        let receiver_stats = manager.get_receiver_stats(receiver);
        assert!(receiver_stats.has_history);

        Ok(())
    }
}