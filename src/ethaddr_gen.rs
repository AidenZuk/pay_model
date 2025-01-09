use crate::models::EthAddress;
use rand::{Rng, thread_rng};
use sha3::{Digest, Keccak256};
use std::time::{SystemTime, UNIX_EPOCH};

/// 通过随机数创建以太坊地址的工具函数集合
pub struct EthAddressGen;

impl EthAddressGen {
    /// 使用完全随机数生成地址
    pub fn random() -> EthAddress {
        let mut rng = thread_rng();
        let mut addr = [0u8; 20];
        rng.fill(&mut addr);
        addr
    }

    /// 使用种子生成确定性地址
    pub fn from_seed(seed: u64) -> EthAddress {
        let mut hasher = Keccak256::new();
        hasher.update(seed.to_be_bytes());
        let result = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&result[12..32]);
        addr
    }

    /// 使用当前时间戳作为种子生成地址
    pub fn from_timestamp() -> EthAddress {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::from_seed(timestamp as u64)
    }

    /// 使用自定义数据生成地址
    pub fn from_data(data: &[u8]) -> EthAddress {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&result[12..32]);
        addr
    }

    /// 生成一系列不同的地址
    pub fn generate_batch(count: usize) -> Vec<EthAddress> {
        let mut addresses = Vec::with_capacity(count);
        let  rng = thread_rng();
        
        for _ in 0..count {
            addresses.push(Self::random());
        }
        
        addresses
    }

    /// 生成一个有特定前缀的地址（用于测试）
    pub fn with_prefix(prefix: u8) -> EthAddress {
        let mut addr = Self::random();
        addr[0] = prefix;
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, thread};

    #[test]
    fn test_random_address() {
        let addr1 = EthAddressGen::random();
        let addr2 = EthAddressGen::random();
        
        // 验证两个随机地址不相同
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_seeded_address() {
        let seed = 12345u64;
        let addr1 = EthAddressGen::from_seed(seed);
        let addr2 = EthAddressGen::from_seed(seed);
        
        // 验证相同种子生成相同地址
        assert_eq!(addr1, addr2);
        
        // 验证不同种子生成不同地址
        let addr3 = EthAddressGen::from_seed(seed + 1);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_timestamp_address() {
        let addr1 = EthAddressGen::from_timestamp();
        thread::sleep(std::time::Duration::from_millis(1));
        let addr2 = EthAddressGen::from_timestamp();
        
        // 验证不同时间戳生成不同地址
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_data_address() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        
        let addr1 = EthAddressGen::from_data(data1);
        let addr2 = EthAddressGen::from_data(data2);
        
        // 验证不同数据生成不同地址
        assert_ne!(addr1, addr2);
        
        // 验证相同数据生成相同地址
        let addr3 = EthAddressGen::from_data(data1);
        assert_eq!(addr1, addr3);
    }

    #[test]
    fn test_batch_generation() {
        let count = 1000;
        let addresses = EthAddressGen::generate_batch(count);
        
        // 验证生成的数量正确
        assert_eq!(addresses.len(), count);
        
        // 验证生成的地址都是唯一的
        let unique_addresses: HashSet<_> = addresses.into_iter().collect();
        assert_eq!(unique_addresses.len(), count);
    }

    #[test]
    fn test_prefixed_address() {
        let prefix = 0xAB;
        let addr = EthAddressGen::with_prefix(prefix);
        
        // 验证地址前缀正确
        assert_eq!(addr[0], prefix);
    }

    #[test]
    fn test_address_format() {
        let addr = EthAddressGen::random();
        
        // 验证地址长度
        assert_eq!(addr.len(), 20);
    }
}