


pub mod hashstore;
// pub mod mmr;
// pub mod settlement;
pub mod pay_id_infos;
pub mod proof;
pub mod segment_vc;

use alloy_primitives::{U256,B256};
use serde::{Deserialize, Serialize};
use sp1_zkvm::io as spio;
use std::collections::BTreeMap;
// use crate::receipts::{PaymentSettledByProxy, };

pub use crate::{keccak256,keccak256_more as keccak256_add,EthAddress};
// pub use proof::Proof;
pub use hashstore::CircularHashStore;
// pub use mmr::MerkleRangeWithDCCH;
// pub use settlement::{ProxySettlement, ReceiverSettlement, SettlementManager};
pub use pay_id_infos::{PayIdInfo,PayIdManager};

pub use segment_vc::print_proof;
// 首先定义 trait
pub trait SettlementTracker {
    /// 记录新的结算记录
    fn track_settlement(&mut self, id: U256, hash: B256);
    
    /// 根据 settlement_id 获取对应的哈希
    fn get_settlement_hash(&self, settlement_id: B256) -> Option<B256>;
    
    /// 检查 settlement_id 是否存在
    fn has_settlement(&self, settlement_id: B256) -> bool;
    
    /// 获取所有已记录的 settlement_id
    fn get_all_settlement_ids(&self) -> Vec<B256>;
    
    /// 获取记录数量
    fn len(&self) -> usize;
    
    /// 检查是否为空
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// 清除所有记录
    fn clear(&mut self);
}

// 服务费率配置
#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct ServiceFeeConfig {
    pub serv_id: u32,
    pub system_fee_rate: u16,  // 基数为10000
    pub proxy_fee_rate: u16,   // 基数为10000
}
// 为 ServiceFeeConfig 实现读取方法
impl ServiceFeeConfig {
    pub fn read_from_stdin() -> Self {
        Self {
            serv_id: spio::read::<u32>(),
            system_fee_rate: spio::read::<u16>(),
            proxy_fee_rate: spio::read::<u16>(),
        }
    }
}
pub(crate) const SEGMENT_SIZE: usize = 16;    // 每段128个元素
pub(crate) const CHUNK_SIZE: usize = 16;      // 每chunk16个元素
pub(crate) const NODE_WIDTH: usize = 16;      // 节点宽度
pub(crate) const TREE_DEPTH: usize = 10;      // 树的深度
pub(crate) const LEFT_LEAF_INDEX: usize = 1431655765; // 预计算值：(16^10 - 1) / 15
//pub(crate) const LEFT_LEAF_INDEX: usize = (NODE_WIDTH.pow(TREE_DEPTH as u32) - 1) / (NODE_WIDTH - 1);