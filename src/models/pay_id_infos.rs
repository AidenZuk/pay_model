use alloy_sol_types::abi::Token;
use alloy_primitives::{ B256, U256,keccak256};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use super::{EthAddress};
use sp1_zkvm::io as spio;

#[derive(Debug, Clone,Serialize, Deserialize)]
pub struct PayIdInfo {
    pub id: U256,
    pub amount: U256,
    pub sender: EthAddress,
    pub proxy: EthAddress,
    pub state: u8,
    pub created_at: u64,
    pub closing_time: u64,
}
impl PayIdInfo {
    // 使用encodePacked方式计算PayIdInfo的哈希值
    pub fn hash(&self) -> B256 {
        // 准备编码数据
        let mut packed = Vec::new();
        
        packed.extend_from_slice(&self.id.to_be_bytes::<32>());           // bytes32 id
        
        let amount_bytes = self.amount.to_be_bytes::<32>();  
        packed.extend_from_slice(&amount_bytes);                // uint256 amount
        
        packed.extend_from_slice(&self.sender);       // address sender
        packed.extend_from_slice(&self.proxy);        // address proxy
        
        let state_bytes = u8::from(self.state).to_be_bytes();
        packed.extend_from_slice(&state_bytes);                 // uint8 state
        
        let created_at_bytes = self.created_at.to_be_bytes();
        packed.extend_from_slice(&created_at_bytes);           // uint64 created_at
        
        let closing_time_bytes = self.closing_time.to_be_bytes();
        packed.extend_from_slice(&closing_time_bytes);         // uint64 closing_time
        // 计算keccak256哈希
     
       let result = keccak256(&packed);
  
        
        B256::from_slice(&result[..])
    }

 
}



#[derive(Debug)]
pub struct PayIdManager {
    // 每个代理的PayId列表
    pay_ids: HashMap<EthAddress, Vec<PayIdInfo>>,
    // 每个代理的当前根哈希
    root_hashes: HashMap<EthAddress, B256>,
    // 每个PayId的最新状态
    id_states: HashMap<U256, PayIdInfo>,
}

impl PayIdManager {
    pub fn new() -> Self {
        Self {
            pay_ids: HashMap::new(),
            root_hashes: HashMap::new(),
            id_states: HashMap::new(),
        }
    }

    pub fn update_pay_id(&mut self, pay_id: PayIdInfo) {
        // 更新PayId状态
        let proxy = pay_id.proxy;
        let id =pay_id.id;
        
        // 更新或添加到代理的PayId列表
        self.pay_ids.entry(proxy)
            .or_insert_with(Vec::new)
            .push(pay_id.clone());

        // 更新PayId状态映射
        self.id_states.insert(id, pay_id);
    }

    pub fn get_pay_ids(&self, proxy: &EthAddress) -> Option<&Vec<PayIdInfo>> {
        self.pay_ids.get(proxy)
    }

    pub fn get_pay_id(&self, id: &U256) -> Option<&PayIdInfo> {
        self.id_states.get(id)
    }

    pub fn update_root_hash(&mut self, proxy: EthAddress, root: B256) {
        self.root_hashes.insert(proxy, root);
    }

    pub fn get_root_hash(&self, proxy: &EthAddress) -> Option<B256> {
        self.root_hashes.get(proxy).copied()
    }

    pub fn get_all_proxies(&self) -> Vec<EthAddress> {
        self.pay_ids.keys().cloned().collect()
    }

    pub fn get_active_pay_ids(&self, proxy: &EthAddress) -> Vec<PayIdInfo> {
        self.pay_ids.get(proxy)
            .map(|pay_ids| {
                pay_ids.iter()
                    .filter(|pay_id| pay_id.state == 1) // 假设1表示活跃状态
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}