use std::collections::HashMap;
use primitive_types::{H160, H256, U256};

#[derive(Debug, Clone, PartialEq)]
pub struct ProxyState {
    pub staked: U256,
    pub block_height: u64,
    pub shutdown_hash: H256,
    pub transfer_block: u64,
    pub is_active: bool,
    pub tags: u64,
    pub is_slashed: bool,
}

impl Default for ProxyState {
    fn default() -> Self {
        ProxyState {
            staked: U256::zero(),
            block_height: 0,
            shutdown_hash: H256::zero(),
            transfer_block: 0,
            is_active: false,
            tags: 0,
            is_slashed: false,
        }
    }
}

#[derive(Default)]
pub struct ProxyManager {
    proxy_states: HashMap<H160, ProxyState>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            proxy_states: HashMap::new(),
        }
    }

    pub fn update_state(&mut self, proxy: H160, state: ProxyState) {
        self.proxy_states.insert(proxy, state);
    }

    pub fn get_state(&self, proxy: &H160) -> Option<&ProxyState> {
        self.proxy_states.get(proxy)
    }

    pub fn get_all_states(&self) -> &HashMap<H160, ProxyState> {
        &self.proxy_states
    }
}