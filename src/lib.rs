use alloy_primitives::ruint::aliases::U256;
use alloy_sol_types::sol;
use alloy_sol_types::SolType;  
use models::segment_vc::MerkleProof;
use serde_json; 
use alloy_primitives::{Address, B256, U256 as AlloyU256,Bytes};

use libsecp256k1::{
    Message, SecretKey, PublicKey, Signature, 
    RecoveryId, recover, sign,verify
};
use sp1_zkvm::io as spio;

use serde::{Deserialize, Serialize};
use tiny_keccak::{Keccak, Hasher};
pub mod models;
pub mod receipts;
pub mod ethaddr_gen;
pub mod proxy_settler;
pub mod receiver_settler;
pub use receipts::overpay_checker::{ReceiptsOverpayChecker,OverpayCheckResult};
pub use receipts::{PaymentSettledByProxy,ReceiverProof};
pub use models::{segment_vc::SegmentVC,PayIdInfo};
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }

    // 首先定义 ReceiverProof 结构
    struct ReceiverProofStruct {
        address receiver;

        bytes proof; // 改为 bytes32[] 类型
    }

    // 然后定义主结构
    struct OverpayCheckResultStruct {
        bytes32 payments_root;
        ReceiverProofStruct[] receiver_proofs;  // 移除 receiver_len，因为可以从数组长度获取
        bytes32 pay_ids_root;
    }

    // 使用 sol! 宏定义与 Solidity 兼容的结构

    /// @notice 代理结算结果结构
    struct ProxySettlementResultStruct {
        bytes32 vks_hash;
        /// @notice 结算ID
        bytes32 settlement_id;
        /// @notice 代理地址
        address proxy;
        /// @notice 支付ID的默克尔树根
        bytes32 pay_ids_root;
        /// @notice 服务ID的默克尔树根
        bytes32 serv_ids_root;
        /// @notice 系统利润
        uint256 system_profits;
        /// @notice 代理利润
        uint256 proxy_profits;
        /// @notice 总金额
        uint256 amount;
    }


}

// 在 receipts_overpay_checker.rs 中的转换代码：
// 转换实现
impl From<ReceiverProof> for ReceiverProofStruct {
    fn from(proof: ReceiverProof) -> Self {
                // 直接序列化 MerkleProof
                let serialized_proof = serde_json::to_vec(&proof.proof)
                .expect("Failed to serialize MerkleProof");
        ReceiverProofStruct {
            receiver: proof.receiver.into(),
           
            // 将 MerkleProof 序列化为 bytes
            proof: Bytes::from(serialized_proof),
        }
    }
}
impl From<OverpayCheckResult> for OverpayCheckResultStruct {
    fn from(result: OverpayCheckResult) -> Self {
        OverpayCheckResultStruct {
            payments_root: result.payments_root,
            receiver_proofs: result.receiver_proofs
                .into_iter()
                .map(ReceiverProofStruct::from)
                .collect(),
            pay_ids_root: result.pay_ids_root
        }
    }
}
impl From<OverpayCheckResultStruct> for OverpayCheckResult {
    fn from(result: OverpayCheckResultStruct) -> Self {
        // 转换 receiver_proofs
        let receiver_proofs = result.receiver_proofs
            .into_iter()
            .map(|proof_struct| {
                // 从 proof_struct.proof (Bytes) 反序列化得到 MerkleProof
                let merkle_proof: MerkleProof = serde_json::from_slice(&proof_struct.proof)
                    .expect("Failed to deserialize MerkleProof");
                
                // 创建 ReceiverProof
                ReceiverProof {
                    receiver: proof_struct.receiver.as_slice().try_into()
                        .expect("Invalid receiver address length"),
                    
                    proof: merkle_proof,
                }
            })
            .collect();

        OverpayCheckResult {
            payments_root: result.payments_root,
            receiver_proofs,
            pay_ids_root: result.pay_ids_root,
        }
    }
}

// 添加便捷方法
impl OverpayCheckResultStruct {
    pub fn to_result(self) -> OverpayCheckResult {
        self.into()
    }
}


/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut output);
    output
}

pub fn keccak256_more(prev_hash:&B256,new_data:&[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(prev_hash.as_slice());
    keccak.update(new_data);
    keccak.finalize(&mut output);
    output
}

// 生成新的私钥
fn generate_private_key() -> SecretKey {
    let mut rng = rand::thread_rng();
    SecretKey::random(&mut rng)
}

// 从私钥获取公钥
pub fn get_public_key(secret_key: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secret_key)
}

// 签名消息
pub fn sign_message(secret_key: &SecretKey, message: &[u8]) -> Result<EthSignature, BoxError> {
    // 计算消息哈希
    let message_hash = keccak256(message);
    let msg = Message::parse_slice(&message_hash)?;

    // 签名
    let (signature, recovery_id) = sign(&msg, secret_key);

    // 组装完整签名（r + s + v）
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..32].copy_from_slice(&signature.r.b32());
    sig_bytes[32..64].copy_from_slice(&signature.s.b32());
    sig_bytes[64] = recovery_id.serialize();

    Ok(sig_bytes)
}

// 从签名恢复公钥
pub fn recover_public_key(signature: &EthSignature, message: &[u8]) -> Result<PublicKey, BoxError >{
    // 解析签名组件
    let recovery_id = RecoveryId::parse(signature[64])?;
    let sig = Signature::parse_standard_slice(&signature[..64])?;

    // 计算消息哈希
    let message_hash = keccak256(message);
    let msg = Message::parse_slice(&message_hash)?;

    // 恢复公钥
    let public_key = recover(&msg, &sig, &recovery_id)?;
    Ok(public_key)
}

// 验证签名
pub fn verify_signature(public_key: &PublicKey, signature: &EthSignature, message: &[u8]) -> Result<bool, BoxError> {
    let sig = Signature::parse_standard_slice(&signature[..64])?;
    let message_hash = keccak256(message);
    let msg = Message::parse_slice(&message_hash)?;
    
    Ok(verify(&msg, &sig, public_key))
}

// 获取以太坊地址（公钥的keccak256哈希的后20字节）
pub fn get_ethereum_address(public_key: &PublicKey) -> EthAddress {
    let public_key_serialized = public_key.serialize();
    let hash = keccak256(&public_key_serialized[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}
// 定义以太坊签名类型（65字节）

pub type EthSignature = [u8; 65];
// 首先，在适当的位置添加这个辅助函数
fn read_eth_signature() -> [u8; 65] {
    let mut sig = [0u8; 65];
    for i in 0..65 {
        sig[i] = spio::read::<u8>();
    }
    sig
}


// 可选：你也可以为其他常用类型定义类型别名
pub type EthAddress = [u8; 20];
pub type EthHash = [u8; 32];

// 签名包装类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSignature(#[serde(with = "signature_serde")] pub EthSignature);
impl SerializableSignature {
    pub fn new(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

// 签名的序列化助手
pub mod signature_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(signature: &EthSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = signature.to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<EthSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        EthSignature::try_from(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("Invalid signature: {}", e)))
    }
}
pub fn signature_to_eth(signature:Signature) -> EthSignature {

    // 获取 r 和 s 的字节表示
    let r_bytes: [u8; 32] = signature.r.b32();
    let s_bytes: [u8; 32] = signature.s.b32();

    // 序列化为以太坊格式（65字节）
    let mut eth_signature = [0u8; 65];
    eth_signature[0..32].copy_from_slice(&r_bytes);
    eth_signature[32..64].copy_from_slice(&s_bytes);
    eth_signature[64] = 27; // recovery id + 27

    eth_signature
}

pub fn eth_address_to_B256(addr: &EthAddress) -> B256 {
    let mut bytes = [0u8; 32];
    // 将地址复制到后20个字节
    bytes[12..32].copy_from_slice(addr);
    B256::from(bytes)
}

// 利润计算结果
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProfitResult {
    pub receiver: EthAddress,
    pub proxy: EthAddress,
    pub receipts_root: B256,
    pub pay_ids_root: B256,
    pub serv_ids_root: B256,
    pub system_profit: U256,
    pub proxy_profit: U256,
    pub receiver_profit: U256,
}

#[derive(Debug)]
pub struct ProxySettlementResult {
    pub vks_hash: B256,           // 添加验证密钥哈希
    pub settlement_id: B256,
    pub proxy: EthAddress,
    pub pay_ids_root: B256,
    pub serv_ids_root: B256,
    pub system_profits: U256,
    pub proxy_profits: U256,
    pub amount: U256,
}

// 添加 Solidity 类型定义
sol! {
    struct ProfitResultStruct {
        bytes32 vks_hash;
        address receiver;
        address proxy;
        bytes32 receipts_root;
        bytes32 pay_ids_root;
        bytes32 serv_ids_root;
        uint256 system_profit;
        uint256 proxy_profit;
        uint256 receiver_profit;
    }
}
impl ProxySettlementResult {
 /// 验证 settlement_id 是否正确
    pub fn verify_settlement_id(&self, receipts_root: B256) -> bool {
        // 复制计算 settlement_id 的算法
        let mut data = Vec::new();
        data.extend_from_slice(&self.proxy);  // EthAddress -> &[u8]
        data.extend_from_slice(self.pay_ids_root.as_slice());
        data.extend_from_slice(self.serv_ids_root.as_slice());
        data.extend_from_slice(&self.system_profits.to_be_bytes::<32>());
        data.extend_from_slice(&self.proxy_profits.to_be_bytes::<32>());
        data.extend_from_slice(&self.amount.to_be_bytes::<32>());
        
        let mut data2 = keccak256(&data).to_vec();
        data2.extend_from_slice(receipts_root.as_slice());
        let calculated_id = B256::from_slice(&keccak256(&data2));

        // 比较计算得到的 settlement_id 和存储的是否一致
        calculated_id == self.settlement_id
    }

    /// 计算正确的 settlement_id（可选，用于调试）
    pub fn calculate_settlement_id(&self, receipts_root: B256) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.proxy);
        data.extend_from_slice(self.pay_ids_root.as_slice());
        data.extend_from_slice(self.serv_ids_root.as_slice());
        data.extend_from_slice(&self.system_profits.to_be_bytes::<32>());
        data.extend_from_slice(&self.proxy_profits.to_be_bytes::<32>());
        data.extend_from_slice(&self.amount.to_be_bytes::<32>());
        
        let mut data2 = keccak256(&data).to_vec();
        data2.extend_from_slice(receipts_root.as_slice());
        B256::from_slice(&keccak256(&data2))
    }
    pub fn build_settlement_id(&mut self){
        self.settlement_id = self.calculate_settlement_id(self.pay_ids_root);
    }
}
// ProfitResult 转换为 ProfitResultStruct
impl From<ProfitResult> for ProfitResultStruct {
    fn from(result: ProfitResult) -> Self {
        ProfitResultStruct {
            receiver: Address::from_slice(&result.receiver),
            proxy: Address::from_slice(&result.proxy),
            receipts_root: result.receipts_root,
            pay_ids_root: result.pay_ids_root,
            serv_ids_root: result.serv_ids_root,
            system_profit: result.system_profit,
            proxy_profit: result.proxy_profit,
            receiver_profit: result.receiver_profit,
        }
    }
}

// ProfitResultStruct 转换为 ProfitResult
impl From<ProfitResultStruct> for ProfitResult {
    fn from(result: ProfitResultStruct) -> Self {
        let mut receiver = [0u8; 20];
        receiver.copy_from_slice(result.receiver.as_slice());
        
        let mut proxy = [0u8; 20];
        proxy.copy_from_slice(result.proxy.as_slice());

        ProfitResult {
            receiver,
            proxy,
            receipts_root: result.receipts_root,
            pay_ids_root: result.pay_ids_root,
            serv_ids_root: result.serv_ids_root,
            system_profit: result.system_profit,
            proxy_profit: result.proxy_profit,
            receiver_profit: result.receiver_profit,
        }
    }
}

// 使用示例：
impl ProfitResult {
    pub fn to_struct(self) -> ProfitResultStruct {
        self.into()
    }
}

impl ProfitResultStruct {
    pub fn to_result(self) -> ProfitResult {
        self.into()
    }
}


// ProxySettlementResult 转换为 ProxySettlementResultStruct
impl From<ProxySettlementResult> for ProxySettlementResultStruct {
    fn from(result: ProxySettlementResult) -> Self {
        ProxySettlementResultStruct {
            vks_hash: result.vks_hash,
            settlement_id: result.settlement_id,
            proxy: Address::from_slice(&result.proxy),
            pay_ids_root: result.pay_ids_root,
            serv_ids_root: result.serv_ids_root,
            system_profits: result.system_profits,
            proxy_profits: result.proxy_profits,
            amount: result.amount,
        }
    }
}

// ProxySettlementResultStruct 转换为 ProxySettlementResult
impl From<ProxySettlementResultStruct> for ProxySettlementResult {
    fn from(result: ProxySettlementResultStruct) -> Self {
        let mut proxy = [0u8; 20];
        proxy.copy_from_slice(result.proxy.as_slice());

        ProxySettlementResult {
            vks_hash: result.vks_hash,
            settlement_id: result.settlement_id,
            proxy,
            pay_ids_root: result.pay_ids_root,
            serv_ids_root: result.serv_ids_root,
            system_profits: result.system_profits,
            proxy_profits: result.proxy_profits,
            amount: result.amount,
        }
    }
}

// 便捷方法
impl ProxySettlementResult {
    pub fn to_struct(self) -> ProxySettlementResultStruct {
        self.into()
    }
}

impl ProxySettlementResultStruct {
    pub fn to_result(self) -> ProxySettlementResult {
        self.into()
    }
}
/******************
 
 // contracts/IProfitResult.sol
pragma solidity ^0.8.0;

interface IProfitResult {
    struct ProfitResultStruct {
        address receiver;
        address proxy;
        bytes32 receipts_root;
        bytes32 pay_ids_root;
        bytes32 serv_ids_root;
        uint256 system_profit;
        uint256 proxy_profit;
        uint256 receiver_profit;
    }

    event ProfitCalculated(
        address indexed receiver,
        address indexed proxy,
        bytes32 receipts_root,
        uint256 system_profit,
        uint256 proxy_profit,
        uint256 receiver_profit
    );

    function verifyAndProcessProfit(
        ProfitResultStruct calldata result,
        bytes calldata proof
    ) external returns (bool);
}

 */
#[derive(Debug, Clone, Serialize, Deserialize)]
 pub struct ReceiverSettleResult{
    pub vk_hash:B256,
    pub settlement_root:B256,
    pub receiver:EthAddress,
    pub profit:U256,
 }
 // 在 sol! 宏中添加 ReceiverSettleResultStruct 定义
sol! {
    struct ReceiverSettleResultStruct {
        bytes32 vk_hash;
        bytes32 settlement_root;
        address receiver;
        uint256 profit;
    }
}

// 实现相互转换
impl From<ReceiverSettleResult> for ReceiverSettleResultStruct {
    fn from(result: ReceiverSettleResult) -> Self {
        ReceiverSettleResultStruct {
            vk_hash: result.vk_hash,
            settlement_root: result.settlement_root,
            profit: result.profit,
            receiver: Address::from_slice(&result.receiver),

        }
    }
}

impl From<ReceiverSettleResultStruct> for ReceiverSettleResult {
    fn from(result: ReceiverSettleResultStruct) -> Self {
        ReceiverSettleResult {
            vk_hash: result.vk_hash,
            settlement_root: result.settlement_root,
            profit: result.profit,
            receiver: result.receiver.as_slice().try_into()
                .expect("Invalid receiver address length"),
        }
    }
}

// 为 ReceiverSettleResult 添加便捷方法
impl ReceiverSettleResult {
    pub fn to_struct(self) -> ReceiverSettleResultStruct {
        self.into()
    }
}

impl ReceiverSettleResultStruct {
    pub fn to_result(self) -> ReceiverSettleResult {
        self.into()
    }
}

// 使用示例
#[cfg(test)]
mod test_receiver_settle_result_conversion{
    use super::*;

    #[test]
    fn test_receiver_settle_result_conversion() {
        // 创建 Rust 结构
        let result = ReceiverSettleResult {
            vk_hash: B256::ZERO,
            settlement_root: B256::ZERO,
            profit: U256::from(100u32),
            receiver: [0u8; 20],
        };

        // 转换为 Solidity 结构
        let sol_result: ReceiverSettleResultStruct = result.clone().into();
        
        // 转换回 Rust 结构
        let rust_result: ReceiverSettleResult = sol_result.into();
        
        // 验证转换正确性
        assert_eq!(result.vk_hash, rust_result.vk_hash);
        assert_eq!(result.settlement_root, rust_result.settlement_root);
        assert_eq!(result.profit, rust_result.profit);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
 pub struct SettlementProof {
    pub proxy: EthAddress,  //Proxy的地址
    pub start_history_hash:B256,
    pub settlement_ids:Vec<B256>,
    pub proof: MerkleProof // 实际使用时替换为具体的证明类型
}
impl SettlementProof {
    pub fn verify(&self) -> Result<bool,BoxError> {
        // 1. 计算最终哈希
        let final_hash = self.calculate_final_hash();
        if final_hash.ne(&self.proof.value_proof.value) {
            return Err("Final hash mismatch".into());
        }
        // 2. 使用 MerkleProof 验证
        self.proof.verify()
    }

    /// 计算最终哈希值
    fn calculate_final_hash(&self) -> B256 {
        // 从 start_history_hash 开始
        let mut current_hash = self.start_history_hash;

        // 针对每个 settlement_id 计算新的哈希
        for settlement_id in &self.settlement_ids {
            current_hash = B256::from_slice(
                &keccak256_more(&current_hash, settlement_id.as_slice())
            );
        }

        current_hash
    }
}