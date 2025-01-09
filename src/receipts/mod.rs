use crate::{keccak256, read_eth_signature, SerializableSignature};

use super::{EthAddress, EthHash, EthSignature,signature_serde};
use sp1_zkvm::io as spio;
use libsecp256k1::{recover, sign, verify, Message, PublicKey, RecoveryId, SecretKey, Signature};
use alloy_primitives::{B256, U256};
use tiny_keccak::{Hasher, Keccak};
use crate::models::segment_vc::MerkleProof;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Serialize, Deserialize};
pub mod overpay_checker;
pub mod pay_ids_to_segvc;
pub mod payment_grouper;
pub mod profit_calculator;
// mod pay_ids_to_segvc;
// mod receipts_pay_check;
pub use pay_ids_to_segvc::PayIdsProcessor;
pub use payment_grouper::PaymentsGrouper;

// 为外部类型创建新的包装类型
#[derive(Debug, Clone, PartialEq)]
pub struct RlpAddress(EthAddress);

#[derive(Debug, Clone, PartialEq)]
pub struct RlpU256(U256);

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ReceiverProof {
    pub receiver: EthAddress,
    pub proof: MerkleProof // 实际使用时替换为具体的证明类型
}



#[derive(Debug, Clone,Serialize, Deserialize)]
pub struct Payment {
    pay_id: U256,
    serv_id: u32,
    pub amount: U256,     // 新增字段
    receiver: EthAddress,
    #[serde(with = "signature_serde")]
    sig_sender: EthSignature,
}
impl Payment {
    // 已有的方法保持不变...

    // 添加新的签名方法
    pub fn sign(&mut self, secret_key: &SecretKey) -> Result<(), DecoderError> {
        // 1. 将字段紧密打包
        let mut packed = Vec::new();
        
        // 添加pay_id (转换为固定长度的字节数组)
        let pay_id_bytes:[u8;32] = self.pay_id.to_be_bytes();
        packed.extend_from_slice(&pay_id_bytes);
        
        // 添加serv_id (转换为固定长度的字节数组)
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
          // 添加 amount
          let amount_bytes: [u8; 32] = self.amount.to_be_bytes();
          packed.extend_from_slice(&amount_bytes);
        // 添加receiver地址
        packed.extend_from_slice(&self.receiver);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 签名消息
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        let (signature, recovery_id) = sign(&msg, secret_key);
        
        // 4. 组装签名
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&signature.r.b32());
        sig_bytes[32..64].copy_from_slice(&signature.s.b32());
        sig_bytes[64] = recovery_id.serialize();
        
        // 5. 设置签名
        self.sig_sender = sig_bytes;
        
        Ok(())
    }

    // 验证签名
    pub fn verify(&self, public_key: &PublicKey) -> Result<bool, DecoderError> {
        // 1. 重新构建消息
        let mut packed = Vec::new();
        
        let pay_id_bytes:[u8;32] = self.pay_id.to_be_bytes();
        packed.extend_from_slice(&pay_id_bytes);
        
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
       
       let amount_bytes: [u8; 32] = self.amount.to_be_bytes();
        packed.extend_from_slice(&amount_bytes);
        
        packed.extend_from_slice(&self.receiver);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 解析签名
        let sig = Signature::parse_standard_slice(&self.sig_sender[..64])
            .map_err(|_| DecoderError::Custom("Failed to parse signature"))?;
            
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        // 4. 验证签名
        Ok(verify(&msg, &sig, public_key))
    }

    // 从签名恢复公钥
    pub fn recover_signer(&self) -> Result<PublicKey, DecoderError> {
        // 1. 重新构建消息
        let mut packed = Vec::new();
        
        let pay_id_bytes:[u8;32] = self.pay_id.to_be_bytes();
        packed.extend_from_slice(&pay_id_bytes);
        
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
        
        packed.extend_from_slice(&self.receiver);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 解析签名和恢复ID
        let sig = Signature::parse_standard_slice(&self.sig_sender[..64])
            .map_err(|_| DecoderError::Custom("Failed to parse signature"))?;
            
        let recovery_id = RecoveryId::parse(self.sig_sender[64])
            .map_err(|_| DecoderError::Custom("Failed to parse recovery id"))?;
            
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        // 4. 恢复公钥
        recover(&msg, &sig, &recovery_id)
            .map_err(|_| DecoderError::Custom("Failed to recover public key"))
    }
        /// 获取签名者的以太坊地址
        pub fn get_signer_address(&self) -> Result<EthAddress, DecoderError> {
            // 1. 首先恢复公钥
            let public_key = self.recover_signer()?;
            
            // 2. 将公钥转换为以太坊地址
            Ok(super::get_ethereum_address(&public_key))
        }
}
#[derive(Debug, Clone,Serialize, Deserialize)]
pub struct PaymentSettledByProxy {
    pub pay_id: U256,
    pub serv_id: u32,
    pub amount: U256,
    pub receiver: EthAddress,
    #[serde(with = "signature_serde")]
    pub sig_sender: EthSignature,
    pub settled: bool,
    #[serde(with = "signature_serde")]
    pub sig_proxy: EthSignature,
}

// 为 PaymentSettledByProxy 实现读取方法
impl PaymentSettledByProxy {
  pub   fn read_from_stdin() -> Self {
        Self {
            pay_id: spio::read::<U256>(),
            serv_id: spio::read::<u32>(),
            amount: spio::read::<U256>(),
            receiver: spio::read::<EthAddress>(),
            sig_sender:read_eth_signature(), 
            settled: spio::read::<bool>(),
            sig_proxy: read_eth_signature(), 
        }
    }
}
// 在PaymentSettledByProxy实现块中添加新方法
impl PaymentSettledByProxy {
    // 已有的方法保持不变...

    // 代理签名方法
    pub fn sign_by_proxy(&mut self, secret_key: &SecretKey) -> Result<(), DecoderError> {
        // 1. 将字段紧密打包
        let mut packed = Vec::new();
        
        // 添加pay_id (转换为固定长度的字节数组)
        let  pay_id_bytes:[u8;32] = self.pay_id.to_be_bytes::<32>();
        packed.extend_from_slice(&pay_id_bytes);
        
        // 添加serv_id
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
        
        // 添加amount
        let  amount_bytes:[u8;32]  = self.amount.to_be_bytes::<32>();
        packed.extend_from_slice(&amount_bytes);
        
        // 添加receiver地址
        packed.extend_from_slice(&self.receiver);
        
        // 添加sender的签名
        packed.extend_from_slice(&self.sig_sender);
        
        // 添加settled状态
        packed.extend_from_slice(&[self.settled as u8]);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 签名消息
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        let (signature, recovery_id) = sign(&msg, secret_key);
        
        // 4. 组装签名
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..32].copy_from_slice(&signature.r.b32());
        sig_bytes[32..64].copy_from_slice(&signature.s.b32());
        sig_bytes[64] = recovery_id.serialize();
        
        // 5. 设置代理签名
        self.sig_proxy = sig_bytes;
        
        Ok(())
    }

    // 验证代理签名
    pub fn verify_proxy_signature(&self, public_key: &PublicKey) -> Result<bool, DecoderError> {
        // 1. 重新构建消息
        let mut packed = Vec::new();
        
        let  pay_id_bytes = self.pay_id.to_be_bytes::<32>();
        packed.extend_from_slice(&pay_id_bytes);
        
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
        
        let  amount_bytes =    self.amount.to_be_bytes::<32>();
        packed.extend_from_slice(&amount_bytes);
        
        packed.extend_from_slice(&self.receiver);
        packed.extend_from_slice(&self.sig_sender);
        packed.extend_from_slice(&[self.settled as u8]);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 解析签名
        let sig = Signature::parse_standard_slice(&self.sig_proxy[..64])
            .map_err(|_| DecoderError::Custom("Failed to parse signature"))?;
            
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        // 4. 验证签名
        Ok(verify(&msg, &sig, public_key))
    }


    // 继续完成recover_proxy_signer方法
    pub fn recover_proxy_signer(&self) -> Result<PublicKey, DecoderError> {
        // 1. 重新构建消息
        let mut packed = Vec::new();
        
        let  pay_id_bytes:[u8;32] = self.pay_id.to_be_bytes();
        packed.extend_from_slice(&pay_id_bytes);
        
        let serv_id_bytes = self.serv_id.to_be_bytes();
        packed.extend_from_slice(&serv_id_bytes);
        
        let  amount_bytes:[u8;32] = self.amount.to_be_bytes();
        packed.extend_from_slice(&amount_bytes);
        
        packed.extend_from_slice(&self.receiver);
        packed.extend_from_slice(&self.sig_sender);
        packed.extend_from_slice(&[self.settled as u8]);
        
        // 2. 计算消息哈希
        let message_hash = keccak256(&packed);
        
        // 3. 解析签名和恢复ID
        let sig = Signature::parse_standard_slice(&self.sig_proxy[..64])
            .map_err(|_| DecoderError::Custom("Failed to parse signature"))?;
            
        let recovery_id = RecoveryId::parse(self.sig_proxy[64])
            .map_err(|_| DecoderError::Custom("Failed to parse recovery id"))?;
            
        let msg = Message::parse_slice(&message_hash)
            .map_err(|_| DecoderError::Custom("Failed to parse message"))?;
            
        // 4. 恢复公钥
        recover(&msg, &sig, &recovery_id)
            .map_err(|_| DecoderError::Custom("Failed to recover public key"))
    }

    // 便利方法：设置金额和结算状态
    pub fn set_settlement(&mut self, amount: U256, settled: bool) {
        self.amount = amount;
        self.settled = settled;
    }
    /// 获取代理签名者的以太坊地址
    pub fn get_proxy_address(&self) -> Result<EthAddress, DecoderError> {
        // 1. 首先恢复公钥
        let public_key = self.recover_proxy_signer()?;
        
        // 2. 将公钥转换为以太坊地址
        Ok(super::get_ethereum_address(&public_key))
    }

    /// 获取原始签名者的以太坊地址
    pub fn get_sender_address(&self) -> Result<EthAddress, DecoderError> {
        // 1. 创建临时Payment对象用于恢复原始签名者
        let temp_payment = Payment {
            pay_id: self.pay_id,
            serv_id: self.serv_id,
            receiver: self.receiver,
            sig_sender: self.sig_sender,
            amount:self.amount,
        };
        
        // 2. 使用Payment的方法获取签名者地址
        temp_payment.get_signer_address()
    }
}
// 为PaymentSettledByProxy实现From<Payment> trait
impl From<Payment> for PaymentSettledByProxy {
    fn from(payment: Payment) -> Self {
        PaymentSettledByProxy {
            pay_id: payment.pay_id,
            serv_id: payment.serv_id,
            amount: payment.amount, // 默认金额设为0
            receiver: payment.receiver,
            sig_sender: payment.sig_sender,
            settled: false,       // 默认未结算
            sig_proxy: [0u8; 65], // 默认签名
        }
    }
}

// 包装类型
#[derive(Debug, Clone, PartialEq)]
pub struct RlpSignature(EthSignature);

// 实现转换方法
impl From<EthAddress> for RlpAddress {
    fn from(addr: EthAddress) -> Self {
        RlpAddress(addr)
    }
}

impl From<RlpAddress> for EthAddress {
    fn from(addr: RlpAddress) -> Self {
        addr.0
    }
}

impl From<U256> for RlpU256 {
    fn from(value: U256) -> Self {
        RlpU256(value)
    }
}

impl From<RlpU256> for U256 {
    fn from(value: RlpU256) -> Self {
        value.0
    }
}

impl From<EthSignature> for RlpSignature {
    fn from(sig: EthSignature) -> Self {
        RlpSignature(sig)
    }
}

impl From<RlpSignature> for EthSignature {
    fn from(sig: RlpSignature) -> Self {
        sig.0
    }
}

// 为包装类型实现 RLP 编码和解码
impl Encodable for RlpAddress {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append(&&self.0[..]);
    }
}

impl Decodable for RlpAddress {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let bytes = rlp.data()?;
        if bytes.len() != 20 {
            return Err(DecoderError::Custom("Invalid Address length"));
        }
        let array: [u8; 20] = bytes
            .try_into()
            .map_err(|_| DecoderError::Custom("Failed to convert signature bytes"))?;

        Ok(RlpAddress(array.into()))
    }
}

impl Encodable for RlpU256 {
    fn rlp_append(&self, stream: &mut RlpStream) {
        let bytes = self.0.to_be_bytes::<32>();
        // 移除前导零
        let mut start = 0;
        while start < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        if start == bytes.len() {
            stream.append(&&[0u8][..]);
        } else {
            stream.append(&&bytes[start..]);
        }
    }
}

impl Decodable for RlpU256 {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let bytes = rlp.data()?;
        if bytes.is_empty() || bytes.len() > 32 {
            return Err(DecoderError::Custom("Invalid U256 length"));
        }
        let mut buffer = [0u8; 32];
        buffer[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(RlpU256(U256::from_be_slice(&buffer)))
    }
}

impl Encodable for RlpSignature {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append(&&self.0[..]);
    }
}

impl Decodable for RlpSignature {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let bytes = rlp.data()?;
        if bytes.len() != 65 {
            return Err(DecoderError::Custom("Invalid signature length"));
        }
        let array: [u8; 65] = bytes
            .try_into()
            .map_err(|_| DecoderError::Custom("Failed to convert signature bytes"))?;

        Ok(RlpSignature(array.into()))
    }
}

// 为 Payment 实现序列化
impl Encodable for Payment {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(4);
        stream.append(&RlpU256(self.pay_id));
        stream.append(&self.serv_id);
        stream.append(&RlpU256(self.amount));  // 新增字段
 
        stream.append(&RlpAddress(self.receiver));
        stream.append(&RlpSignature(self.sig_sender));
    }
}

impl Decodable for Payment {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 5 {  // 修改为5个字段
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(Payment {
            pay_id: RlpU256::decode(&rlp.at(0)?)?.into(),
            serv_id: rlp.val_at(1)?,
            amount: RlpU256::decode(&rlp.at(2)?)?.into(),  // 新增字段
            receiver: RlpAddress::decode(&rlp.at(3)?)?.into(),
            sig_sender: RlpSignature::decode(&rlp.at(4)?)?.into(),
        })
    }
}

// 为 PaymentSettledByProxy 实现序列化
impl Encodable for PaymentSettledByProxy {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(7);
        stream.append(&RlpU256(self.pay_id));
        stream.append(&self.serv_id);
        stream.append(&RlpU256(self.amount));
        stream.append(&RlpAddress(self.receiver));
        stream.append(&RlpSignature(self.sig_sender));
        stream.append(&self.settled);
        stream.append(&RlpSignature(self.sig_proxy));
    }
}

impl Decodable for PaymentSettledByProxy {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 7 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(PaymentSettledByProxy {
            pay_id: RlpU256::decode(&rlp.at(0)?)?.into(),
            serv_id: rlp.val_at(1)?,
            amount: RlpU256::decode(&rlp.at(2)?)?.into(),
            receiver: RlpAddress::decode(&rlp.at(3)?)?.into(),
            sig_sender: RlpSignature::decode(&rlp.at(4)?)?.into(),
            settled: rlp.val_at(5)?,
            sig_proxy: RlpSignature::decode(&rlp.at(6)?)?.into(),
        })
    }
}

// 为两个结构体添加便利方法
impl Payment {
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        self.rlp_append(&mut stream);
        stream.out().to_vec()
    }

    pub fn rlp_decode(bytes: &[u8]) -> Result<Self, DecoderError> {
        let rlp = Rlp::new(bytes);
        Self::decode(&rlp)
    }
}

impl PaymentSettledByProxy {
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        self.rlp_append(&mut stream);
        stream.out().to_vec()
    }

    pub fn rlp_decode(bytes: &[u8]) -> Result<Self, DecoderError> {
        let rlp = Rlp::new(bytes);
        Self::decode(&rlp)
    }
}
impl Payment {
    pub fn hash(&self) -> B256 {
        // 将所有字段按固定顺序打包
        let mut packed = Vec::new();
        
        // 添加 pay_id
        packed.extend_from_slice(&self.pay_id.to_be_bytes::<32>());
        
        // 添加 serv_id
        packed.extend_from_slice(&self.serv_id.to_be_bytes());
        
        packed.extend_from_slice(&self.amount.to_be_bytes::<32>());
   
        // 添加 receiver
        packed.extend_from_slice(&self.receiver);
        
        // 添加 sig_sender
        packed.extend_from_slice(&self.sig_sender);
        
        // 计算哈希
        B256::from_slice(&keccak256(&packed))
    }
}

impl PaymentSettledByProxy {
    pub fn hash(&self) -> B256 {
        // 将所有字段按固定顺序打包
        let mut packed = Vec::new();
        
        // 添加 pay_id
        packed.extend_from_slice(&self.pay_id.to_be_bytes::<32>());
        
        // 添加 serv_id
        packed.extend_from_slice(&self.serv_id.to_be_bytes());
        
        // 添加 amount
        packed.extend_from_slice(&self.amount.to_be_bytes::<32>());
        
        // 添加 receiver
        packed.extend_from_slice(&self.receiver);
        
        // 添加 sig_sender
        packed.extend_from_slice(&self.sig_sender);
        
        // 添加 settled
        packed.push(self.settled as u8);
        
        // 添加 sig_proxy
        packed.extend_from_slice(&self.sig_proxy);
        
        // 计算哈希
        B256::from_slice(&keccak256(&packed))
    }

    // hash_for_signing 方法也需要更新
    pub fn hash_for_signing(&self) -> B256 {
        let mut packed = Vec::new();
        
        packed.extend_from_slice(&self.pay_id.to_be_bytes::<32>());
        packed.extend_from_slice(&self.serv_id.to_be_bytes());
        packed.extend_from_slice(&self.amount.to_be_bytes::<32>());
        packed.extend_from_slice(&self.receiver);
        packed.extend_from_slice(&self.sig_sender);
        packed.push(self.settled as u8);
        
        B256::from_slice(&keccak256(&packed))
    }
    // 辅助函数：将payment转换为key
    pub fn to_key(&self) ->B256{
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(&self.pay_id.to_be_bytes::<32>());
        hasher.update(&self.serv_id.to_be_bytes());
        hasher.update(&self.receiver);
        hasher.finalize(&mut output);
        output.into()
    }
}


// 添加测试
#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn test_payment_hash() {
        let payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
        };

        let hash1 = payment.hash();
        let hash2 = payment.hash();
        
        // 相同数据应产生相同的哈希
        assert_eq!(hash1, hash2);
        
        // 修改任何字段应产生不同的哈希
        let mut payment2 = payment.clone();
        payment2.pay_id = U256::from(2);
        assert_ne!(payment.hash(), payment2.hash());
    }

    #[test]
    fn test_payment_settled_hash() {
        let payment = PaymentSettledByProxy {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
            settled: true,
            sig_proxy: EthSignature::from([2u8; 65]),
        };

        let hash1 = payment.hash();
        let hash2 = payment.hash();
        
        // 相同数据应产生相同的哈希
        assert_eq!(hash1, hash2);
        
        // 测试 hash_for_signing
        let signing_hash1 = payment.hash_for_signing();
        let signing_hash2 = payment.hash_for_signing();
        assert_eq!(signing_hash1, signing_hash2);
        
        // signing hash 应该与完整 hash 不同
        assert_ne!(hash1, signing_hash1);
        
        // 修改签名不应影响 hash_for_signing
        let mut payment2 = payment.clone();
        payment2.sig_proxy = EthSignature::from([3u8; 65]);
        assert_eq!(payment.hash_for_signing(), payment2.hash_for_signing());
        assert_ne!(payment.hash(), payment2.hash());
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_rlp() {
        let payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),  // 添加 amount
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
        };

        let encoded = payment.rlp_encode();
        let decoded = Payment::rlp_decode(&encoded).unwrap();

        assert_eq!(payment.pay_id, decoded.pay_id);
        assert_eq!(payment.serv_id, decoded.serv_id);
        assert_eq!(payment.receiver, decoded.receiver);
        assert_eq!(payment.sig_sender, decoded.sig_sender);
    }

    #[test]
    fn test_payment_settled_rlp() {
        let payment_settled = PaymentSettledByProxy {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
            settled: true,
            sig_proxy: EthSignature::from([2u8; 65]),
        };

        let encoded = payment_settled.rlp_encode();
        let decoded = PaymentSettledByProxy::rlp_decode(&encoded).unwrap();

        assert_eq!(payment_settled.pay_id, decoded.pay_id);
        assert_eq!(payment_settled.serv_id, decoded.serv_id);
        assert_eq!(payment_settled.amount, decoded.amount);
        assert_eq!(payment_settled.receiver, decoded.receiver);
        assert_eq!(payment_settled.sig_sender, decoded.sig_sender);
        assert_eq!(payment_settled.settled, decoded.settled);
        assert_eq!(payment_settled.sig_proxy, decoded.sig_proxy);
    }


    // 辅助函数：创建测试数据
    fn create_test_payment() -> Payment {
        Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),  // 添加 amount
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
        }
    }

    fn create_test_payment_settled() -> PaymentSettledByProxy {
        PaymentSettledByProxy {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),
            receiver: EthAddress::from([1u8; 20]),
            sig_sender: EthSignature::from([1u8; 65]),
            settled: true,
            sig_proxy: EthSignature::from([2u8; 65]),
        }
    }

    // U256 编码测试
    #[test]
    fn test_u256_rlp_zero() {
        let value = RlpU256(U256::default());
        let mut stream = RlpStream::new();
        stream.append(&value);
        let encoded = stream.out();
        let decoded = RlpU256::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u256_rlp_max() {
        let value = RlpU256(U256::MAX);
        let mut stream = RlpStream::new();
        stream.append(&value);
        let encoded = stream.out();
        let decoded = RlpU256::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u256_rlp_random_values() {
        let values = vec![
            U256::from(1),
            U256::from(0xFF),
            U256::from(0xFFFF),
            U256::from(0xFFFFFF),
        ];

        for value in values {
            let rlp_value = RlpU256(value);
            let mut stream = RlpStream::new();
            stream.append(&rlp_value);
            let encoded = stream.out();
            let decoded = RlpU256::decode(&Rlp::new(&encoded)).unwrap();
            assert_eq!(rlp_value, decoded);
        }
    }

    // Address 编码测试
    #[test]
    fn test_address_rlp_zero() {
        let addr = RlpAddress(EthAddress::from([0u8; 20]));
        let mut stream = RlpStream::new();
        stream.append(&addr);
        let encoded = stream.out();
        let decoded = RlpAddress::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_rlp_all_ones() {
        let addr = RlpAddress(EthAddress::from([0xFFu8; 20]));
        let mut stream = RlpStream::new();
        stream.append(&addr);
        let encoded = stream.out();
        let decoded = RlpAddress::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(addr, decoded);
    }

    // Signature 编码测试
    #[test]
    fn test_signature_rlp_zero() {
        let sig = RlpSignature(EthSignature::from([0u8; 65]));
        let mut stream = RlpStream::new();
        stream.append(&sig);
        let encoded = stream.out();
        let decoded = RlpSignature::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_signature_rlp_all_ones() {
        let sig = RlpSignature(EthSignature::from([0xFFu8; 65]));
        let mut stream = RlpStream::new();
        stream.append(&sig);
        let encoded = stream.out();
        let decoded = RlpSignature::decode(&Rlp::new(&encoded)).unwrap();
        assert_eq!(sig, decoded);
    }

    // Payment 结构体测试
    #[test]
    fn test_payment_rlp_normal() {
        let payment = create_test_payment();
        let encoded = payment.rlp_encode();
        let decoded = Payment::rlp_decode(&encoded).unwrap();
        assert_eq!(payment.pay_id, decoded.pay_id);
        assert_eq!(payment.serv_id, decoded.serv_id);
        assert_eq!(payment.receiver, decoded.receiver);
        assert_eq!(payment.sig_sender, decoded.sig_sender);
    }

    #[test]
    fn test_payment_rlp_zero_values() {
        let payment = Payment {
            pay_id: U256::default(),
            serv_id: 0,
            amount: U256::from(100),  // 添加 amount
            receiver: EthAddress::from([0u8; 20]),
            sig_sender: EthSignature::from([0u8; 65]),
        };
        let encoded = payment.rlp_encode();
        let decoded = Payment::rlp_decode(&encoded).unwrap();
        assert_eq!(payment.pay_id, decoded.pay_id);
        assert_eq!(payment.serv_id, decoded.serv_id);
        assert_eq!(payment.receiver, decoded.receiver);
        assert_eq!(payment.sig_sender, decoded.sig_sender);
    }

    // PaymentSettledByProxy 结构体测试
    #[test]
    fn test_payment_settled_rlp_normal() {
        let payment = create_test_payment_settled();
        let encoded = payment.rlp_encode();
        let decoded = PaymentSettledByProxy::rlp_decode(&encoded).unwrap();
        assert_eq!(payment.pay_id, decoded.pay_id);
        assert_eq!(payment.serv_id, decoded.serv_id);
        assert_eq!(payment.amount, decoded.amount);
        assert_eq!(payment.receiver, decoded.receiver);
        assert_eq!(payment.sig_sender, decoded.sig_sender);
        assert_eq!(payment.settled, decoded.settled);
        assert_eq!(payment.sig_proxy, decoded.sig_proxy);
    }

    // 错误情况测试
    #[test]
    fn test_invalid_address_length() {
        let invalid_bytes = vec![0u8; 19]; // 错误的地址长度
        let result = RlpAddress::decode(&Rlp::new(&invalid_bytes));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        // 1. 测试长度不足的签名
        let mut stream = RlpStream::new();
        let short_sig = vec![1u8; 64]; // 64字节（少于所需的65字节）
        stream.append(&short_sig);
        let encoded = stream.out();
        let result = RlpSignature::decode(&Rlp::new(&encoded));
        assert!(result.is_err());

        // 2. 测试过长的签名
        let mut stream = RlpStream::new();
        let long_sig = vec![1u8; 66]; // 66字节（多于所需的65字节）
        stream.append(&long_sig);
        let encoded = stream.out();
        let result = RlpSignature::decode(&Rlp::new(&encoded));
        assert!(result.is_err());

        // 3. 测试空签名
        let mut stream = RlpStream::new();
        let empty_sig = vec![]; // 空字节数组
        stream.append(&empty_sig);
        let encoded = stream.out();
        let result = RlpSignature::decode(&Rlp::new(&encoded));
        assert!(result.is_err());

        // 4. 测试错误的RLP列表格式
        let mut stream = RlpStream::new();
        stream.begin_list(1);
        stream.append(&vec![1u8; 65]); // 正确长度但错误格式
        let encoded = stream.out();
        let result = RlpSignature::decode(&Rlp::new(&encoded));
        assert!(result.is_err());
    }
    // 添加正确情况的测试作为对比
    #[test]
    fn test_valid_signature_length() {
        let mut stream = RlpStream::new();
        let valid_sig = vec![1u8; 65]; // 正确的65字节长度
        stream.append(&valid_sig);
        let encoded = stream.out();
        let result = RlpSignature::decode(&Rlp::new(&encoded));
        assert!(result.is_ok());
    }
    #[test]
    fn test_invalid_u256_length() {
        let mut stream = RlpStream::new();
        let invalid_bytes = vec![1u8; 33]; // 33字节的数据（超过U256的32字节限制）
        stream.append(&invalid_bytes);
        let encoded = stream.out();
        let result = RlpU256::decode(&Rlp::new(&encoded));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_payment_format() {
        let invalid_encoded = vec![0u8; 10]; // 无效的RLP编码
        let result = Payment::rlp_decode(&invalid_encoded);
        assert!(result.is_err());
    }

    // From trait 测试
    #[test]
    fn test_payment_to_settled() {
        let payment = create_test_payment();
        let settled: PaymentSettledByProxy = payment.clone().into();

        assert_eq!(payment.pay_id, settled.pay_id);
        assert_eq!(payment.serv_id, settled.serv_id);
        assert_eq!(payment.receiver, settled.receiver);
        assert_eq!(payment.sig_sender, settled.sig_sender);
        assert_eq!(settled.amount, U256::default());
        assert!(!settled.settled);
        assert_eq!(settled.sig_proxy, EthSignature::from([0u8; 65]));
    }

    // 边界值测试
    #[test]
    fn test_boundary_values() {
        let payment = Payment {
            pay_id: U256::MAX,
            serv_id: u32::MAX,
            amount: U256::MAX,  // 添加 amount
            receiver: EthAddress::from([0xFFu8; 20]),
            sig_sender: EthSignature::from([0xFFu8; 65]),
        };

        let encoded = payment.rlp_encode();
        let decoded = Payment::rlp_decode(&encoded).unwrap();
        assert_eq!(payment.pay_id, decoded.pay_id);
        assert_eq!(payment.serv_id, decoded.serv_id);
        assert_eq!(payment.receiver, decoded.receiver);
        assert_eq!(payment.sig_sender, decoded.sig_sender);
    }

    #[test]
    fn test_payment_settled_sign_and_verify() {
        // 1. 创建私钥
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_public_key = PublicKey::from_secret_key(&proxy_key);
        
        // 2. 创建初始Payment并签名
        let mut payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount:U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65],
        };
        payment.sign(&sender_key).unwrap();
        
        // 3. 转换为PaymentSettledByProxy
        let mut payment_settled: PaymentSettledByProxy = payment.into();
        
        // 4. 设置结算信息
        payment_settled.set_settlement(U256::from(100), true);
        
        // 5. 代理签名
        payment_settled.sign_by_proxy(&proxy_key).unwrap();
        
        // 6. 验证代理签名
        assert!(payment_settled.verify_proxy_signature(&proxy_public_key).unwrap());
        
        // 7. 测试恢复签名者
        let recovered_key = payment_settled.recover_proxy_signer().unwrap();
        assert_eq!(recovered_key, proxy_public_key);
    }

    #[test]
    fn test_payment_settled_invalid_proxy_signature() {
        // 1. 创建私钥
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key1 = SecretKey::random(&mut rand::thread_rng());
        let proxy_key2 = SecretKey::random(&mut rand::thread_rng());
        let proxy_public_key2 = PublicKey::from_secret_key(&proxy_key2);
        
        // 2. 创建初始Payment并签名
        let mut payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount:U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65],
        };
        payment.sign(&sender_key).unwrap();
        
        // 3. 转换为PaymentSettledByProxy
        let mut payment_settled: PaymentSettledByProxy = payment.into();
        
        // 4. 设置结算信息并用proxy_key1签名
        payment_settled.set_settlement(U256::from(100), true);
        payment_settled.sign_by_proxy(&proxy_key1).unwrap();
        
        // 5. 用proxy_key2的公钥验证，应该失败
        assert!(!payment_settled.verify_proxy_signature(&proxy_public_key2).unwrap());
    }

    #[test]
    fn test_payment_settled_data_integrity() {
        // 1. 创建私钥
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_public_key = PublicKey::from_secret_key(&proxy_key);
        
        // 2. 创建并签名PaymentSettledByProxy
        let mut payment_settled = PaymentSettledByProxy {
            pay_id: U256::from(1),
            serv_id: 1,
            amount: U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65],
            settled: true,
            sig_proxy: [0u8; 65],
        };
        
        // 3. 签名
        payment_settled.sign_by_proxy(&proxy_key).unwrap();
        
        // 4. 验证签名
        assert!(payment_settled.verify_proxy_signature(&proxy_public_key).unwrap());
        
        // 5. 修改数据后验证应该失败
        payment_settled.amount = U256::from(200);
        assert!(!payment_settled.verify_proxy_signature(&proxy_public_key).unwrap());
    }
    #[test]
    fn test_payment_get_signer_address() {
        // 1. 创建私钥和对应的公钥
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secret_key);
        
        // 2. 创建支付对象
        let mut payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount:U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65],
        };
        
        // 3. 签名
        payment.sign(&secret_key).unwrap();
        
        // 4. 获取签名者地址
        let signer_address = payment.get_signer_address().unwrap();
        
        // 5. 直接从公钥计算地址进行比较
        let expected_address = crate::get_ethereum_address(&public_key);
        assert_eq!(signer_address, expected_address);
    }

    #[test]
    fn test_payment_get_signer_address_with_invalid_signature() {
        // 1. 创建无效签名的支付对象
        let payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount:U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65], // 无效签名
        };
        
        // 2. 尝试获取签名者地址，应该失败
        assert!(payment.get_signer_address().is_err());
    }

    #[test]
    fn test_payment_signer_address_consistency() {
        // 1. 创建私钥
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secret_key);
        
        // 2. 创建多个不同的支付对象
        let mut payments = vec![];
        for i in 0..3 {
            let mut payment = Payment {
                pay_id: U256::from(i),
                serv_id: i as u32,
                amount:U256::from(i),
                receiver: [1u8; 20],
                sig_sender: [0u8; 65],
            };
            payment.sign(&secret_key).unwrap();
            payments.push(payment);
        }
        
        // 3. 验证所有支付对象恢复出相同的地址
        let first_address = payments[0].get_signer_address().unwrap();
        for payment in payments.iter().skip(1) {
            assert_eq!(payment.get_signer_address().unwrap(), first_address);
        }
        
        // 4. 验证地址与直接从公钥计算的地址相同
        let expected_address = crate::get_ethereum_address(&public_key);
        assert_eq!(first_address, expected_address);
    }
    #[test]
    fn test_payment_settled_get_signer_addresses() {
        // 1. 创建发送者和代理的私钥
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key = SecretKey::random(&mut rand::thread_rng());
        
        let sender_public_key = PublicKey::from_secret_key(&sender_key);
        let proxy_public_key = PublicKey::from_secret_key(&proxy_key);
        
        // 2. 创建初始Payment并签名
        let mut payment = Payment {
            pay_id: U256::from(1),
            serv_id: 1,
            amount:U256::from(100),
            receiver: [1u8; 20],
            sig_sender: [0u8; 65],
        };
        payment.sign(&sender_key).unwrap();
        
        // 3. 转换为PaymentSettledByProxy并添加代理签名
        let mut payment_settled: PaymentSettledByProxy = payment.into();
        payment_settled.set_settlement(U256::from(100), true);
        payment_settled.sign_by_proxy(&proxy_key).unwrap();
        
        // 4. 验证原始签名者地址
        let sender_address = payment_settled.get_sender_address().unwrap();
        let expected_sender_address = crate::get_ethereum_address(&sender_public_key);
        assert_eq!(sender_address, expected_sender_address);
        
        // 5. 验证代理签名者地址
        let proxy_address = payment_settled.get_proxy_address().unwrap();
        let expected_proxy_address = crate::get_ethereum_address(&proxy_public_key);
        assert_eq!(proxy_address, expected_proxy_address);
    }
}
