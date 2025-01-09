use super::{EthAddress, PaymentSettledByProxy};
use crate::ethaddr_gen::EthAddressGen;
use crate::{
    get_ethereum_address,
    models::{segment_vc::MerkleProof, PayIdInfo, ServiceFeeConfig},
    BoxError,
};
/**
 * @fileoverview added by tsickle
 * @promotion
 * 输入以下的内容： 接收者地址，代理地址， 针对该接收者的所有已经结算的收据，一个默克尔证明，一组PayIdInfos，一组ServID
 *
 * 处理过程：
 * 预验证
 * 1. 验证PayIdInfos的合法性，确保所有的PayIdInfo的Channel都属于同一个代理
 * 2. 收据的默克尔证明验证通过以下方式验证：
 *  所有的收据以排序 通过to_key(),hash()得到值
 *  所有的收据以to_key()的结果排序
 *  对所有的哈希全部再哈希一次，得到hash_of_all_payment
 *  hash_of_all_payment必须能够通过默克尔证明
 * 3. 收据中所有的接收者都是自己
 * 4. 针对每个收据，验证sig_sender,sig_proxy的有效性，以及sig_proxy必须由代理地址签发，sig_sender必须与PayIdInfos中的Sender一致
 *
 * 进行计算：
 * 1. 针对每一个收据，根据Amount和ServID，计算得到 system_profit = Amount * b_system, 代理分佣 Proxy_Profit = Amount * b_proxy  ,剩下的是接收者的收入,receiver
 * 2. 累计每个收据得总的system_profit,Proxy_profit,receiver_profit
 *
 * 输出：
 *  接收者地址
 *  代理地址
 *  所有收据的哈希（从默克尔证明中取得）
 *  PayIdInfos的哈希
 *  ServID的哈希
 *  总的system_profit,Proxy_profit,receiver_profit
 *
 */
use alloy_primitives::{B256, U256};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use crate::ProfitResult;

pub struct ReceiptsProfitCalculator {
    receiver: EthAddress,
    proxy: EthAddress,
    receipts: Vec<PaymentSettledByProxy>,
    merkle_proof: MerkleProof,
    pay_id_infos: Vec<PayIdInfo>,
    service_configs: Vec<ServiceFeeConfig>,
}

impl ReceiptsProfitCalculator {
    pub fn new(
        receiver: EthAddress,
        proxy: EthAddress,
        receipts: Vec<PaymentSettledByProxy>,
        merkle_proof: MerkleProof,
        pay_id_infos: Vec<PayIdInfo>,
        service_configs: Vec<ServiceFeeConfig>,
    ) -> Self {
        Self {
            receiver,
            proxy,
            receipts,
            merkle_proof,
            pay_id_infos,
            service_configs,
        }
    }

    pub fn calculate(&self) -> Result<ProfitResult, BoxError> {
        // 1. 预验证
        self.validate_prerequisites()?;

        // 2. 计算利润
        let (system_profit, proxy_profit, receiver_profit) = self.calculate_profits()?;

        // 3. 计算各种根哈希
        let receipts_root = self.merkle_proof.root_hash;
        let pay_ids_root = self.calculate_pay_ids_root()?;
        let serv_ids_root = self.calculate_serv_ids_root()?;

        Ok(ProfitResult {
            receiver: self.receiver,
            proxy: self.proxy,
            receipts_root,
            pay_ids_root,
            serv_ids_root,
            system_profit,
            proxy_profit,
            receiver_profit,
        })
    }

    fn validate_prerequisites(&self) -> Result<(), BoxError> {
        // 1. 验证PayIdInfos的代理地址
        for info in &self.pay_id_infos {
            if info.proxy != self.proxy {
                return Err(format!(
                    "Invalid proxy in PayIdInfo. Expected: {:?}, Got: {:?}",
                    self.proxy, info.proxy
                )
                .into());
            }
        }

        // 2. 验证默克尔证明
        self.validate_merkle_proof()?;

        // 3. 验证接收者地址
        for receipt in &self.receipts {
            if receipt.receiver != self.receiver {
                return Err(format!(
                    "Invalid receiver in receipt. Expected: {:?}, Got: {:?}",
                    self.receiver, receipt.receiver
                )
                .into());
            }
        }

        // 4. 验证签名
        self.validate_signatures()?;

        Ok(())
    }

    fn validate_merkle_proof(&self) -> Result<(), BoxError> {
        // 1. 对收据排序
        let mut sorted_receipts = self.receipts.clone();
        sorted_receipts.sort_by(|a, b| a.to_key().cmp(&b.to_key()));

        // 2. 计算所有收据的组合哈希
        let mut hasher = Keccak256::new();
        for receipt in &sorted_receipts {
            let receipt_hash = receipt.hash();
            hasher.update(receipt_hash.as_slice());
        }
        let hash_of_all_payments = B256::from_slice(&hasher.finalize());

        // 3. 验证组合哈希是否与证明中的值相等
        if self.merkle_proof.value_proof.value != hash_of_all_payments {
            return Err("Invalid Merkle proof and hash of receipts".into());
        }
        // 4. 验证默克尔证明
        if !self.merkle_proof.verify()? {
            return Err("Invalid Merkle proof for receipts".into());
        }

        Ok(())
    }

    fn validate_signatures(&self) -> Result<(), BoxError> {
        // 创建PayId到发送者的映射
        let pay_id_senders: HashMap<U256, EthAddress> = self
            .pay_id_infos
            .iter()
            .map(|info| (info.id, info.sender))
            .collect();

        for receipt in &self.receipts {
            // 获取对应的发送者
            let sender = pay_id_senders
                .get(&receipt.pay_id)
                .ok_or_else(|| format!("PayId {} not found in PayIdInfos", receipt.pay_id))?;

            // 验证发送者地址
            let recovered_sender = receipt.get_sender_address()?;
            if &recovered_sender != sender {
                return Err(format!(
                    "Invalid sender signature. Expected: {:?}, Got: {:?}",
                    sender, recovered_sender
                )
                .into());
            }

            // 验证代理地址
            let recovered_proxy = receipt.get_proxy_address()?;
            if recovered_proxy != self.proxy {
                return Err(format!(
                    "Invalid proxy signature. Expected: {:?}, Got: {:?}",
                    self.proxy, recovered_proxy
                )
                .into());
            }
        }

        Ok(())
    }

    fn calculate_profits(&self) -> Result<(U256, U256, U256), BoxError> {
        let mut total_system_profit = U256::default();
        let mut total_proxy_profit = U256::default();
        let mut total_receiver_profit = U256::default();

        // 创建服务费率查找表
        let fee_configs: HashMap<u32, &ServiceFeeConfig> = self
            .service_configs
            .iter()
            .map(|config| (config.serv_id, config))
            .collect();

        let base_rate = U256::from(10000); // 费率基数

        for receipt in &self.receipts {
            let config = fee_configs.get(&receipt.serv_id).ok_or_else(|| {
                format!("Service config not found for serv_id: {}", receipt.serv_id)
            })?;
            let system_fee_rate = U256::from(config.system_fee_rate);
            let proxy_fee_rate = U256::from(config.proxy_fee_rate);
            // 计算系统分成
            let system_fee = receipt
                .amount
                .checked_mul(system_fee_rate)
                .ok_or("Multiplication overflow")?
                .checked_div(base_rate)
                .ok_or("Division by zero")?;
            total_system_profit = total_system_profit
                .checked_add(system_fee)
                .ok_or("Addition overflow")?;

            // 计算代理分成
            let proxy_fee = receipt
                .amount
                .checked_mul(proxy_fee_rate)
                .ok_or("Multiplication overflow")?
                .checked_div(base_rate)
                .ok_or("Division by zero")?;
            total_proxy_profit = total_proxy_profit
                .checked_add(proxy_fee)
                .ok_or("Addition overflow")?;

            // 计算接收者收入
            let receiver_fee = receipt
                .amount
                .checked_sub(system_fee)
                .ok_or("Subtraction overflow")?
                .checked_sub(proxy_fee)
                .ok_or("Subtraction overflow")?;
            total_receiver_profit = total_receiver_profit
                .checked_add(receiver_fee)
                .ok_or("Addition overflow")?;
        }

        Ok((
            total_system_profit,
            total_proxy_profit,
            total_receiver_profit,
        ))
    }

    fn calculate_pay_ids_root(&self) -> Result<B256, BoxError> {
        // 对PayIdInfo排序并计算哈希
        let mut sorted_pay_ids = self.pay_id_infos.clone();
        sorted_pay_ids.sort_by(|a, b| a.id.cmp(&b.id));

        let mut hasher = Keccak256::new();
        for pay_id_info in &sorted_pay_ids {
            hasher.update(pay_id_info.hash().as_slice());
        }

        Ok(B256::from_slice(&hasher.finalize()))
    }

    fn calculate_serv_ids_root(&self) -> Result<B256, BoxError> {
        // 对ServiceFeeConfig排序并计算哈希
        let mut sorted_configs = self.service_configs.clone();
        sorted_configs.sort_by(|a, b| a.serv_id.cmp(&b.serv_id));

        let mut hasher = Keccak256::new();
        for config in &sorted_configs {
            // 打包服务配置数据
            hasher.update(&config.serv_id.to_be_bytes());
            hasher.update(&config.system_fee_rate.to_be_bytes());
            hasher.update(&config.proxy_fee_rate.to_be_bytes());
        }

        Ok(B256::from_slice(&hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::overpay_checker::ReceiptsOverpayChecker;
    use libsecp256k1::{PublicKey, SecretKey}; // 添加这行

    fn create_test_payment(
        pay_id: u64,
        serv_id: u32,
        amount: u64,
        receiver: EthAddress,
        sender_key: &SecretKey,
        proxy_key: &SecretKey,
    ) -> Result<PaymentSettledByProxy, BoxError> {
        // 1. 创建并签名Payment
        let mut payment = super::super::Payment {
            pay_id: U256::from(pay_id),
            serv_id,
            receiver,
            sig_sender: [0u8; 65],
        };
        payment.sign(sender_key)?;

        // 2. 转换为PaymentSettledByProxy并签名
        let mut settled = PaymentSettledByProxy::from(payment);
        settled.set_settlement(U256::from(amount), true);
        settled.sign_by_proxy(proxy_key)?;

        Ok(settled)
    }

    #[test]
    fn test_complete_calculation() -> Result<(), BoxError> {
        // 1. 创建密钥对
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key = SecretKey::random(&mut rand::thread_rng());

        let sender = get_ethereum_address(&PublicKey::from_secret_key(&sender_key));
        let proxy = get_ethereum_address(&PublicKey::from_secret_key(&proxy_key));
        let receiver = EthAddressGen::random();

        // 2. 创建测试数据
        let pay_id_infos = vec![
            PayIdInfo {
                id: U256::from(1),
                amount: U256::from(1000),
                sender,
                proxy,
                state: 1,
                created_at: 0,
                closing_time: 0,
            },
            PayIdInfo {
                id: U256::from(2),
                amount: U256::from(2000),
                sender,
                proxy,
                state: 1,
                created_at: 0,
                closing_time: 0,
            },
        ];

        let service_configs = vec![
            ServiceFeeConfig {
                serv_id: 1,
                system_fee_rate: 500, // 5%
                proxy_fee_rate: 1000, // 10%
            },
            ServiceFeeConfig {
                serv_id: 2,
                system_fee_rate: 300, // 3%
                proxy_fee_rate: 700,  // 7%
            },
        ];

        // 3. 创建收据
        let receipts = vec![
            create_test_payment(1, 1, 1000, receiver, &sender_key, &proxy_key)?,
            create_test_payment(2, 2, 2000, receiver, &sender_key, &proxy_key)?,
        ];
        // 4. 使用ReceiptsSorter生成MerkleProof
        let sorter = ReceiptsOverpayChecker::new(proxy, pay_id_infos.clone(), receipts.clone());
        let sort_result = sorter.process()?;
        // 找到对应receiver的proof
        let receiver_proof = sort_result
            .receiver_proofs
            .into_iter()
            .find(|p| p.receiver == receiver)
            .ok_or("Receiver proof not found")?;

        let service_configs = vec![
            ServiceFeeConfig {
                serv_id: 1,
                system_fee_rate: 500, // 5%
                proxy_fee_rate: 1000, // 10%
            },
            ServiceFeeConfig {
                serv_id: 2,
                system_fee_rate: 300, // 3%
                proxy_fee_rate: 700,  // 7%
            },
        ];
        // 4. 创建计算器实例
        let calculator = ReceiptsProfitCalculator::new(
            receiver,
            proxy,
            receipts,
            receiver_proof.proof, // 使用生成的proof
            pay_id_infos,
            service_configs,
        );

        // 5. 执行计算
        let result = calculator.calculate()?;

        // 6. 验证结果
        assert_eq!(result.receiver, receiver);
        assert_eq!(result.proxy, proxy);

        // 验证利润计算
        // 第一笔交易: 1000 * (5% + 10%) = 150
        // 第二笔交易: 2000 * (3% + 7%) = 200
        assert!(result.system_profit > U256::ZERO);
        assert!(result.proxy_profit > U256::ZERO);
        assert!(result.receiver_profit > U256::ZERO);

        // 验证总额
        let total = result.system_profit + result.proxy_profit + result.receiver_profit;
        assert_eq!(total, U256::from(3000)); // 1000 + 2000

        Ok(())
    }

    #[test]
    fn test_invalid_proxy() -> Result<(), BoxError> {
        let sender_key = SecretKey::random(&mut rand::thread_rng());
        let proxy_key = SecretKey::random(&mut rand::thread_rng());
        let wrong_proxy = EthAddressGen::random();
        let receiver = EthAddressGen::random();

        let sender = get_ethereum_address(&PublicKey::from_secret_key(&sender_key));
        let proxy = get_ethereum_address(&PublicKey::from_secret_key(&proxy_key));

        // 创建收据
        let receipts = vec![create_test_payment(
            1,
            1,
            1000,
            receiver,
            &sender_key,
            &proxy_key,
        )?];

        // 使用ReceiptsSorter生成MerkleProof
        let sorter = ReceiptsOverpayChecker::new(
            proxy, // 使用正确的代理地址生成proof
            vec![PayIdInfo {
                id: U256::from(1),
                amount: U256::from(1000),
                sender,
                proxy,
                state: 1,
                created_at: 0,
                closing_time: 0,
            }],
            receipts.clone(),
        );
        let sort_result = sorter.process()?;

        // 找到对应receiver的proof
        let receiver_proof = sort_result
            .receiver_proofs
            .into_iter()
            .find(|p| p.receiver == receiver)
            .ok_or("Receiver proof not found")?;

        // 创建测试数据，但使用错误的代理地址
        let calculator = ReceiptsProfitCalculator::new(
            receiver,
            wrong_proxy, // 使用错误的代理地址
            receipts,
            receiver_proof.proof, // 使用生成的proof
            vec![PayIdInfo {
                id: U256::from(1),
                amount: U256::from(1000),
                sender,
                proxy,
                state: 1,
                created_at: 0,
                closing_time: 0,
            }],
            vec![ServiceFeeConfig {
                serv_id: 1,
                system_fee_rate: 500,
                proxy_fee_rate: 1000,
            }],
        );

        // 验证应该失败
        assert!(calculator.calculate().is_err());

        Ok(())
    }
}
