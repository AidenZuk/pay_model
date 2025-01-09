use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{models::segment_vc::MerkleProof, BoxError};
use super::{EthAddress, PayIdsProcessor, PaymentsGrouper, PaymentSettledByProxy, ReceiverProof};
use crate:: models::{pay_id_infos::PayIdInfo,segment_vc::SegmentVC};
/**
 * 
 *   @pay_id_infos.rs
输一个地址channel(Ethaddress) 和两个数组对象，一个是PayIdInfo数组，一个是PaymentSettledByProxy数组，执行：

预处理：
1. 所有的PayIdInfo的Channel必须等于channel

2. 验证PaymentSettledByProxy中的每一个对象的settled必须为true

3.     pub pay_id: U256,
    pub serv_id: u32,
    pub receiver: EthAddress,
    以(pay_id,serv_idreceiver)为key,PaymentSettledByProxyn必须是唯一的

进行以下的处理

1. 超付管理
1.1. 根据PaymentSettledByProxy统计每一个pay_id的amount,得到每个pay_id累计amount的总额。

1.2. 每个pay_id累计的总额必须小于等于对应的PayIdInfo（以PayIdInfo.id对应）的amount

2.分类管理

 2.1 所有的PaymentSettledByProxy依照receiver分类，组成segment_vc，代码已经实现在receipts_pay_check中

3. PayIdInfo根据ID从小到大排序，然后组成segment_vc,代码已经实现在pay_ids_to_segvc中


4. 如果1.2满足，
    输出2.1的root_hash,每个receiver和相应的proof
    输出3的root_hash
 */
// PaymentSettledByProxy 结构体定义

pub struct ReceiptsOverpayChecker {
    channel: EthAddress,
    pay_id_infos: Vec<PayIdInfo>,
    settled_payments: Vec<PaymentSettledByProxy>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct OverpayCheckResult {
    pub payments_root: B256,
    pub receiver_proofs: Vec<ReceiverProof>,
    pub pay_ids_root: B256,
}

impl OverpayCheckResult {
    /// 根据接收者地址获取对应的默克尔证明
    pub fn get_merkle_proof(&self, receiver: EthAddress) -> Result<MerkleProof, BoxError> {
        // 从 receiver_proofs 中查找对应接收者的证明
        self.receiver_proofs
            .iter()
            .find(|proof| proof.receiver == receiver)
            .map(|proof| proof.proof.clone())
            .ok_or_else(|| "Merkle proof not found for receiver".into())
    }
}

impl ReceiptsOverpayChecker {
    pub fn new(
        channel: EthAddress,
        pay_id_infos: Vec<PayIdInfo>,
        settled_payments: Vec<PaymentSettledByProxy>,
    ) -> Self {
        Self {
            channel,
            pay_id_infos,
            settled_payments,
        }
    }

    pub fn process(&self) -> Result<OverpayCheckResult, BoxError> {
        // 1. 预处理验证
        self.validate_prerequisites()?;

        // 2. 超付验证
        self.validate_overpayment()?;

        // 3. 按receiver分类并创建segment_vc
        let (payments_root, receiver_proofs) = self.create_payments_vc()?;

        // 4. 创建PayIdInfo的segment_vc
        let pay_ids_root = self.create_pay_ids_vc()?;

        Ok(OverpayCheckResult {
            payments_root,
            receiver_proofs,
            pay_ids_root,
        })
    }

    fn validate_prerequisites(&self) -> Result<(), BoxError> {
        // 1. 验证channel
        for info in &self.pay_id_infos {
            if info.proxy != self.channel {
                return Err("Invalid channel in PayIdInfo".into());
            }
        }

        // 2. 验证settled状态
        for payment in &self.settled_payments {
            if !payment.settled {
                return Err("Found unsettled payment".into());
            }
        }

        // 3. 验证唯一性
        let mut seen = HashMap::new();
        for payment in &self.settled_payments {
            let key = (payment.pay_id, payment.serv_id, payment.receiver);
            if seen.insert(key, true).is_some() {
                return Err("Duplicate payment found".into());
            }
        }

        Ok(())
    }

    fn validate_overpayment(&self) -> Result<(), BoxError> {
        // 1. 统计每个pay_id的总额
        let mut pay_id_totals: HashMap<U256, U256> = HashMap::new();
        for payment in &self.settled_payments {
            *pay_id_totals.entry(payment.pay_id).or_default() += payment.amount;
        }

        //2. 统计每个pid的允许总额
        let pay_id_info_map: HashMap<U256, U256> = self.pay_id_infos
            .iter()
            .map(|info| (info.id, info.amount))
            .collect();
        
        // 3. 验证不超过PayIdInfo中的amount
        for (pay_id, total) in pay_id_totals {
            // let pay_id_bytes = B256::from_uint(&pay_id);
            if let Some(&max_amount) = pay_id_info_map.get(&pay_id) {
                if total > max_amount {
                    return Err(format!("Overpayment detected for pay_id {}", pay_id).into());
                }
            } else {
                return Err(format!("PayId {} not found in PayIdInfos", pay_id).into());
            }
        }

        Ok(())
    }
    fn create_payments_vc(&self) -> Result<(B256, Vec<ReceiverProof>), BoxError> {
        PaymentsGrouper::group_by_receiver(&self.settled_payments)
    }

    fn create_pay_ids_vc(&self) -> Result<B256, BoxError> {
        PayIdsProcessor::get_root_hash(&self.pay_id_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pay_id_info(id: u64, amount: u64, channel: EthAddress) -> PayIdInfo {
        PayIdInfo {
            id: U256::from(id),
            amount: U256::from(amount),
            sender: [0u8; 20].into(),
            proxy: channel,
            state: 1,
            created_at: 1000,
            closing_time: 2000,
        }
    }

    fn create_test_payment(
        pay_id: u64,
        serv_id: u32,
        receiver: EthAddress,
        amount: u64,
    ) -> PaymentSettledByProxy {
        PaymentSettledByProxy {
            pay_id: U256::from(pay_id),
            serv_id,
            receiver,
            amount: U256::from(amount),
            settled: true,
            sig_sender: [1u8;65],
            sig_proxy: [2u8;65],
        }
    }

    #[test]
    fn test_prerequisites_validation() -> Result<(), BoxError> {
        let channel = [1u8;20];
        let receiver = [21u8;20];

        let pay_id_infos = vec![
            create_test_pay_id_info(1, 1000, channel),
            create_test_pay_id_info(2, 2000, channel),
        ];

        let settled_payments = vec![
            create_test_payment(1, 1, receiver, 500),
            create_test_payment(1, 2, receiver, 400),
            create_test_payment(2, 1, receiver, 1000),
        ];

        let sorter = ReceiptsOverpayChecker::new(channel, pay_id_infos, settled_payments);
        sorter.validate_prerequisites()?;

        Ok(())
    }

    #[test]
    fn test_overpayment_validation() -> Result<(), BoxError> {
        let channel = [1u8;20];
        let receiver = [2u8;20];

        let pay_id_infos = vec![
            create_test_pay_id_info(1, 1000, channel),
            create_test_pay_id_info(2, 2000, channel),
        ];

        // 正常支付场景
        let valid_payments = vec![
            create_test_payment(1, 1, receiver, 500),
            create_test_payment(1, 2, receiver, 400),
            create_test_payment(2, 1, receiver, 1000),
        ];

        let sorter = ReceiptsOverpayChecker::new(channel, pay_id_infos.clone(), valid_payments);
        assert!(sorter.validate_overpayment().is_ok());

        // 超付场景
        let overpaid_payments = vec![
            create_test_payment(1, 1, receiver, 600),
            create_test_payment(1, 2, receiver, 500), // 总额超过1000
            create_test_payment(2, 1, receiver, 1000),
        ];

        let sorter = ReceiptsOverpayChecker::new(channel, pay_id_infos, overpaid_payments);
        assert!(sorter.validate_overpayment().is_err());

        Ok(())
    }
}

// /**
//  * // 创建并处理
//     let sorter = ReceiptsSorter::new(channel, pay_id_infos, settled_payments);
//     let result = sorter.process()?;

//     // 获取结果
//     println!("Payments root: {:?}", result.payments_root);
//     println!("PayIds root: {:?}", result.pay_ids_root);

//     // 处理每个receiver的证明
//     for proof in result.receiver_proofs {
//         println!("Receiver: {:?}", proof.receiver);
//         // 使用proof进行验证...
//     }
//  */