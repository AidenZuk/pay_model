use alloy_primitives::B256;
use tiny_keccak::{Keccak,Hasher};
use std::collections::HashMap;
use crate::models::segment_vc::MerkleProof;
use crate::{eth_address_to_B256, BoxError};
use crate::{
    EthAddress,
    models::segment_vc::SegmentVC,
};
use super::{PaymentSettledByProxy, ReceiverProof};

pub struct PaymentsGrouper;

impl PaymentsGrouper {
    /// 按receiver分类处理支付记录，创建SegmentVC并返回根哈希和每个receiver的证明
    pub fn group_by_receiver(
        payments: &[PaymentSettledByProxy]
    ) -> Result<(B256, Vec<ReceiverProof>), BoxError> {
        // 1. 按receiver分组
        let mut receiver_groups: HashMap<EthAddress, Vec<PaymentSettledByProxy>> = HashMap::new();
        for payment in payments {
            receiver_groups
                .entry(payment.receiver)
                .or_default()
                .push(payment.clone());
        }

        // 2. 为每个receiver创建Vec<PaymentSettledByProxy>
        let mut all_entries = Vec::new();
        let mut receiver_proofs = Vec::new();

        // 按receiver地址排序，确保确定性
        let mut receivers: Vec<EthAddress> = receiver_groups.keys().cloned().collect();
        receivers.sort();

        for receiver in &receivers {
            let payments = &receiver_groups[receiver];
            
            // 为每个payment创建key-value对
            let mut entries: Vec<(B256, B256)> = payments
                .iter()
                .map(|payment| {
                    let key = payment.to_key();
                    let value = payment_to_hash(payment);
                    (key, value)
                })
                .collect();
            
            // 排序确保确定性
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            
            //创建Vec<PaymentSettledByProxy>的哈希
            let mut hasher = Keccak::v256();
            for (key,hash_of_payment) in &entries {
                hasher.update(&hash_of_payment.as_slice());
               
            }
            let mut output = [0u8;32];
            hasher.finalize(&mut output[..]);
            

            
            // 添加到总的entries中
            all_entries.push((eth_address_to_B256(receiver), B256::from_slice(&output)));
        }

        // 3. 创建总的SegmentVC
        let mut vc = SegmentVC::new(all_entries.len());
        let root = vc.insert_batch(all_entries)?;

        // 4. 为每个receiver创建证明
        for receiver in receivers {
            let receiver_hash = eth_address_to_B256(&receiver);
            let proof = vc.generate_proof(receiver_hash)?;
            receiver_proofs.push(ReceiverProof {
                receiver,
                proof,
            });
        }

        Ok((root, receiver_proofs.clone()))
    }
}



// 辅助函数：将payment转换为hash值
#[inline]
fn payment_to_hash(payment: &PaymentSettledByProxy) -> B256 {
    // 计算整个payment对象的哈希
    payment.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};

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
    fn test_payment_processing() -> Result<(), BoxError> {
        let receiver1 = [1u8;20];
        let receiver2 = [2u8;20];

        let payments = vec![
            create_test_payment(1, 1, receiver1, 100),
            create_test_payment(1, 2, receiver1, 200),
            create_test_payment(2, 1, receiver2, 300),
            create_test_payment(2, 2, receiver2, 400),
        ];

        let (root, proofs) = PaymentsGrouper::group_by_receiver(&payments)?;
        
        // 验证生成了正确数量的证明
        assert_eq!(proofs.len(), 2);
        
        // 验证每个receiver都有对应的证明
        let proof_receivers: Vec<EthAddress> = proofs.iter().map(|p| p.receiver).collect();
        assert!(proof_receivers.contains(&receiver1));
        assert!(proof_receivers.contains(&receiver2));

        Ok(())
    }

    #[test]
    fn test_deterministic_root() -> Result<(), BoxError> {
        let receiver1 = [1u8;20];
        let receiver2 = [2u8;20];


        // 创建两组顺序不同但内容相同的支付记录
        let payments1 = vec![
            create_test_payment(1, 1, receiver1, 100),
            create_test_payment(2, 1, receiver2, 300),
            create_test_payment(1, 2, receiver1, 200),
            create_test_payment(2, 2, receiver2, 400),
        ];

        let payments2 = vec![
            create_test_payment(2, 1, receiver2, 300),
            create_test_payment(1, 2, receiver1, 200),
            create_test_payment(2, 2, receiver2, 400),
            create_test_payment(1, 1, receiver1, 100),
        ];

        let (root1, _) = PaymentsGrouper::group_by_receiver(&payments1)?;
        let (root2, _) = PaymentsGrouper::group_by_receiver(&payments2)?;

        // 验证生成相同的根哈希
        assert_eq!(root1, root2);

        Ok(())
    }
}