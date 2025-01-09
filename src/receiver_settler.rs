/***
 * 
 * 创建实现一个ReceiverSettler结构体，用于接收和处理数据
 * 数据的输入
 * 来自于多个Proxy的
 * 1. Vec<PaymentSettledByProxy>
 * 2. ProfitResult
 * 
 * 
 * 处理过程如下：
 * 1. 验证Vec<PaymentSettledByProxy>的哈希根与ProfitResult.receipts_root 一致
 * 2. 累计所有的ProfitResult中的receiver_profit得到结果
 * 
 * 返回累计的结果
 */

 use alloy_primitives::{Address, B256, U256};
use crate::{
    keccak256, keccak256_more, BoxError, PaymentSettledByProxy, ProfitResult
};

/// 接收者结算器
pub struct ReceiverSettler {
    receiver: Address,
    total_profit: U256,
}

impl ReceiverSettler {
    /// 创建新的接收者结算器
    pub fn new(receiver: Address) -> Self {
        Self {
            receiver,
            total_profit: U256::ZERO,
        }
    }

    /// 处理来自一个代理的结算数据
    pub fn process_proxy_settlement(
        &mut self,
        payments: &[PaymentSettledByProxy],
        profit_result: &ProfitResult,
    ) -> Result<(), BoxError> {
        // 1. 验证支付列表的哈希根与 ProfitResult 中的 receipts_root 一致
        let calculated_root = self.calculate_payments_root(payments);
        if calculated_root != profit_result.receipts_root {
            return Err("Payments root mismatch".into());
        }

        // 2. 验证接收者地址匹配
        if self.receiver != Address::from_slice(&profit_result.receiver) {
            return Err("Receiver mismatch".into());
        }

        // 3. 累加接收者利润
        self.total_profit = self.total_profit
            .checked_add(profit_result.receiver_profit)
            .ok_or("Profit overflow")?;

        Ok(())
    }

    /// 计算支付列表的哈希根
    fn calculate_payments_root(&self, payments: &[PaymentSettledByProxy]) -> B256 {
        let mut current_hash = B256::ZERO;
        
        for payment in payments {
            // 序列化支付数据
            let mut data = Vec::new();
            data.extend_from_slice(&payment.pay_id.to_be_bytes::<32>());
            data.extend_from_slice(&payment.serv_id.to_be_bytes());
            data.extend_from_slice(&payment.amount.to_be_bytes::<32>());
            data.extend_from_slice(&payment.receiver);
            data.extend_from_slice(&payment.sig_sender);
            data.extend_from_slice(&[payment.settled as u8]);
            data.extend_from_slice(&payment.sig_proxy);

            // 计算当前支付的哈希，并更新累积哈希
            current_hash = B256::from_slice(
                &keccak256_more(&current_hash, &keccak256(&data))
            );
        }

        current_hash
    }

    /// 获取累计的总利润
    pub fn total_profit(&self) -> U256 {
        self.total_profit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_settler() {
        // 创建测试数据
        let receiver = Address::new([1u8;20]);
        let mut settler = ReceiverSettler::new(receiver);

        // 创建测试支付列表
        let payments = vec![
            PaymentSettledByProxy {
                pay_id: U256::from(1u32),
                serv_id: 0xFFFFFFF,
                amount: U256::from(100u32),
                receiver: receiver.into(),
                sig_sender: [0u8; 65],
                settled: true,
                sig_proxy: [0u8; 65],
            }
        ];

        // 计算支付列表的哈希根
        let receipts_root = settler.calculate_payments_root(&payments);

        // 创建利润结果
        let profit_result = ProfitResult {
            receiver: receiver.into(),
            proxy: [0u8; 20],
            receipts_root,
            pay_ids_root: B256::ZERO,
            serv_ids_root: B256::ZERO,
            system_profit: U256::from(10u32),
            proxy_profit: U256::from(20u32),
            receiver_profit: U256::from(70u32),
        };

        // 处理结算
        settler.process_proxy_settlement(&payments, &profit_result)
            .expect("Processing should succeed");

        // 验证总利润
        assert_eq!(settler.total_profit(), U256::from(70u32));

        // 测试错误情况：错误的 receipts_root
        let invalid_profit_result = ProfitResult {
            receipts_root: B256::ZERO,
            ..profit_result
        };
        assert!(settler.process_proxy_settlement(&payments, &invalid_profit_result).is_err());

        // 测试错误情况：错误的接收者
        let invalid_profit_result = ProfitResult {
            receiver: Address::new([3u8;20]).into(),
            ..profit_result
        };
        assert!(settler.process_proxy_settlement(&payments, &invalid_profit_result).is_err());
    }
}