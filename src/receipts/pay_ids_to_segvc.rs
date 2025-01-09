use alloy_primitives::{B256, U256};
use crate::BoxError;
use crate::models::{PayIdInfo, segment_vc::SegmentVC};

pub struct PayIdsProcessor;

impl PayIdsProcessor {
    /// 将PayIdInfo数组转换为SegmentVC并返回根哈希
    /// PayIdInfo按id从小到大排序，以id为key，PayIdInfo的哈希为值创建SegmentVC
    pub fn create_segment_vc(pay_ids: &[PayIdInfo]) -> Result<(SegmentVC, B256), BoxError> {
        // 1. 克隆并排序PayIdInfo数组
        let mut sorted_pay_ids = pay_ids.to_vec();
        sorted_pay_ids.sort_by(|a, b| a.id.cmp(&b.id));

        // 2. 准备批量插入数据
        let entries: Vec<(B256, B256)> = sorted_pay_ids
            .iter()
            .map(|pay_id| (pay_id.id.into(), pay_id.hash()))
            .collect();

        // 3. 创建SegmentVC并批量插入
        let mut vc = SegmentVC::new(entries.len());
        let root = vc.insert_batch(entries)?;

        Ok((vc, root))
    }

    /// 只获取根哈希
    pub fn get_root_hash(pay_ids: &[PayIdInfo]) -> Result<B256, BoxError> {
        let (_, root) = Self::create_segment_vc(pay_ids)?;
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use crate::models::EthAddress;

    fn create_test_pay_id(id: i64, amount: u64) -> PayIdInfo {
        PayIdInfo {
            id: U256::from(id),
            amount: U256::from(amount),
            sender: [1u8;20],
            proxy: [2u8;20],
            state: 1,
            created_at: 1000,
            closing_time: 2000,
        }
    }

    #[test]
    fn test_pay_ids_processing() -> Result<(), BoxError> {
        // 创建测试数据（乱序）
        let pay_ids = vec![
            create_test_pay_id(3, 300),
            create_test_pay_id(1, 100),
            create_test_pay_id(2, 200),
        ];

        // 创建SegmentVC
        let (vc, root1) = PayIdsProcessor::create_segment_vc(&pay_ids)?;

        // 验证所有PayId都能在VC中找到
        for pay_id in &pay_ids {
            let h_pay_id = B256::from(pay_id.id.to_be_bytes());
            let value = vc.get_value(h_pay_id)?;
            assert_eq!(value, pay_id.hash());
        }

        // 验证只获取根哈希的方法
        let root2 = PayIdsProcessor::get_root_hash(&pay_ids)?;
        assert_eq!(root1, root2);

        Ok(())
    }

    #[test]
    fn test_pay_ids_order() -> Result<(), BoxError> {
        // 创建两组顺序不同但内容相同的数据
        let pay_ids1 = vec![
            create_test_pay_id(2, 200),
            create_test_pay_id(1, 100),
            create_test_pay_id(3, 300),
        ];

        let pay_ids2 = vec![
            create_test_pay_id(1, 100),
            create_test_pay_id(3, 300),
            create_test_pay_id(2, 200),
        ];

        // 验证生成相同的根哈希
        let root1 = PayIdsProcessor::get_root_hash(&pay_ids1)?;
        let root2 = PayIdsProcessor::get_root_hash(&pay_ids2)?;
        assert_eq!(root1, root2);

        Ok(())
    }
}