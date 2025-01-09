use alloy_primitives::{Address, B256, U256,keccak256};

use crate::{BoxError, EthAddress, OverpayCheckResult, ProfitResult, ProxySettlementResult};


pub struct ProxySettlementAggregator;

impl ProxySettlementAggregator {
    pub fn new() -> Self {
        Self
    }

    pub fn aggregate(
        &self,
        profit_results: Vec<ProfitResult>,
        overpay_result: OverpayCheckResult,
    ) -> Result<ProxySettlementResult, BoxError> {
        // 1. 预验证
        self.pre_validate(&profit_results, &overpay_result)?;

        // 2. 计算聚合结果
        self.calculate_aggregate_result(profit_results)
    }

    fn pre_validate(
        &self,
        profit_results: &[ProfitResult],
        overpay_result: &OverpayCheckResult,
    ) -> Result<(), BoxError> {
        if profit_results.is_empty() {
            return Err("Empty profit results".into());
        }

        let first_result = &profit_results[0];
        let proxy = first_result.proxy;
        let pay_ids_root = first_result.pay_ids_root;
        let receipts_root = first_result.receipts_root;

        // 验证所有结果的一致性
        for profit_result in profit_results {
            if profit_result.proxy != proxy {
                return Err("Inconsistent proxy address".into());
            }
            if profit_result.pay_ids_root != pay_ids_root {
                return Err("Inconsistent pay_ids_root".into());
            }
            if profit_result.receipts_root != receipts_root {
                return Err("Inconsistent receipts_root".into());
            }
        }

        if overpay_result.pay_ids_root != pay_ids_root {
            return Err("Overpay check pay_ids_root mismatch".into());
        }

        Ok(())
    }

    fn calculate_aggregate_result(
        &self,
        profit_results: Vec<ProfitResult>,
    ) -> Result<ProxySettlementResult, BoxError> {
        let first_result = &profit_results[0].clone();
        let proxy = first_result.proxy;
        let pay_ids_root = first_result.pay_ids_root;
        let serv_ids_root = first_result.serv_ids_root;

        // 累计所有利润
        let mut system_profits = U256::ZERO;
        let mut proxy_profits = U256::ZERO;
        let mut receiver_profits = U256::ZERO;

        for profit_result in profit_results {
            system_profits += profit_result.system_profit;
            proxy_profits += profit_result.proxy_profit;
            receiver_profits += profit_result.receiver_profit;
        }

        // 计算总金额
        let amount = system_profits + proxy_profits + receiver_profits;

        let mut profit_result = ProxySettlementResult {
            vks_hash: B256::ZERO,
            settlement_id:B256::ZERO,
            proxy,
            pay_ids_root,
            serv_ids_root,
            system_profits,
            proxy_profits,
            amount,
        };
        profit_result.build_settlement_id();



        Ok(profit_result)
    }

   
}

/********   doc
 * 创建一个聚合中验证器，其输入是多个settle_one_receiver的证据和一个overpay_check的证据。其过程是



    3. 然后进行下面的操作
     累计所有的ProfitResult system_profit，proxy_profit,receiver_profit到相应的system_profits，proxy_profits,receiver_profits

    4. 输出结果
        settlement_id: keccak256(proxy||receipts_root||pay_ids_root||serv_ids_root||system_profits||proxy_profits||receiver_profits)
        proxy
        pay_ids_root
        serv_ids_root
        system_profits
        proxy_profits
        amount:system_profits + proxy_profits + receiver_profits

 */
