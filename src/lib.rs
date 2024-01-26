use bigdecimal::ToPrimitive;
use starknet::{accounts::Call, core::types::FieldElement};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodeCalldataError {
    #[error("field '{0}' at index {1} was not found in calldata")]
    FieldNotFound(String, usize),
    #[error("failed to convert field '{0}' to u64 at index {1}")]
    Conversion(String, usize),
    #[error("actual calldata length {0} does not match the expected length of {1}")]
    UnexpectedLength(u64, u64),
}

struct CallBuilder {
    to: FieldElement,
    selector: FieldElement,
    data_offset: u64,
    data_len: u64,
}

pub fn decode_calldata(calls: &[FieldElement]) -> Result<Vec<Call>, DecodeCalldataError> {
    decode_new_execution_calldata(calls).or_else(|_| decode_legacy_execution_calldata(calls))
}

fn decode_legacy_execution_calldata(
    calldata: &[FieldElement],
) -> Result<Vec<Call>, DecodeCalldataError> {
    let mut calls = vec![];

    let calls_length = calldata
        .first()
        .ok_or(DecodeCalldataError::FieldNotFound(
            String::from("calls_length"),
            0,
        ))?
        .to_big_decimal(0);

    let calls_length = calls_length
        .to_u64()
        .ok_or(DecodeCalldataError::Conversion(
            String::from("calls_length"),
            0,
        ))?;

    let mut offset = 1;
    let mut call_builders: Vec<CallBuilder> = vec![];
    for _ in 0..calls_length {
        let to = *calldata
            .get(offset)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("to"),
                offset,
            ))?;

        let selector = *calldata
            .get(offset + 1)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("selector"),
                offset + 1,
            ))?;

        let data_offset = calldata
            .get(offset + 2)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("data_offset"),
                offset + 2,
            ))?;
        let data_offset = data_offset.to_big_decimal(0);
        let data_offset = data_offset.to_u64().ok_or(DecodeCalldataError::Conversion(
            String::from("data_offset"),
            offset + 2,
        ))?;

        let data_len = calldata
            .get(offset + 3)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("data_len"),
                offset + 3,
            ))?;
        let data_len = data_len.to_big_decimal(0);
        let data_len = data_len.to_u64().ok_or(DecodeCalldataError::Conversion(
            String::from("data_len"),
            offset + 3,
        ))?;

        call_builders.push(CallBuilder::new(to, selector, data_offset, data_len));

        offset += 4;
    }

    let calldata_len = calldata
        .get(offset)
        .ok_or(DecodeCalldataError::FieldNotFound(
            String::from("calldata_len"),
            offset,
        ))?;
    let calldata_len = calldata_len.to_big_decimal(0);
    let calldata_len = calldata_len
        .to_u64()
        .ok_or(DecodeCalldataError::Conversion(
            String::from("calldata_len"),
            0,
        ))?;

    let expected_calldata_len = call_builders
        .iter()
        .fold(0, |acc, call_builder| acc + call_builder.data_len);
    if calldata_len != expected_calldata_len {
        return Err(DecodeCalldataError::UnexpectedLength(
            calldata_len,
            expected_calldata_len,
        ));
    }

    offset += 1;

    for call_builder in call_builders.into_iter() {
        let calldata = calldata
            .get(
                offset + call_builder.data_offset as usize
                    ..offset + call_builder.data_offset as usize + call_builder.data_len as usize,
            )
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("calldata"),
                offset + call_builder.data_offset as usize,
            ))?
            .to_vec();

        calls.push(call_builder.build(calldata));
    }

    Ok(calls)
}

fn decode_new_execution_calldata(
    calldata: &[FieldElement],
) -> Result<Vec<Call>, DecodeCalldataError> {
    let mut calls = vec![];

    let calls_length = calldata
        .first()
        .ok_or(DecodeCalldataError::FieldNotFound(
            String::from("calls_length"),
            0,
        ))?
        .to_big_decimal(0);
    let calls_length = calls_length
        .to_u64()
        .ok_or(DecodeCalldataError::Conversion(
            String::from("calls_length"),
            0,
        ))?;

    let mut offset = 1;
    for _ in 0..calls_length {
        let to = *calldata
            .get(offset)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("to"),
                offset,
            ))?;

        let selector = *calldata
            .get(offset + 1)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("selector"),
                offset + 1,
            ))?;

        let calldata_len = calldata
            .get(offset + 2)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("calldata_len"),
                offset + 2,
            ))?;
        let calldata_len = calldata_len.to_big_decimal(0);
        let calldata_len = calldata_len
            .to_u64()
            .ok_or(DecodeCalldataError::Conversion(
                String::from("calldata_len"),
                offset + 2,
            ))?;

        let calldata = calldata
            .get(offset + 3..offset + 3 + calldata_len as usize)
            .ok_or(DecodeCalldataError::FieldNotFound(
                String::from("calldata"),
                offset + 3,
            ))?
            .to_vec();

        offset += 3 + calldata_len as usize;

        calls.push(Call {
            to,
            selector,
            calldata,
        });
    }

    Ok(calls)
}

impl CallBuilder {
    fn new(to: FieldElement, selector: FieldElement, data_offset: u64, data_len: u64) -> Self {
        CallBuilder {
            to,
            selector,
            data_offset,
            data_len,
        }
    }

    fn build(&self, calldata: Vec<FieldElement>) -> Call {
        Call {
            to: self.to,
            selector: self.selector,
            calldata,
        }
    }
}

#[cfg(test)]
mod tests {
    use starknet::macros::felt;

    use super::*;

    #[test]
    fn test_decode_new_approve_repay_calldata() {
        let calldata = vec![
            // calls len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // to
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // selector (approve)
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // d0
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // d1
            felt!("0x000000000000000000000000000000000000000000000000000c35f7d2acc9ec"),
            // d2
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (repay)
            felt!("0x00ad257770e86a03742ebe0a615fb19503d9c891d118daa82163867444c08680"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // token (d0)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // amount (d1)
            felt!("0x000000000000000000000000000000000000000000000000000c35f7d2acc9ec"),
        ];

        let calls = decode_new_execution_calldata(&calldata).unwrap();
        assert_eq!(calls.len(), 2);

        assert_eq!(
            calls[0].to,
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c")
        );

        assert_eq!(calls[0].calldata.len(), 3);

        assert_eq!(
            calls[1].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[1].selector,
            felt!("0x00ad257770e86a03742ebe0a615fb19503d9c891d118daa82163867444c08680")
        );
        assert_eq!(calls[1].calldata.len(), 2);
    }

    #[test]
    fn test_decode_new_withdraw_all_calldata() {
        let calldata = vec![
            // calls len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (withdraw_all)
            felt!("0x0275dc81fcd5c700205ff6dc320e9d54ed3f0ace21177d591d6d5d259ee1d7c2"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // token (d0)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        ];

        let calls = decode_new_execution_calldata(&calldata).unwrap();

        assert_eq!(calls.len(), 1);

        assert_eq!(
            calls[0].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0275dc81fcd5c700205ff6dc320e9d54ed3f0ace21177d591d6d5d259ee1d7c2")
        );
    }

    #[test]
    fn test_decode_new_approve_deposit_enable_collateral_calldata() {
        let calldata = vec![
            // calls len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // to
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // selector (approve)
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // d0
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // d1
            felt!("0x00000000000000000000000000000000000000000000000000c60349dcfe6c7d"),
            // d2
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (deposit)
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // token (d0)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // amount (d1)
            felt!("0x00000000000000000000000000000000000000000000000000c60349dcfe6c7d"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (enable_collateral)
            felt!("0x0271680756697a04d1447ad4c21d53bdf15966bdc5b78bd52d4fc2153aa76bda"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // token (d0)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        ];

        let calls = decode_new_execution_calldata(&calldata).unwrap();

        assert_eq!(calls.len(), 3);

        assert_eq!(
            calls[0].to,
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c")
        );
        assert_eq!(calls[0].calldata.len(), 3);

        assert_eq!(
            calls[1].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[1].selector,
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01")
        );
        assert_eq!(calls[1].calldata.len(), 2);

        assert_eq!(
            calls[2].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[2].selector,
            felt!("0x0271680756697a04d1447ad4c21d53bdf15966bdc5b78bd52d4fc2153aa76bda")
        );
        assert_eq!(calls[2].calldata.len(), 1);
    }

    #[test]
    fn test_decode_new_approve_deposit_calldata() {
        let calldata = vec![
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // to
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // selector (approve)
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"),
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            felt!("0x000000000000000000000000000000000000000000000000255c9da2d84e8000"),
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (deposit)
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"),
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            felt!("0x000000000000000000000000000000000000000000000000255c9da2d84e8000"),
        ];

        let calls = decode_new_execution_calldata(&calldata).unwrap();

        assert_eq!(calls.len(), 2);

        assert_eq!(
            calls[0].to,
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c")
        );
        assert_eq!(calls[0].calldata.len(), 3);

        assert_eq!(
            calls[1].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[1].selector,
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01")
        );
        assert_eq!(calls[1].calldata.len(), 2);
    }

    #[test]
    fn test_decode_legacy_withdraw_all_calldata() {
        let calldata = vec![
            // calls len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (withdraw_all)
            felt!("0x0275dc81fcd5c700205ff6dc320e9d54ed3f0ace21177d591d6d5d259ee1d7c2"),
            // data_offset
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // data_len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // calldata array starts

            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // d0 (token)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        ];

        let calls = decode_legacy_execution_calldata(&calldata).unwrap();

        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0275dc81fcd5c700205ff6dc320e9d54ed3f0ace21177d591d6d5d259ee1d7c2")
        );
        assert_eq!(calls[0].calldata.len(), 1);
        assert_eq!(
            calls[0].calldata[0],
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        )
    }

    #[test]
    fn test_decode_legacy_withdraw_calldata() {
        let calldata = vec![
            // calls len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // call array starts

            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector (withdraw)
            felt!("0x015511cc3694f64379908437d6d64458dc76d02482052bfb8a5b33a72c054c77"),
            // data_offset
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // data_len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // calldata array starts

            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // d0 (token)
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
            // d1 (amount)
            felt!("0x000000000000000000000000000000000000000000000000057664a5e4444d40"),
        ];

        let calls = decode_legacy_execution_calldata(&calldata).unwrap();

        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x015511cc3694f64379908437d6d64458dc76d02482052bfb8a5b33a72c054c77")
        );
        assert_eq!(calls[0].calldata.len(), 2);
        assert_eq!(
            calls[0].calldata[0],
            felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        );
        assert_eq!(
            calls[0].calldata[1],
            felt!("0x000000000000000000000000000000000000000000000000057664a5e4444d40")
        );
    }

    #[test]
    fn test_decode_legacy_approve_deposit_enable_collateral() {
        let calldata = vec![
            // call array len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // call array starts

            // to
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8"),
            // selector (approve)
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c"),
            // data_offset
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // data_len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"),
            // data_offset
            felt!("0x0000000000000000000000000000000000000000000000000000000000000003"),
            // data_len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000002"),
            // to
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // selector
            felt!("0x0271680756697a04d1447ad4c21d53bdf15966bdc5b78bd52d4fc2153aa76bda"),
            // data_offset
            felt!("0x0000000000000000000000000000000000000000000000000000000000000005"),
            // data_len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            // calldata len
            felt!("0x0000000000000000000000000000000000000000000000000000000000000006"),
            // calldata array starts

            // approve d0 (spender)
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05"),
            // approve d1 (amount)
            felt!("0x000000000000000000000000000000000000000000000000000000000020bde4"),
            // approve d2
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            // deposit d0 (token)
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8"),
            // deposit d1 (amount)
            felt!("0x000000000000000000000000000000000000000000000000000000000020bde4"),
            // enable_collateral d0 (token)
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8"),
        ];

        let calls = decode_legacy_execution_calldata(&calldata).unwrap();
        assert_eq!(calls.len(), 3);

        assert_eq!(
            calls[0].to,
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8")
        );
        assert_eq!(
            calls[0].selector,
            felt!("0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c")
        );
        assert_eq!(calls[0].calldata.len(), 3);
        assert_eq!(
            calls[0].calldata[0],
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[0].calldata[1],
            felt!("0x000000000000000000000000000000000000000000000000000000000020bde4")
        );
        assert_eq!(
            calls[0].calldata[2], // approve d2
            felt!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );

        assert_eq!(
            calls[1].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[1].selector,
            felt!("0x00c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01")
        );
        assert_eq!(calls[1].calldata.len(), 2);
        assert_eq!(
            calls[1].calldata[0],
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8")
        );
        assert_eq!(
            calls[1].calldata[1],
            felt!("0x000000000000000000000000000000000000000000000000000000000020bde4")
        );

        assert_eq!(
            calls[2].to,
            felt!("0x04c0a5193d58f74fbace4b74dcf65481e734ed1714121bdc571da345540efa05")
        );
        assert_eq!(
            calls[2].selector,
            felt!("0x0271680756697a04d1447ad4c21d53bdf15966bdc5b78bd52d4fc2153aa76bda")
        );
        assert_eq!(calls[2].calldata.len(), 1);
        assert_eq!(
            calls[2].calldata[0],
            felt!("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8")
        );
    }
}
