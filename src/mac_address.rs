#![allow(clippy::result_large_err)]
use pest::{iterators::Pairs, Parser};
use pest_derive::Parser;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self> {
        // Should be safe to unwrap since we should have at least one match
        let parsed = MacAddressParse::parse(Rule::mac, s)?
            .next()
            .expect("at least one mac should match");
        from_mac(parsed.into_inner())
    }
}

#[derive(Parser)]
#[grammar = "mac_address.pest"]
struct MacAddressParse;

pub type Result<T> = std::result::Result<T, ParseError>;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Parsing failed:\n{0}")]
    Parsing(#[from] pest::error::Error<Rule>),
    #[error("Hex decoding failed: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

fn from_mac(mut mac: Pairs<'_, Rule>) -> Result<MacAddress> {
    let mut bytes = [0; 6];
    // Should be safe to unwrap because exactly one type of mac address will be matched according to the grammar
    let parts = mac
        .next()
        .expect("exactly one type of mac should have matched")
        .into_inner()
        .map(|octet| decode_octet(octet.as_str()))
        .try_collect::<Vec<_>>()?;
    bytes[0..6].copy_from_slice(&parts[0..6]);
    Ok(MacAddress(bytes))
}

fn decode_octet(octet: &str) -> Result<u8> {
    let mut res = [0; 1];
    hex::decode_to_slice(octet, &mut res)?;
    Ok(res[0])
}
