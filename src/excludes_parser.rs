#![allow(clippy::result_large_err)]
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::{
    net::{AddrParseError, Ipv4Addr},
    num::ParseIntError,
};
use thiserror::Error;

use crate::excludes::ExcludedIps;

#[derive(Parser)]
#[grammar = "excludes.pest"]
struct ExcludesParser;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse:\n{0}")]
    Parsing(#[from] pest::error::Error<Rule>),
    #[error("CIDR mask is greater than 32: {0}")]
    CidrMaskTooLarge(u8),
    #[error("Not an IP address: {0}")]
    NotIp(#[from] AddrParseError),
    #[error("Not a number: {0}")]
    Nan(#[from] ParseIntError),
    #[error("Invalid line: {0}")]
    InvalidLine(String),
    #[error("Parser failed for unknown reason")]
    UnknownFailure,
}

pub fn parse_excludes(excludes: &str) -> Result<Vec<ExcludedIps>> {
    // We can unwrap because at least one file has to match
    ExcludesParser::parse(Rule::file, excludes)?
        .next()
        .expect("there should be a valid file!")
        .into_inner()
        .filter(|pair| pair.as_rule() != Rule::EOI)
        .map(|pair| match pair.as_rule() {
            Rule::cidr => parse_cidr(pair),
            Rule::range => parse_range(pair),
            Rule::address => parse_address(pair),
            _ => Err(Error::InvalidLine(pair.as_str().to_owned())),
        })
        .try_collect()
}

fn parse_cidr(cidr: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut cidr_iter = cidr.into_inner();
    let ip = cidr_iter
        .next()
        .ok_or(Error::UnknownFailure)?
        .as_str()
        .parse::<Ipv4Addr>()?;
    let mask = cidr_iter
        .next()
        .ok_or(Error::UnknownFailure)?
        .as_str()
        .parse::<u8>()?;

    // Subnet mask is max 32
    if mask > 32 {
        Err(Error::CidrMaskTooLarge(mask))
    } else {
        Ok(ExcludedIps::Cidr(ip, mask))
    }
}

fn parse_range(range: Pair<'_, Rule>) -> Result<ExcludedIps> {
    let mut range_iter = range.into_inner();
    let ip1 = range_iter
        .next()
        .ok_or(Error::UnknownFailure)?
        .as_str()
        .parse::<Ipv4Addr>()?;
    let ip2 = range_iter
        .next()
        .ok_or(Error::UnknownFailure)?
        .as_str()
        .parse::<Ipv4Addr>()?;

    Ok(ExcludedIps::Range(ip1, ip2))
}

fn parse_address(address: Pair<'_, Rule>) -> Result<ExcludedIps> {
    Ok(ExcludedIps::Address(address.as_str().parse::<Ipv4Addr>()?))
}
