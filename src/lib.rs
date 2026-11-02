#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod client;
pub mod error;
pub mod iso;
pub mod proto;
pub mod types;

pub use client::{S7Client, CT_OP, CT_PG, CT_S7};
pub use error::{cpu_error_text, error_text, ErrorKind, S7Error};
pub use proto::{
    MAX_VARS, S7_AREA_CT, S7_AREA_DB, S7_AREA_MK, S7_AREA_PA, S7_AREA_PE, S7_AREA_TM, S7_WL_BIT,
    S7_WL_BYTE, S7_WL_CHAR, S7_WL_COUNTER, S7_WL_DINT, S7_WL_DWORD, S7_WL_INT, S7_WL_REAL,
    S7_WL_TIMER, S7_WL_WORD,
};
pub use types::{
    CpuStatus, S7BlockEntry, S7BlockInfo, S7BlocksList, S7CpInfo, S7CpuInfo, S7DataItem,
    S7DateTime, S7OrderCode, S7Protection, S7Szl, BLOCK_DB, BLOCK_FB, BLOCK_FC, BLOCK_OB,
    BLOCK_SDB, BLOCK_SFB, BLOCK_SFC,
};
