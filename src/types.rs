// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! The values the client's functions take and return — the Rust
//! counterparts of Snap7's `TS7DataItem`, `TS7BlocksList`,
//! `TS7BlockInfo`, `TS7SZL`, `TS7OrderCode`, `TS7CpuInfo`, `TS7CpInfo`,
//! `TS7Protection`, and the PLC date and time.

use crate::error::{ErrorKind, S7Error};
use crate::proto::{word_size, S7_AREA_CT, S7_AREA_TM, S7_WL_BIT, S7_WL_COUNTER, S7_WL_TIMER};

/// Organization block.
pub const BLOCK_OB: u8 = 0x38;
/// Data block.
pub const BLOCK_DB: u8 = 0x41;
/// System data block.
pub const BLOCK_SDB: u8 = 0x42;
/// Function.
pub const BLOCK_FC: u8 = 0x43;
/// System function.
pub const BLOCK_SFC: u8 = 0x44;
/// Function block.
pub const BLOCK_FB: u8 = 0x45;
/// System function block.
pub const BLOCK_SFB: u8 = 0x46;

/// The block types, in the order Snap7 lists them.
pub const BLOCK_TYPES: [u8; 7] = [
    BLOCK_OB, BLOCK_FB, BLOCK_FC, BLOCK_DB, BLOCK_SDB, BLOCK_SFC, BLOCK_SFB,
];

/// Sub block types, as a block's header carries them.
pub mod sub_block {
    /// OB.
    pub const OB: u8 = 0x08;
    /// DB.
    pub const DB: u8 = 0x0A;
    /// SDB.
    pub const SDB: u8 = 0x0B;
    /// FC.
    pub const FC: u8 = 0x0C;
    /// SFC.
    pub const SFC: u8 = 0x0D;
    /// FB.
    pub const FB: u8 = 0x0E;
    /// SFB.
    pub const SFB: u8 = 0x0F;
}

/// Block languages.
pub mod language {
    /// STL (AWL).
    pub const AWL: u8 = 0x01;
    /// LAD (KOP).
    pub const KOP: u8 = 0x02;
    /// FBD (FUP).
    pub const FUP: u8 = 0x03;
    /// SCL.
    pub const SCL: u8 = 0x04;
    /// Data block.
    pub const DB: u8 = 0x05;
    /// GRAPH.
    pub const GRAPH: u8 = 0x06;
}

/// The block type a header's sub block type stands for.
pub fn block_type_of_sub_block(sub: u8) -> Option<u8> {
    Some(match sub {
        sub_block::OB => BLOCK_OB,
        sub_block::DB => BLOCK_DB,
        sub_block::SDB => BLOCK_SDB,
        sub_block::FC => BLOCK_FC,
        sub_block::SFC => BLOCK_SFC,
        sub_block::FB => BLOCK_FB,
        sub_block::SFB => BLOCK_SFB,
        _ => return None,
    })
}

/// Whether `block_type` is one of the `BLOCK_*` codes.
pub fn is_block_type(block_type: u8) -> bool {
    BLOCK_TYPES.contains(&block_type)
}

/// One item of a multi-variable read or write (Snap7's `TS7DataItem`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S7DataItem {
    /// The area (`S7_AREA_*`).
    pub area: u8,
    /// The word length (`S7_WL_*`). Counter and timer areas always use
    /// [`S7_WL_COUNTER`] / [`S7_WL_TIMER`].
    pub word_len: u8,
    /// The DB number (ignored outside the DB area).
    pub db_number: u16,
    /// The start: a bit number (`byte * 8 + bit`) for bit access, an
    /// element number for counters and timers, a byte offset otherwise.
    pub start: u32,
    /// How many elements of `word_len` (1 for bit access).
    pub amount: u16,
    /// The data: filled by a read, sent by a write.
    pub data: Vec<u8>,
    /// The item's outcome. A read or write leaves `Ok(())` where the PLC
    /// carried the item out, and the PLC's refusal otherwise (see
    /// [`S7Error::cpu_code`]).
    pub result: Result<(), S7Error>,
}

impl S7DataItem {
    /// An item to read `amount` elements.
    pub fn read(area: u8, db_number: u16, start: u32, amount: u16, word_len: u8) -> Self {
        Self {
            area,
            word_len,
            db_number,
            start,
            amount,
            data: Vec::new(),
            result: Ok(()),
        }
    }

    /// An item writing `data` (whose length sets the amount).
    pub fn write(area: u8, db_number: u16, start: u32, word_len: u8, data: Vec<u8>) -> Self {
        let size = word_size(word_len).unwrap_or(1);
        let amount = if word_len == S7_WL_BIT {
            1
        } else {
            (data.len() / size) as u16
        };
        Self {
            area,
            word_len,
            db_number,
            start,
            amount,
            data,
            result: Ok(()),
        }
    }

    /// The word length the wire uses: counters and timers for their
    /// areas, as Snap7 forces.
    pub(crate) fn effective_word_len(&self) -> u8 {
        match self.area {
            S7_AREA_CT => S7_WL_COUNTER,
            S7_AREA_TM => S7_WL_TIMER,
            _ => self.word_len,
        }
    }

    /// The bytes the item's data spans, after validation.
    pub(crate) fn byte_len(&self) -> Result<usize, S7Error> {
        let word_len = self.effective_word_len();
        let size = word_size(word_len).ok_or(ErrorKind::InvalidWordLen)?;
        if word_len == S7_WL_BIT {
            if self.amount != 1 {
                return Err(S7Error::with_detail(
                    ErrorKind::InvalidParams,
                    "bit access reads or writes exactly one bit",
                ));
            }
            return Ok(1);
        }
        if self.amount == 0 {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                "an item of zero elements",
            ));
        }
        Ok(usize::from(self.amount) * size)
    }
}

/// How many blocks of each type the PLC holds (Snap7's `TS7BlocksList`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct S7BlocksList {
    /// Organization blocks.
    pub ob_count: u16,
    /// Function blocks.
    pub fb_count: u16,
    /// Functions.
    pub fc_count: u16,
    /// System function blocks.
    pub sfb_count: u16,
    /// System functions.
    pub sfc_count: u16,
    /// Data blocks.
    pub db_count: u16,
    /// System data blocks.
    pub sdb_count: u16,
}

impl S7BlocksList {
    /// The count for block type `block_type`.
    pub fn count(&self, block_type: u8) -> u16 {
        match block_type {
            BLOCK_OB => self.ob_count,
            BLOCK_FB => self.fb_count,
            BLOCK_FC => self.fc_count,
            BLOCK_SFB => self.sfb_count,
            BLOCK_SFC => self.sfc_count,
            BLOCK_DB => self.db_count,
            BLOCK_SDB => self.sdb_count,
            _ => 0,
        }
    }

    pub(crate) fn set(&mut self, block_type: u8, count: u16) {
        match block_type {
            BLOCK_OB => self.ob_count = count,
            BLOCK_FB => self.fb_count = count,
            BLOCK_FC => self.fc_count = count,
            BLOCK_SFB => self.sfb_count = count,
            BLOCK_SFC => self.sfc_count = count,
            BLOCK_DB => self.db_count = count,
            BLOCK_SDB => self.sdb_count = count,
            _ => {}
        }
    }
}

/// One entry of [`list_blocks_of_type`](crate::S7Client::list_blocks_of_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7BlockEntry {
    /// The block number.
    pub number: u16,
    /// The block flags.
    pub flags: u8,
    /// The block language (`language::*`).
    pub language: u8,
}

/// A block's properties (Snap7's `TS7BlockInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S7BlockInfo {
    /// The sub block type (`sub_block::*`).
    pub block_type: u8,
    /// The block number.
    pub block_number: u16,
    /// The language (`language::*`).
    pub block_lang: u8,
    /// The block flags.
    pub block_flags: u8,
    /// The MC7 code size — for a DB, its data size.
    pub mc7_size: u16,
    /// The size in load memory.
    pub load_size: u32,
    /// The local data size.
    pub local_data: u16,
    /// The SBB length.
    pub sbb_length: u16,
    /// The checksum.
    pub checksum: u16,
    /// The version (major in the high nibble, minor in the low).
    pub version: u8,
    /// The code date, `YYYY/MM/DD`.
    pub code_date: String,
    /// The interface date, `YYYY/MM/DD`.
    pub intf_date: String,
    /// The author.
    pub author: String,
    /// The family.
    pub family: String,
    /// The header (name).
    pub header: String,
}

/// A system status list read (Snap7's `TS7SZL`): the record length, the
/// record count, and the records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S7Szl {
    /// The SZL ID read.
    pub id: u16,
    /// The index read.
    pub index: u16,
    /// The length of one record (`LENTHDR`).
    pub record_len: u16,
    /// How many records (`N_DR`).
    pub record_count: u16,
    /// The records, back to back.
    pub data: Vec<u8>,
}

impl S7Szl {
    /// The records.
    pub fn records(&self) -> impl Iterator<Item = &[u8]> {
        let len = usize::from(self.record_len).max(1);
        self.data.chunks(len).filter(move |r| r.len() == len)
    }

    /// The record whose first word (the index field most SZLs carry) is
    /// `index`.
    pub fn record(&self, index: u16) -> Option<&[u8]> {
        self.records()
            .find(|r| r.len() >= 2 && u16::from_be_bytes([r[0], r[1]]) == index)
    }
}

/// The PLC's order code and firmware version (Snap7's `TS7OrderCode`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S7OrderCode {
    /// The order code (MLFB), as `6ES7 315-2EH14-0AB0`.
    pub code: String,
    /// Firmware version, major.
    pub v1: u8,
    /// Firmware version, minor.
    pub v2: u8,
    /// Firmware version, patch.
    pub v3: u8,
}

/// The CPU's identification (Snap7's `TS7CpuInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S7CpuInfo {
    /// The module type name.
    pub module_type_name: String,
    /// The serial number.
    pub serial_number: String,
    /// The automation system name.
    pub as_name: String,
    /// The copyright notice.
    pub copyright: String,
    /// The module name.
    pub module_name: String,
}

/// The communication processor's capabilities (Snap7's `TS7CpInfo`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct S7CpInfo {
    /// The largest PDU.
    pub max_pdu_length: u16,
    /// The most connections.
    pub max_connections: u16,
    /// The MPI rate in bit/s.
    pub max_mpi_rate: u32,
    /// The communication bus rate in bit/s.
    pub max_bus_rate: u32,
}

/// The protection settings (Snap7's `TS7Protection`, SZL `0x0232`
/// index 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct S7Protection {
    /// Protection level set with the mode selector (1..3, 0 none).
    pub sch_schal: u16,
    /// Password level (0 none).
    pub sch_par: u16,
    /// The valid protection level of the CPU.
    pub sch_rel: u16,
    /// Mode selector setting (1 RUN, 2 RUN-P, 3 STOP, 4 MRES, 0 none).
    pub bart_sch: u16,
    /// Startup switch setting (1 CRST, 2 WRST, 0 none).
    pub anl_sch: u16,
}

/// The PLC's operating state (Snap7's `S7CpuStatus*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuStatus {
    /// Unknown (`0x00`).
    Unknown,
    /// RUN (`0x08`).
    Run,
    /// STOP (`0x04`).
    Stop,
}

impl CpuStatus {
    /// Snap7's numeric value.
    pub fn code(self) -> u8 {
        match self {
            Self::Unknown => 0x00,
            Self::Run => 0x08,
            Self::Stop => 0x04,
        }
    }
}

/// A PLC date and time, as the clock functions carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7DateTime {
    /// The year, 1990..=2089.
    pub year: u16,
    /// The month, 1..=12.
    pub month: u8,
    /// The day of the month, 1..=31.
    pub day: u8,
    /// The hour, 0..=23.
    pub hour: u8,
    /// The minute, 0..=59.
    pub minute: u8,
    /// The second, 0..=59.
    pub second: u8,
    /// The millisecond, 0..=999.
    pub millisecond: u16,
    /// The day of the week, 1 (Sunday) ..= 7 (Saturday), as S7 counts it.
    pub weekday: u8,
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count since 1970-01-01.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

impl S7DateTime {
    /// The date and time `seconds` and `millis` after the Unix epoch
    /// (UTC), with the weekday computed.
    pub fn from_unix(seconds: u64, millis: u16) -> Self {
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        let (year, month, day) = civil_from_days(days);
        Self {
            year: year as u16,
            month: month as u8,
            day: day as u8,
            hour: (rest / 3600) as u8,
            minute: (rest / 60 % 60) as u8,
            second: (rest % 60) as u8,
            millisecond: millis,
            // 1970-01-01 was a Thursday (S7 weekday 5).
            weekday: ((days + 4).rem_euclid(7) + 1) as u8,
        }
    }

    /// The weekday (1 = Sunday) of the date.
    pub fn weekday_of(year: u16, month: u8, day: u8) -> u8 {
        let days = days_from_civil(i64::from(year), u32::from(month), u32::from(day));
        ((days + 4).rem_euclid(7) + 1) as u8
    }

    pub(crate) fn validate(&self) -> Result<(), S7Error> {
        let valid = (1990..=2089).contains(&self.year)
            && (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            && self.second < 60
            && self.millisecond < 1000;
        if valid {
            Ok(())
        } else {
            Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                format!("{self:?} is not a date and time an S7 clock can hold (years 1990..=2089)"),
            ))
        }
    }
}

/// An S7 date as a block carries it — days since 1984-01-01 — as
/// `YYYY/MM/DD`.
pub(crate) fn s7_date(days_since_1984: u16) -> String {
    let base = days_from_civil(1984, 1, 1);
    let (y, m, d) = civil_from_days(base + i64::from(days_since_1984));
    format!("{y:04}/{m:02}/{d:02}")
}

/// Text from a fixed-width field: up to the first NUL, trailing spaces
/// trimmed.
pub(crate) fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .trim_end()
        .to_string()
}
