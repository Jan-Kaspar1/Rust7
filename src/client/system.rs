// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! System information (SZL), status, clock and session password.
//!
//! # Telegrams
//!
//! All are UserData:
//!
//! - Read SZL: CPU-functions group, subfunction 1, payload `<id:2>
//!   <index:2>`; the answer starts `<id:2> <index:2> <record length:2>
//!   <record count:2>` and continues with the records, in as many parts
//!   as needed. Order code is SZL `0x0011`, CPU info `0x001C`, CP info
//!   `0x0131` index 1, protection `0x0232` index 4, status `0x0424`.
//! - Clock: time group, subfunction 1 (read, no payload) and 2 (set);
//!   the payload is 10 octets — a reserved octet, a century octet, then
//!   BCD year, month, day, hour, minute, second, three BCD digits of
//!   milliseconds and the weekday nibble (1 = Sunday). On set the
//!   century octet is sent as `0x19`, as Snap7 does; the PLC takes the
//!   century from the year (90..99 → 19xx, else 20xx).
//! - Session password: security group, subfunction 1 (set, payload the
//!   8 octets of the password encoded as below) and 2 (clear).

use super::S7Client;
use crate::error::{ErrorKind, S7Error};
use crate::proto::{answer, be16, be32, group, subfunction};
use crate::types::{
    text, CpuStatus, S7CpInfo, S7CpuInfo, S7DateTime, S7OrderCode, S7Protection, S7Szl,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

fn from_bcd(value: u8) -> u8 {
    (value >> 4) * 10 + (value & 0x0F)
}

/// The 8 octets a session password travels as: padded with spaces to 8
/// characters, the first two XORed with `0x55`, each further one with
/// `0x55` and the encoded octet two before it.
pub fn encode_password(password: &str) -> [u8; 8] {
    let mut out = [b' '; 8];
    for (slot, byte) in out.iter_mut().zip(password.bytes()) {
        *slot = byte;
    }
    out[0] ^= 0x55;
    out[1] ^= 0x55;
    for i in 2..8 {
        out[i] = out[i] ^ 0x55 ^ out[i - 2];
    }
    out
}

impl S7Client {
    /// ### Reads a system status list (Snap7's `ReadSZL`)
    ///
    /// Fetches every part of the answer.
    ///
    /// ### Errors
    /// - `ItemNotAvailable` (or the PLC's refusal code) for an SZL ID or
    ///   index the PLC does not have.
    pub fn read_szl(&mut self, id: u16, index: u16) -> Result<S7Szl, S7Error> {
        let mut request = id.to_be_bytes().to_vec();
        request.extend_from_slice(&index.to_be_bytes());
        let parts = self
            .userdata(group::CPU, subfunction::READ_SZL, Some(&request))
            .map_err(|e| e.refused_as(ErrorKind::ItemNotAvailable))?;
        let first = parts.first().map(Vec::as_slice).unwrap_or(&[]);
        if first.len() < 8 {
            return Err(answer(format!("an SZL answer of {} octets", first.len())));
        }
        let record_len = be16(first, 4);
        let mut data = first[8..].to_vec();
        for part in &parts[1..] {
            data.extend_from_slice(part);
        }
        let record_count = if record_len > 0 {
            (data.len() / usize::from(record_len)) as u16
        } else {
            be16(first, 6)
        };
        Ok(S7Szl {
            id: be16(first, 0),
            index: be16(first, 2),
            record_len,
            record_count,
            data,
        })
    }

    /// ### Lists the SZL IDs the PLC provides (Snap7's `ReadSZLList`)
    pub fn read_szl_list(&mut self) -> Result<Vec<u16>, S7Error> {
        let szl = self.read_szl(0x0000, 0x0000)?;
        Ok(szl.data.chunks_exact(2).map(|id| be16(id, 0)).collect())
    }

    /// ### Reads the order code and firmware version (Snap7's `GetOrderCode`)
    ///
    /// The version is taken from the firmware record (index 7) of SZL
    /// `0x0011`; where there is none, from the answer's last three
    /// octets, as Snap7 does.
    pub fn get_order_code(&mut self) -> Result<S7OrderCode, S7Error> {
        let szl = self.read_szl(0x0011, 0x0000)?;
        let first = szl
            .records()
            .next()
            .ok_or_else(|| answer("an order-code answer without records"))?;
        let version: &[u8] = match szl.record(0x0007) {
            Some(record) if record.len() >= 3 => &record[record.len() - 3..],
            _ if szl.data.len() >= 3 => &szl.data[szl.data.len() - 3..],
            _ => &[0, 0, 0],
        };
        Ok(S7OrderCode {
            code: text(first.get(2..22).unwrap_or(&[])),
            v1: version[0],
            v2: version[1],
            v3: version[2],
        })
    }

    /// ### Reads the CPU's identification (Snap7's `GetCpuInfo`)
    ///
    /// From SZL `0x001C`: the automation system name (record 1), module
    /// name (2), copyright (4), serial number (5) and module type name (7).
    pub fn get_cpu_info(&mut self) -> Result<S7CpuInfo, S7Error> {
        let szl = self.read_szl(0x001C, 0x0000)?;
        let field = |index: u16, len: usize| {
            szl.record(index)
                .and_then(|record| record.get(2..(2 + len).min(record.len())))
                .map(text)
                .unwrap_or_default()
        };
        Ok(S7CpuInfo {
            as_name: field(0x0001, 24),
            module_name: field(0x0002, 24),
            copyright: field(0x0004, 26),
            serial_number: field(0x0005, 24),
            module_type_name: field(0x0007, 32),
        })
    }

    /// ### Reads the communication capabilities (Snap7's `GetCpInfo`)
    pub fn get_cp_info(&mut self) -> Result<S7CpInfo, S7Error> {
        let szl = self.read_szl(0x0131, 0x0001)?;
        let record = szl
            .records()
            .next()
            .filter(|r| r.len() >= 14)
            .ok_or_else(|| answer("a CP-info answer without its record"))?;
        Ok(S7CpInfo {
            max_pdu_length: be16(record, 2),
            max_connections: be16(record, 4),
            max_mpi_rate: be32(record, 6),
            max_bus_rate: be32(record, 10),
        })
    }

    /// ### Reads the protection settings (Snap7's `GetProtection`)
    pub fn get_protection(&mut self) -> Result<S7Protection, S7Error> {
        let szl = self.read_szl(0x0232, 0x0004)?;
        let record = szl
            .records()
            .next()
            .filter(|r| r.len() >= 12)
            .ok_or_else(|| answer("a protection answer without its record"))?;
        Ok(S7Protection {
            sch_schal: be16(record, 2),
            sch_par: be16(record, 4),
            sch_rel: be16(record, 6),
            bart_sch: be16(record, 8),
            anl_sch: be16(record, 10),
        })
    }

    /// ### Reads the operating state (Snap7's `GetPlcStatus`)
    ///
    /// From the mode octet of SZL `0x0424`: RUN, STOP, or unknown.
    pub fn get_plc_status(&mut self) -> Result<CpuStatus, S7Error> {
        let szl = self.read_szl(0x0424, 0x0000)?;
        let mode = szl
            .data
            .get(3)
            .copied()
            .ok_or_else(|| answer("a status answer without its record"))?;
        Ok(match mode & 0x0F {
            0x08 => CpuStatus::Run,
            0x01..=0x04 => CpuStatus::Stop,
            _ => CpuStatus::Unknown,
        })
    }

    /// ### Reads the PLC's clock (Snap7's `GetPlcDateTime`)
    pub fn get_plc_date_time(&mut self) -> Result<S7DateTime, S7Error> {
        let parts = self.userdata(group::TIME, subfunction::READ_CLOCK, None)?;
        let t = parts.concat();
        if t.len() < 10 {
            return Err(answer(format!("a clock answer of {} octets", t.len())));
        }
        let year = u16::from(from_bcd(t[2]));
        Ok(S7DateTime {
            year: if year < 90 { 2000 + year } else { 1900 + year },
            month: from_bcd(t[3]),
            day: from_bcd(t[4]),
            hour: from_bcd(t[5]),
            minute: from_bcd(t[6]),
            second: from_bcd(t[7]),
            millisecond: u16::from(from_bcd(t[8])) * 10 + u16::from(t[9] >> 4),
            weekday: t[9] & 0x0F,
        })
    }

    /// ### Sets the PLC's clock (Snap7's `SetPlcDateTime`)
    ///
    /// The weekday is computed from the date.
    ///
    /// ### Errors
    /// - `InvalidParams`: a date outside 1990..=2089 or an invalid field.
    pub fn set_plc_date_time(&mut self, time: &S7DateTime) -> Result<(), S7Error> {
        time.validate()?;
        let weekday = S7DateTime::weekday_of(time.year, time.month, time.day);
        let payload = [
            0x00,
            0x19,
            bcd((time.year % 100) as u8),
            bcd(time.month),
            bcd(time.day),
            bcd(time.hour),
            bcd(time.minute),
            bcd(time.second),
            bcd((time.millisecond / 10) as u8),
            (((time.millisecond % 10) as u8) << 4) | weekday,
        ];
        self.userdata_command(group::TIME, subfunction::SET_CLOCK, Some(&payload))
    }

    /// ### Sets the PLC's clock to this computer's (Snap7's `SetPlcSystemDateTime`)
    ///
    /// Uses UTC (Snap7 uses the local time zone; Rust's standard library
    /// knows none).
    pub fn set_plc_system_date_time(&mut self) -> Result<(), S7Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            S7Error::with_detail(ErrorKind::InvalidParams, "the system clock is before 1970")
        })?;
        let time = S7DateTime::from_unix(now.as_secs(), now.subsec_millis() as u16);
        self.set_plc_date_time(&time)
    }

    /// ### Sends the session password (Snap7's `SetSessionPassword`)
    ///
    /// Raises the connection's access to a protected CPU's password
    /// level. At most 8 characters; shorter ones are padded with spaces.
    ///
    /// ### Errors
    /// - `InvalidParams`: longer than 8 characters or not ASCII.
    /// - `InvalidPassword` (`0xD602`).
    pub fn set_session_password(&mut self, password: &str) -> Result<(), S7Error> {
        if password.len() > 8 || !password.is_ascii() {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                "a session password is at most 8 ASCII characters",
            ));
        }
        let encoded = encode_password(password);
        self.userdata_command(group::SECURITY, subfunction::SET_PASSWORD, Some(&encoded))
    }

    /// ### Clears the session password (Snap7's `ClearSessionPassword`)
    pub fn clear_session_password(&mut self) -> Result<(), S7Error> {
        self.userdata_command(group::SECURITY, subfunction::CLEAR_PASSWORD, None)
    }
}
