// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! PLC control: start, stop, copy RAM to ROM, compress.
//!
//! # Telegrams
//!
//! - Hot start: PI service `P_PROGRAM` with an empty parameter block.
//! - Cold start: PI service `P_PROGRAM` with the parameter block `C `.
//! - Stop: function `0x29` with `P_PROGRAM`.
//! - Copy RAM to ROM: PI service `_MODU` with the parameter block `EP`.
//! - Compress: PI service `_GARB` with an empty parameter block.
//!
//! The PLC answers with its function code and, in the second parameter
//! octet, `0x02` when it is already in RUN or `0x07` when it is already
//! in STOP.

use super::blocks::pi_service;
use super::{elapsed_ms, S7Client};
use crate::error::{ErrorKind, S7Error};
use crate::proto::function;
use std::time::{Duration, Instant};

const ALREADY_RUN: u8 = 0x02;
const ALREADY_STOP: u8 = 0x07;

impl S7Client {
    fn control(
        &mut self,
        param: Vec<u8>,
        refused: ErrorKind,
        already: Option<(u8, ErrorKind)>,
        timeout: Duration,
    ) -> Result<(), S7Error> {
        let started = Instant::now();
        let reply = self.job_with_timeout(param, Vec::new(), timeout)?;
        if reply.error != 0 {
            return Err(S7Error::cpu(refused, reply.error));
        }
        match (reply.param.get(1).copied().unwrap_or(0), already) {
            (0, _) => {}
            (code, Some((value, kind))) if code == value => return Err(kind.into()),
            (code, _) => return Err(S7Error::cpu(refused, u16::from(code))),
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    /// ### Puts the PLC in RUN with a warm restart (Snap7's `PlcHotStart`)
    ///
    /// ### Errors
    /// - `AlreadyRun`; `CannotStartPlc` with the PLC's code.
    pub fn plc_hot_start(&mut self) -> Result<(), S7Error> {
        let param = pi_service(&[], "P_PROGRAM");
        self.control(
            param,
            ErrorKind::CannotStartPlc,
            Some((ALREADY_RUN, ErrorKind::AlreadyRun)),
            self.recv_timeout(),
        )
    }

    /// ### Puts the PLC in RUN with a cold restart (Snap7's `PlcColdStart`)
    ///
    /// ### Errors
    /// - `AlreadyRun`; `CannotStartPlc` with the PLC's code.
    pub fn plc_cold_start(&mut self) -> Result<(), S7Error> {
        let param = pi_service(b"C ", "P_PROGRAM");
        self.control(
            param,
            ErrorKind::CannotStartPlc,
            Some((ALREADY_RUN, ErrorKind::AlreadyRun)),
            self.recv_timeout(),
        )
    }

    /// ### Puts the PLC in STOP (Snap7's `PlcStop`)
    ///
    /// ### Errors
    /// - `AlreadyStop`; `CannotStopPlc` with the PLC's code.
    pub fn plc_stop(&mut self) -> Result<(), S7Error> {
        let mut param = vec![function::PLC_STOP, 0, 0, 0, 0, 0, 9];
        param.extend_from_slice(b"P_PROGRAM");
        self.control(
            param,
            ErrorKind::CannotStopPlc,
            Some((ALREADY_STOP, ErrorKind::AlreadyStop)),
            self.recv_timeout(),
        )
    }

    /// ### Copies RAM to ROM (Snap7's `CopyRamToRom`)
    ///
    /// The PLC answers when it is done, which can take seconds: the
    /// reply is awaited for `timeout_ms`.
    ///
    /// ### Errors
    /// - `InvalidParams`: a timeout of 0.
    /// - `CannotCopyRamToRom` with the PLC's code.
    pub fn copy_ram_to_rom(&mut self, timeout_ms: u64) -> Result<(), S7Error> {
        if timeout_ms == 0 {
            return Err(ErrorKind::InvalidParams.into());
        }
        let param = pi_service(b"EP", "_MODU");
        self.control(
            param,
            ErrorKind::CannotCopyRamToRom,
            None,
            Duration::from_millis(timeout_ms),
        )
    }

    /// ### Compresses the PLC's memory (Snap7's `Compress`)
    ///
    /// The reply is awaited for `timeout_ms`.
    ///
    /// ### Errors
    /// - `InvalidParams`: a timeout of 0.
    /// - `CannotCompress` with the PLC's code.
    pub fn compress(&mut self, timeout_ms: u64) -> Result<(), S7Error> {
        if timeout_ms == 0 {
            return Err(ErrorKind::InvalidParams.into());
        }
        let param = pi_service(&[], "_GARB");
        self.control(
            param,
            ErrorKind::CannotCompress,
            None,
            Duration::from_millis(timeout_ms),
        )
    }
}
