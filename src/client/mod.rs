// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! The S7 client: Snap7's `TS7Client` function set over a synchronous
//! `std` TCP stream.
//!
//! | Snap7 | Rust7 |
//! | --- | --- |
//! | `ConnectTo`, `SetConnectionParams`, `Connect`, `Disconnect` | [`connect_rack_slot`](S7Client::connect_rack_slot), [`set_connection_params`](S7Client::set_connection_params), [`connect`](S7Client::connect), [`connect_tsap`](S7Client::connect_tsap), [`disconnect`](S7Client::disconnect) |
//! | `SetConnectionType`, `SetParam`/`GetParam` | [`set_connection_type`](S7Client::set_connection_type), [`set_connection_port`](S7Client::set_connection_port), [`set_timeout`](S7Client::set_timeout), [`set_pdu_request`](S7Client::set_pdu_request) |
//! | `ReadArea`, `WriteArea`, `DBRead`/`DBWrite`, `MBRead`/`MBWrite`, `EBRead`/`EBWrite`, `ABRead`/`ABWrite`, `TMRead`/`TMWrite`, `CTRead`/`CTWrite` | [`read_area`](S7Client::read_area), [`write_area`](S7Client::write_area), [`read_db`](S7Client::read_db), .. |
//! | `ReadMultiVars`, `WriteMultiVars` | [`read_multi_vars`](S7Client::read_multi_vars), [`write_multi_vars`](S7Client::write_multi_vars) |
//! | `ListBlocks`, `ListBlocksOfType`, `GetAgBlockInfo`, `GetPgBlockInfo` | [`list_blocks`](S7Client::list_blocks), [`list_blocks_of_type`](S7Client::list_blocks_of_type), [`get_ag_block_info`](S7Client::get_ag_block_info), [`get_pg_block_info`](S7Client::get_pg_block_info) |
//! | `Upload`, `FullUpload`, `Download`, `Delete`, `DBGet`, `DBFill` | [`upload`](S7Client::upload), [`full_upload`](S7Client::full_upload), [`download`](S7Client::download), [`delete`](S7Client::delete), [`db_get`](S7Client::db_get), [`db_fill`](S7Client::db_fill) |
//! | `ReadSZL`, `ReadSZLList`, `GetOrderCode`, `GetCpuInfo`, `GetCpInfo` | [`read_szl`](S7Client::read_szl), [`read_szl_list`](S7Client::read_szl_list), [`get_order_code`](S7Client::get_order_code), [`get_cpu_info`](S7Client::get_cpu_info), [`get_cp_info`](S7Client::get_cp_info) |
//! | `PlcHotStart`, `PlcColdStart`, `PlcStop`, `CopyRamToRom`, `Compress`, `GetPlcStatus` | [`plc_hot_start`](S7Client::plc_hot_start), [`plc_cold_start`](S7Client::plc_cold_start), [`plc_stop`](S7Client::plc_stop), [`copy_ram_to_rom`](S7Client::copy_ram_to_rom), [`compress`](S7Client::compress), [`get_plc_status`](S7Client::get_plc_status) |
//! | `GetPlcDateTime`, `SetPlcDateTime`, `SetPlcSystemDateTime` | [`get_plc_date_time`](S7Client::get_plc_date_time), [`set_plc_date_time`](S7Client::set_plc_date_time), [`set_plc_system_date_time`](S7Client::set_plc_system_date_time) |
//! | `GetProtection`, `SetSessionPassword`, `ClearSessionPassword` | [`get_protection`](S7Client::get_protection), [`set_session_password`](S7Client::set_session_password), [`clear_session_password`](S7Client::clear_session_password) |
//! | `IsoExchangeBuffer`, `GetPduLength`, `GetExecTime`, `GetConnected`, `ErrorText` | [`iso_exchange_buffer`](S7Client::iso_exchange_buffer), [`pdu_length`](S7Client::pdu_length), [`last_time`](S7Client::last_time), [`connected`](S7Client::connected), [`error_text`](crate::error_text) |
//!
//! # Connection state
//!
//! An error that leaves the connection in an unknown state — any TCP or
//! ISO error ([`S7Error::is_link`]), or a reply that does not answer the
//! request (wrong PDU reference) — closes the connection; the next call
//! returns [`ErrorKind::TcpNotConnected`] until [`connect`](S7Client::connect)
//! (or another `connect_*`) opens it again. A refusal the PLC sends
//! ([`S7Error::is_cpu`]) keeps it.

mod blocks;
mod control;
mod data;
mod system;

use crate::error::{ErrorKind, S7Error};
use crate::iso::{IsoParams, IsoTcp};
use crate::proto::{
    self, answer, userdata_request_param, Pdu, Rosctr, Setup, UserDataParam, USERDATA_EMPTY,
};
use std::time::{Duration, Instant};

pub use crate::error::ErrorKind as S7ErrorKind;
pub use crate::proto::{
    S7_AREA_CT, S7_AREA_DB, S7_AREA_MK, S7_AREA_PA, S7_AREA_PE, S7_AREA_TM, S7_WL_BIT, S7_WL_BYTE,
    S7_WL_CHAR, S7_WL_COUNTER, S7_WL_DINT, S7_WL_DWORD, S7_WL_INT, S7_WL_REAL, S7_WL_TIMER,
    S7_WL_WORD,
};

/// Connection type: programming device (the default).
pub const CT_PG: u16 = 0x0001;
/// Connection type: operator panel (HMI).
pub const CT_OP: u16 = 0x0002;
/// Connection type: S7 basic.
pub const CT_S7: u16 = 0x0003;

/// The ISO-on-TCP port.
pub const DEFAULT_PORT: u16 = 102;
/// The PDU size proposed by default, as Snap7 does.
pub const DEFAULT_PDU_REQUEST: u16 = 480;
/// The smallest PDU size [`S7Client::set_pdu_request`] accepts.
pub const MIN_PDU_REQUEST: u16 = 240;
/// The largest PDU size [`S7Client::set_pdu_request`] accepts — the
/// largest any S7 CPU negotiates.
pub const MAX_PDU_REQUEST: u16 = 960;
/// The local TSAP used with rack and slot.
pub const DEFAULT_LOCAL_TSAP: u16 = 0x0100;

/// The most parts a multi-part UserData answer may come in.
const MAX_USERDATA_PARTS: usize = 4096;

/// A Siemens S7 client.
#[derive(Debug)]
pub struct S7Client {
    link: Option<IsoTcp>,
    host: String,
    port: u16,
    local_tsap: u16,
    remote_tsap: u16,
    conn_type: u16,
    co_timeout_ms: u64,
    rd_timeout_ms: u64,
    wr_timeout_ms: u64,
    pdu_request: u16,
    pdu_ref: u16,
    /// The PDU length negotiated with the PLC (0 while disconnected).
    pub pdu_length: u16,
    /// Whether the client is connected.
    pub connected: bool,
    /// The last job's duration in milliseconds (0 after an error).
    pub last_time: f64,
    /// How many PDU exchanges the last read or write took.
    pub chunks: usize,
}

impl Default for S7Client {
    fn default() -> Self {
        Self::new()
    }
}

impl S7Client {
    /// ### Creates a new `S7Client` instance with default settings.
    ///
    /// The client starts disconnected; use one of the `connect_*`
    /// methods to open a connection to a PLC.
    pub fn new() -> Self {
        S7Client {
            link: None,
            host: String::new(),
            port: DEFAULT_PORT,
            local_tsap: DEFAULT_LOCAL_TSAP,
            remote_tsap: 0,
            conn_type: CT_PG,
            co_timeout_ms: 3000,
            rd_timeout_ms: 1000,
            wr_timeout_ms: 500,
            pdu_request: DEFAULT_PDU_REQUEST,
            pdu_ref: 0,
            pdu_length: 0,
            connected: false,
            last_time: 0.0,
            chunks: 0,
        }
    }

    // -----------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------

    /// ### Changes the S7 connection type
    ///
    /// - `CT_PG`: as a programming device (the default)
    /// - `CT_OP`: as an HMI
    /// - `CT_S7`: as a generic (S7 basic) device
    ///
    /// The type is the high byte of the remote TSAP that
    /// [`connect_rack_slot`](Self::connect_rack_slot) derives; it does not
    /// apply to [`connect_tsap`](Self::connect_tsap). With old CPUs that
    /// have few connection resources, a PG connection may be refused
    /// while engineering tools are online; use `CT_OP` or `CT_S7`.
    ///
    /// ### Errors
    /// - `InvalidParams`: not one of the three types.
    pub fn set_connection_type(&mut self, connection_type: u16) -> Result<(), S7Error> {
        if !(CT_PG..=CT_S7).contains(&connection_type) {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.conn_type = connection_type;
        Ok(())
    }

    /// ### Sets the timeouts
    ///
    /// - `co_timeout_ms`: TCP connect (default 3000 ms)
    /// - `rd_timeout_ms`: each reply, including the connection confirm
    ///   and the PDU negotiation (default 1000 ms)
    /// - `wr_timeout_ms`: each send (default 500 ms)
    ///
    /// ### Errors
    /// - `InvalidParams`: a value of 0.
    pub fn set_timeout(
        &mut self,
        co_timeout_ms: u64,
        rd_timeout_ms: u64,
        wr_timeout_ms: u64,
    ) -> Result<(), S7Error> {
        if co_timeout_ms == 0 || rd_timeout_ms == 0 || wr_timeout_ms == 0 {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.co_timeout_ms = co_timeout_ms;
        self.rd_timeout_ms = rd_timeout_ms;
        self.wr_timeout_ms = wr_timeout_ms;
        Ok(())
    }

    /// ### Sets the TCP port (default 102)
    ///
    /// ### Errors
    /// - `InvalidParams`: port 0.
    pub fn set_connection_port(&mut self, port: u16) -> Result<(), S7Error> {
        if port == 0 {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.port = port;
        Ok(())
    }

    /// ### Sets the PDU size proposed when connecting (Snap7's `PDURequest`)
    ///
    /// The PLC answers with the size it accepts — 240 for an S7-300 or
    /// LOGO!, 240 or 480 for an S7-1200, up to 960 for an S7-1500 or
    /// S7-400 — and the client never uses more than it proposed.
    ///
    /// ### Errors
    /// - `InvalidParams`: outside 240..=960.
    pub fn set_pdu_request(&mut self, size: u16) -> Result<(), S7Error> {
        if !(MIN_PDU_REQUEST..=MAX_PDU_REQUEST).contains(&size) {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.pdu_request = size;
        Ok(())
    }

    /// The PDU size proposed when connecting.
    pub fn pdu_request(&self) -> u16 {
        self.pdu_request
    }

    /// The PDU size negotiated (0 while disconnected).
    pub fn pdu_length(&self) -> u16 {
        self.pdu_length
    }

    /// Whether the client is connected.
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// The last job's duration in milliseconds.
    pub fn last_time(&self) -> f64 {
        self.last_time
    }

    /// The local TSAP of the configured connection.
    pub fn local_tsap(&self) -> u16 {
        self.local_tsap
    }

    /// The remote TSAP of the configured connection.
    pub fn remote_tsap(&self) -> u16 {
        self.remote_tsap
    }

    /// ### Stores the address and TSAPs for [`connect`](Self::connect)
    ///
    /// `address` is a host name, an IPv4 address, or an IPv6 address
    /// (with or without brackets); the port is set by
    /// [`set_connection_port`](Self::set_connection_port).
    pub fn set_connection_params(&mut self, address: &str, local_tsap: u16, remote_tsap: u16) {
        self.host = address.to_string();
        self.local_tsap = local_tsap;
        self.remote_tsap = remote_tsap;
    }

    // -----------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------

    /// ### Connects to an S7-1200 or S7-1500 (rack 0, slot 0)
    pub fn connect_s71200_1500(&mut self, ip: &str) -> Result<(), S7Error> {
        self.connect_rack_slot(ip, 0, 0)
    }

    /// ### Connects to an S7-300 (rack 0, slot 2)
    pub fn connect_s7300(&mut self, ip: &str) -> Result<(), S7Error> {
        self.connect_rack_slot(ip, 0, 2)
    }

    /// ### Connects using rack and slot (Snap7's `ConnectTo`)
    ///
    /// The remote TSAP is `connection_type << 8 | rack * 32 + slot`, the
    /// local TSAP `0x0100`.
    ///
    /// ### Errors
    /// - `InvalidParams`: rack above 7 or slot above 31.
    /// - Any error of [`connect_tsap`](Self::connect_tsap).
    pub fn connect_rack_slot(&mut self, ip: &str, rack: u16, slot: u16) -> Result<(), S7Error> {
        if rack > 7 || slot > 31 {
            return Err(ErrorKind::InvalidParams.into());
        }
        let remote_tsap = (self.conn_type << 8) | (rack * 0x20 + slot);
        self.connect_tsap(ip, DEFAULT_LOCAL_TSAP, remote_tsap)
    }

    /// ### Connects using TSAPs (LOGO!, S7-200, configured connections)
    ///
    /// Opens TCP, runs the ISO connection request / confirm with the
    /// TSAPs (proposing a 1024-octet TPDU), and negotiates the PDU size
    /// with Setup Communication (proposing
    /// [`pdu_request`](Self::pdu_request) and one parallel job each way).
    ///
    /// ### Errors
    /// - `TcpConnectionFailed`, `TcpConnectionTimeout`,
    ///   `TcpUnreachableHost`: TCP could not connect.
    /// - `IsoConnect`: the PLC refused the TSAPs (wrong rack/slot).
    /// - `NegotiatingPdu`: Setup Communication failed.
    pub fn connect_tsap(
        &mut self,
        ip: &str,
        local_tsap: u16,
        remote_tsap: u16,
    ) -> Result<(), S7Error> {
        self.set_connection_params(ip, local_tsap, remote_tsap);
        self.connect()
    }

    /// ### Connects with the stored parameters (Snap7's `Connect`)
    ///
    /// Reconnects after an error with the address and TSAPs of the last
    /// `connect_*` or [`set_connection_params`](Self::set_connection_params).
    pub fn connect(&mut self) -> Result<(), S7Error> {
        self.disconnect();
        self.last_time = 0.0;
        if self.host.is_empty() {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                "no address to connect to",
            ));
        }
        let start = Instant::now();
        let params = IsoParams {
            host: &self.host,
            port: self.port,
            local_tsap: self.local_tsap,
            remote_tsap: self.remote_tsap,
            connect_timeout: Duration::from_millis(self.co_timeout_ms),
            recv_timeout: Duration::from_millis(self.rd_timeout_ms),
            send_timeout: Duration::from_millis(self.wr_timeout_ms),
        };
        self.link = Some(IsoTcp::connect(&params)?);
        let proposal = Setup {
            max_amq_calling: 1,
            max_amq_called: 1,
            pdu_length: self.pdu_request,
        };
        let request = self.request(Rosctr::Job, proposal.encode(), Vec::new());
        let negotiated = self
            .transact(&request, self.recv_timeout())
            .and_then(|reply| {
                if reply.error != 0 {
                    return Err(S7Error::cpu(ErrorKind::NegotiatingPdu, reply.error));
                }
                let setup = Setup::decode(&reply.param)
                    .map_err(|e| S7Error::new(ErrorKind::NegotiatingPdu).detailed(e.to_string()))?;
                if setup.pdu_length == 0 {
                    return Err(S7Error::with_detail(
                        ErrorKind::NegotiatingPdu,
                        "the PLC negotiated a PDU of 0 octets",
                    ));
                }
                // Never more than was proposed, whatever the PLC says.
                Ok(setup.pdu_length.min(self.pdu_request))
            });
        match negotiated {
            Ok(pdu) => {
                self.pdu_length = pdu;
                self.connected = true;
                self.last_time = elapsed_ms(start);
                Ok(())
            }
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// ### Closes the connection
    ///
    /// Safe to call when not connected.
    pub fn disconnect(&mut self) {
        if let Some(mut link) = self.link.take() {
            link.close();
        }
        self.connected = false;
        self.pdu_length = 0;
    }

    // -----------------------------------------------------------------
    // Exchanges
    // -----------------------------------------------------------------

    pub(crate) fn recv_timeout(&self) -> Duration {
        Duration::from_millis(self.rd_timeout_ms)
    }

    pub(crate) fn require_connected(&self) -> Result<(), S7Error> {
        if self.connected && self.link.is_some() {
            Ok(())
        } else {
            Err(ErrorKind::TcpNotConnected.into())
        }
    }

    fn next_ref(&mut self) -> u16 {
        self.pdu_ref = self.pdu_ref.wrapping_add(1);
        self.pdu_ref
    }

    fn request(&mut self, rosctr: Rosctr, param: Vec<u8>, data: Vec<u8>) -> Pdu {
        let pdu_ref = self.next_ref();
        Pdu::request(rosctr, pdu_ref, param, data)
    }

    /// Drops the connection after an error that leaves it unknown.
    fn fail(&mut self, error: S7Error) -> S7Error {
        if error.is_link() {
            self.disconnect();
        }
        error
    }

    /// Sends one PDU on the link.
    pub(crate) fn send_pdu(&mut self, pdu: &Pdu) -> Result<(), S7Error> {
        let link = self.link.as_mut().ok_or(ErrorKind::TcpNotConnected)?;
        let result = link.send(&pdu.encode());
        result.map_err(|e| self.fail(e))
    }

    /// Receives one PDU by `deadline`.
    pub(crate) fn receive_pdu(&mut self, deadline: Instant) -> Result<Pdu, S7Error> {
        let link = self.link.as_mut().ok_or(ErrorKind::TcpNotConnected)?;
        let result = link.receive(deadline).and_then(|bytes| Pdu::decode(&bytes));
        result.map_err(|e| self.fail(e))
    }

    /// Sends `request` and returns the PLC's reply to it, checking the
    /// reply's type, PDU reference, and (for a Job) function. A reply
    /// that does not answer the request closes the connection.
    fn transact(&mut self, request: &Pdu, timeout: Duration) -> Result<Pdu, S7Error> {
        self.send_pdu(request)?;
        let reply = self.receive_pdu(Instant::now() + timeout)?;
        let expected = match request.rosctr {
            Rosctr::UserData => matches!(reply.rosctr, Rosctr::UserData),
            _ => matches!(reply.rosctr, Rosctr::Ack | Rosctr::AckData),
        };
        let mismatch = if !expected {
            Some(format!(
                "a {:?} answers a {:?}",
                reply.rosctr, request.rosctr
            ))
        } else if reply.pdu_ref != request.pdu_ref {
            Some(format!(
                "the reply carries PDU reference {}, the request {}",
                reply.pdu_ref, request.pdu_ref
            ))
        } else if request.rosctr == Rosctr::Job
            && reply.error == 0
            && !reply.param.is_empty()
            && reply.param.first() != request.param.first()
        {
            Some(format!(
                "the reply answers function {:#04x}, the request sent {:#04x}",
                reply.param[0], request.param[0]
            ))
        } else {
            None
        };
        if let Some(detail) = mismatch {
            self.disconnect();
            return Err(answer(detail));
        }
        Ok(reply)
    }

    /// Runs one Job and returns the reply; the caller looks at
    /// `reply.error`.
    pub(crate) fn job(&mut self, param: Vec<u8>, data: Vec<u8>) -> Result<Pdu, S7Error> {
        self.job_with_timeout(param, data, self.recv_timeout())
    }

    pub(crate) fn job_with_timeout(
        &mut self,
        param: Vec<u8>,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<Pdu, S7Error> {
        self.require_connected()?;
        let request = self.request(Rosctr::Job, param, data);
        self.transact(&request, timeout)
    }

    /// Runs one UserData request and returns the response's parameter
    /// and data parts.
    fn userdata_once(
        &mut self,
        group: u8,
        subfunction: u8,
        sequence: Option<u8>,
        data: Vec<u8>,
    ) -> Result<(UserDataParam, Vec<u8>), S7Error> {
        self.require_connected()?;
        let request = self.request(
            Rosctr::UserData,
            userdata_request_param(group, subfunction, sequence),
            data,
        );
        let reply = self.transact(&request, self.recv_timeout())?;
        let param = UserDataParam::decode(&reply.param)?;
        if param.group != group || param.subfunction != subfunction {
            return Err(answer(format!(
                "the reply answers UserData group {:#x} subfunction {:#04x}, the request asked {group:#x} {subfunction:#04x}",
                param.group, param.subfunction
            )));
        }
        Ok((param, reply.data))
    }

    /// Runs a UserData request and every follow-up its answer needs,
    /// returning each part's payload. A parameter error or a data return
    /// code other than success is the PLC's refusal.
    pub(crate) fn userdata(
        &mut self,
        group: u8,
        subfunction: u8,
        payload: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, S7Error> {
        self.userdata_parts(group, subfunction, payload, true)
    }

    /// Runs a UserData request that answers with no data (set the clock,
    /// set or clear the password): a data return code of "no data" is
    /// success.
    pub(crate) fn userdata_command(
        &mut self,
        group: u8,
        subfunction: u8,
        payload: Option<&[u8]>,
    ) -> Result<(), S7Error> {
        self.userdata_parts(group, subfunction, payload, false)
            .map(|_| ())
    }

    fn userdata_parts(
        &mut self,
        group: u8,
        subfunction: u8,
        payload: Option<&[u8]>,
        expect_data: bool,
    ) -> Result<Vec<Vec<u8>>, S7Error> {
        let data = match payload {
            Some(payload) => proto::userdata_request_data(payload),
            None => USERDATA_EMPTY.to_vec(),
        };
        let mut parts = Vec::new();
        let mut sequence = None;
        loop {
            let (param, data) =
                self.userdata_once(group, subfunction, sequence, data_for(sequence, &data))?;
            if param.error != 0 {
                return Err(S7Error::from_cpu(param.error));
            }
            let (code, bytes) = proto::userdata_payload(&data)?;
            if !expect_data && code == proto::item::NOT_FOUND {
                return Ok(parts);
            }
            if code != proto::item::SUCCESS {
                return Err(S7Error::from_cpu(u16::from(code)));
            }
            parts.push(bytes.to_vec());
            if param.last {
                return Ok(parts);
            }
            if parts.len() >= MAX_USERDATA_PARTS {
                return Err(answer("a UserData answer that never ends"));
            }
            sequence = Some(param.sequence);
        }
    }

    // -----------------------------------------------------------------
    // Low level
    // -----------------------------------------------------------------

    /// ### Exchanges a raw S7 PDU (Snap7's `IsoExchangeBuffer`)
    ///
    /// Sends `pdu` — a complete S7 PDU starting with `0x32` — as is and
    /// returns the PLC's reply PDU, both without the TPKT and COTP
    /// headers. The reply is not checked against the request.
    ///
    /// ### Errors
    /// - `InvalidParams`: `pdu` is longer than the negotiated PDU.
    /// - Any TCP or ISO error.
    pub fn iso_exchange_buffer(&mut self, pdu: &[u8]) -> Result<Vec<u8>, S7Error> {
        self.require_connected()?;
        if pdu.is_empty() || pdu.len() > usize::from(self.pdu_length) {
            return Err(ErrorKind::InvalidParams.into());
        }
        let start = Instant::now();
        let deadline = start + self.recv_timeout();
        let link = self.link.as_mut().ok_or(ErrorKind::TcpNotConnected)?;
        let result = link.send(pdu).and_then(|()| link.receive(deadline));
        let reply = result.map_err(|e| self.fail(e))?;
        self.last_time = elapsed_ms(start);
        Ok(reply)
    }
}

/// The data part of a UserData follow-up: none, whatever the first
/// request carried.
fn data_for(sequence: Option<u8>, first: &[u8]) -> Vec<u8> {
    match sequence {
        None => first.to_vec(),
        Some(_) => USERDATA_EMPTY.to_vec(),
    }
}

pub(crate) fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

impl Drop for S7Client {
    fn drop(&mut self) {
        self.disconnect();
    }
}
