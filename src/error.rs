// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! Errors.
//!
//! Every error has an [`ErrorKind`] whose [`ErrorKind::code`] is the
//! numeric value Snap7 uses for the same condition, so logs and
//! diagnostics line up with Snap7-based tools:
//!
//! - TCP errors occupy the low 16 bits (`0x0000_0001`..),
//! - ISO (RFC 1006 / ISO 8073) errors bits 16..19 (`0x0001_0000`..),
//! - client errors the upper bits (`0x0010_0000`..).
//!
//! When the PLC itself refused something, the error also carries the
//! code the PLC answered with ([`S7Error::cpu_code`]): an item return
//! code (`0x01`..`0x0A`, below `0x100`) or a header / parameter error
//! class and code (`0x8104`, `0xD241`, ..). That code is what tells a
//! hardware fault from a missing DB, or a busy CPU from a refusal.

use std::fmt;
use std::io;

/// What went wrong, one variant per Snap7 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    // --- TCP ---------------------------------------------------------
    /// The socket could not be created.
    TcpSocketCreation,
    /// The TCP connection was not established within the connect timeout.
    TcpConnectionTimeout,
    /// The TCP connection was refused or failed.
    TcpConnectionFailed,
    /// No reply arrived within the receive timeout.
    TcpReceiveTimeout,
    /// Receiving failed.
    TcpDataReceive,
    /// Sending did not complete within the send timeout.
    TcpSendTimeout,
    /// Sending failed.
    TcpDataSend,
    /// The peer closed or reset the connection.
    TcpConnectionReset,
    /// The client is not connected.
    TcpNotConnected,
    /// The host is unreachable or its name does not resolve.
    TcpUnreachableHost,

    // --- ISO ---------------------------------------------------------
    /// The ISO 8073 connection was refused (wrong rack/slot or TSAP).
    IsoConnect,
    /// The peer sent an ISO disconnect request.
    IsoDisconnect,
    /// A TPKT or COTP header is not valid.
    IsoInvalidPdu,
    /// A telegram's length is not valid.
    IsoInvalidDataSize,
    /// A telegram is shorter than its headers.
    IsoShortPacket,
    /// A PDU arrived in too many fragments.
    IsoTooManyFragments,
    /// A PDU is larger than the negotiated size.
    IsoPduOverflow,
    /// A packet could not be sent.
    IsoSendPacket,
    /// A packet could not be received (it broke off).
    IsoRecvPacket,
    /// Invalid ISO connection parameters.
    IsoInvalidParams,

    // --- Client ------------------------------------------------------
    /// Setup Communication (PDU negotiation) failed.
    NegotiatingPdu,
    /// A function was called with invalid parameters.
    InvalidParams,
    /// More than [`MAX_VARS`](crate::MAX_VARS) items in one call where
    /// no splitting applies.
    TooManyItems,
    /// The word length is not valid for the area.
    InvalidWordLen,
    /// A write was only partly carried out.
    PartialDataWritten,
    /// The request or its answer does not fit the negotiated PDU.
    SizeOverPdu,
    /// The PLC's answer is not valid.
    InvalidPlcAnswer,
    /// The address lies outside the area (item code `0x05`).
    AddressOutOfRange,
    /// The transport size is not valid (item code `0x06`).
    InvalidTransportSize,
    /// The written data does not match the item (item code `0x07`).
    WriteDataSizeMismatch,
    /// The object does not exist (item code `0x0A`, `0xD209`).
    ItemNotAvailable,
    /// The value is not valid (`0xDC01`).
    InvalidValue,
    /// The PLC refused to start.
    CannotStartPlc,
    /// The PLC is already in RUN.
    AlreadyRun,
    /// The PLC refused to stop.
    CannotStopPlc,
    /// The PLC refused to copy RAM to ROM.
    CannotCopyRamToRom,
    /// The PLC refused to compress its memory.
    CannotCompress,
    /// The PLC is already in STOP.
    AlreadyStop,
    /// The function is not available on the PLC (`0x8104`).
    FunNotAvailable,
    /// An upload sequence failed.
    UploadSequenceFailed,
    /// The PLC sent more or less data than announced.
    InvalidDataSizeReceived,
    /// The block type is not valid.
    InvalidBlockType,
    /// The block number is not valid.
    InvalidBlockNumber,
    /// The block's size is not valid.
    InvalidBlockSize,
    /// A download sequence failed.
    DownloadSequenceFailed,
    /// The PLC refused to insert (activate) a downloaded block.
    InsertRefused,
    /// The PLC refused to delete a block.
    DeleteRefused,
    /// The function needs a password (`0xD241`).
    NeedPassword,
    /// The password is not valid (`0xD602`).
    InvalidPassword,
    /// There is no password to set or clear (`0xD604`, `0xD605`).
    NoPasswordToSetOrClear,
    /// A job did not complete in time.
    JobTimeout,
    /// A read was only partly carried out.
    PartialDataRead,
    /// The destination buffer is too small for the data.
    BufferTooSmall,
    /// The PLC refused the function (any other refusal code).
    FunctionRefused,
}

impl ErrorKind {
    /// Snap7's numeric code for this kind.
    pub fn code(self) -> u32 {
        use ErrorKind::*;
        match self {
            TcpSocketCreation => 0x0000_0001,
            TcpConnectionTimeout => 0x0000_0002,
            TcpConnectionFailed => 0x0000_0003,
            TcpReceiveTimeout => 0x0000_0004,
            TcpDataReceive => 0x0000_0005,
            TcpSendTimeout => 0x0000_0006,
            TcpDataSend => 0x0000_0007,
            TcpConnectionReset => 0x0000_0008,
            TcpNotConnected => 0x0000_0009,
            TcpUnreachableHost => 0x0000_2751,
            IsoConnect => 0x0001_0000,
            IsoDisconnect => 0x0002_0000,
            IsoInvalidPdu => 0x0003_0000,
            IsoInvalidDataSize => 0x0004_0000,
            IsoShortPacket => 0x0006_0000,
            IsoTooManyFragments => 0x0007_0000,
            IsoPduOverflow => 0x0008_0000,
            IsoSendPacket => 0x0009_0000,
            IsoRecvPacket => 0x000A_0000,
            IsoInvalidParams => 0x000B_0000,
            NegotiatingPdu => 0x0010_0000,
            InvalidParams => 0x0020_0000,
            TooManyItems => 0x0040_0000,
            InvalidWordLen => 0x0050_0000,
            PartialDataWritten => 0x0060_0000,
            SizeOverPdu => 0x0070_0000,
            InvalidPlcAnswer => 0x0080_0000,
            AddressOutOfRange => 0x0090_0000,
            InvalidTransportSize => 0x00A0_0000,
            WriteDataSizeMismatch => 0x00B0_0000,
            ItemNotAvailable => 0x00C0_0000,
            InvalidValue => 0x00D0_0000,
            CannotStartPlc => 0x00E0_0000,
            AlreadyRun => 0x00F0_0000,
            CannotStopPlc => 0x0100_0000,
            CannotCopyRamToRom => 0x0110_0000,
            CannotCompress => 0x0120_0000,
            AlreadyStop => 0x0130_0000,
            FunNotAvailable => 0x0140_0000,
            UploadSequenceFailed => 0x0150_0000,
            InvalidDataSizeReceived => 0x0160_0000,
            InvalidBlockType => 0x0170_0000,
            InvalidBlockNumber => 0x0180_0000,
            InvalidBlockSize => 0x0190_0000,
            DownloadSequenceFailed => 0x01A0_0000,
            InsertRefused => 0x01B0_0000,
            DeleteRefused => 0x01C0_0000,
            NeedPassword => 0x01D0_0000,
            InvalidPassword => 0x01E0_0000,
            NoPasswordToSetOrClear => 0x01F0_0000,
            JobTimeout => 0x0200_0000,
            PartialDataRead => 0x0210_0000,
            BufferTooSmall => 0x0220_0000,
            FunctionRefused => 0x0230_0000,
        }
    }

    /// The kind with Snap7's numeric `code`, if there is one.
    pub fn from_code(code: u32) -> Option<Self> {
        ALL.iter().copied().find(|kind| kind.code() == code)
    }

    /// Whether this is a TCP-level error.
    pub fn is_tcp(self) -> bool {
        self.code() & 0x0000_FFFF != 0
    }

    /// Whether this is an ISO-level error.
    pub fn is_iso(self) -> bool {
        self.code() & 0x000F_0000 != 0
    }

    /// A short description.
    pub fn text(self) -> &'static str {
        use ErrorKind::*;
        match self {
            TcpSocketCreation => "TCP : socket creation failed",
            TcpConnectionTimeout => "TCP : connection timed out",
            TcpConnectionFailed => "TCP : connection failed",
            TcpReceiveTimeout => "TCP : no reply within the receive timeout",
            TcpDataReceive => "TCP : receive error",
            TcpSendTimeout => "TCP : send timed out",
            TcpDataSend => "TCP : send error",
            TcpConnectionReset => "TCP : connection closed by the peer",
            TcpNotConnected => "TCP : not connected",
            TcpUnreachableHost => "TCP : unreachable host",
            IsoConnect => "ISO : connection refused",
            IsoDisconnect => "ISO : disconnected by the peer",
            IsoInvalidPdu => "ISO : invalid PDU",
            IsoInvalidDataSize => "ISO : invalid data size",
            IsoShortPacket => "ISO : short packet",
            IsoTooManyFragments => "ISO : too many fragments",
            IsoPduOverflow => "ISO : PDU overflow",
            IsoSendPacket => "ISO : send packet error",
            IsoRecvPacket => "ISO : receive packet error",
            IsoInvalidParams => "ISO : invalid connection parameters",
            NegotiatingPdu => "CPU : PDU negotiation failed",
            InvalidParams => "CLI : invalid parameter",
            TooManyItems => "CLI : too many items",
            InvalidWordLen => "CLI : invalid word length",
            PartialDataWritten => "CLI : partial data written",
            SizeOverPdu => "CPU : data exceeds the PDU size",
            InvalidPlcAnswer => "CLI : invalid CPU answer",
            AddressOutOfRange => "CPU : address out of range",
            InvalidTransportSize => "CPU : invalid transport size",
            WriteDataSizeMismatch => "CPU : data size mismatch",
            ItemNotAvailable => "CPU : item not available",
            InvalidValue => "CPU : invalid value supplied",
            CannotStartPlc => "CPU : cannot start PLC",
            AlreadyRun => "CPU : PLC already in RUN",
            CannotStopPlc => "CPU : cannot stop PLC",
            CannotCopyRamToRom => "CPU : cannot copy RAM to ROM",
            CannotCompress => "CPU : cannot compress",
            AlreadyStop => "CPU : PLC already in STOP",
            FunNotAvailable => "CPU : function not available",
            UploadSequenceFailed => "CPU : upload sequence failed",
            InvalidDataSizeReceived => "CLI : invalid data size received",
            InvalidBlockType => "CLI : invalid block type",
            InvalidBlockNumber => "CLI : invalid block number",
            InvalidBlockSize => "CLI : invalid block size",
            DownloadSequenceFailed => "CPU : download sequence failed",
            InsertRefused => "CPU : block insert refused",
            DeleteRefused => "CPU : block delete refused",
            NeedPassword => "CPU : function not authorized for the current protection level",
            InvalidPassword => "CPU : invalid password",
            NoPasswordToSetOrClear => "CPU : no password to set or clear",
            JobTimeout => "CLI : job timeout",
            PartialDataRead => "CLI : partial data read",
            BufferTooSmall => "CLI : the buffer supplied is too small",
            FunctionRefused => "CLI : function refused by the CPU",
        }
    }

    /// The kind Snap7 reports for a code the PLC answered with: an item
    /// return code, or a header or parameter error class and code.
    pub fn from_cpu(code: u16) -> Self {
        match code {
            0x0005 => Self::AddressOutOfRange,
            0x0006 => Self::InvalidTransportSize,
            0x0007 => Self::WriteDataSizeMismatch,
            0x000A | 0xD209 => Self::ItemNotAvailable,
            0x8500 => Self::SizeOverPdu,
            0xDC01 => Self::InvalidValue,
            0x8104 => Self::FunNotAvailable,
            0xD241 => Self::NeedPassword,
            0xD602 => Self::InvalidPassword,
            0xD604 | 0xD605 => Self::NoPasswordToSetOrClear,
            _ => Self::FunctionRefused,
        }
    }
}

const ALL: &[ErrorKind] = {
    use ErrorKind::*;
    &[
        TcpSocketCreation,
        TcpConnectionTimeout,
        TcpConnectionFailed,
        TcpReceiveTimeout,
        TcpDataReceive,
        TcpSendTimeout,
        TcpDataSend,
        TcpConnectionReset,
        TcpNotConnected,
        TcpUnreachableHost,
        IsoConnect,
        IsoDisconnect,
        IsoInvalidPdu,
        IsoInvalidDataSize,
        IsoShortPacket,
        IsoTooManyFragments,
        IsoPduOverflow,
        IsoSendPacket,
        IsoRecvPacket,
        IsoInvalidParams,
        NegotiatingPdu,
        InvalidParams,
        TooManyItems,
        InvalidWordLen,
        PartialDataWritten,
        SizeOverPdu,
        InvalidPlcAnswer,
        AddressOutOfRange,
        InvalidTransportSize,
        WriteDataSizeMismatch,
        ItemNotAvailable,
        InvalidValue,
        CannotStartPlc,
        AlreadyRun,
        CannotStopPlc,
        CannotCopyRamToRom,
        CannotCompress,
        AlreadyStop,
        FunNotAvailable,
        UploadSequenceFailed,
        InvalidDataSizeReceived,
        InvalidBlockType,
        InvalidBlockNumber,
        InvalidBlockSize,
        DownloadSequenceFailed,
        InsertRefused,
        DeleteRefused,
        NeedPassword,
        InvalidPassword,
        NoPasswordToSetOrClear,
        JobTimeout,
        PartialDataRead,
        BufferTooSmall,
        FunctionRefused,
    ]
};

/// The text for a code the PLC answered with — an item return code or a
/// header / parameter error class and code — where one is known.
///
/// Sources: the Wireshark S7comm dissector's tables
/// (`epan/dissectors/packet-s7comm.c`); constants only.
pub fn cpu_error_text(code: u16) -> Option<&'static str> {
    Some(match code {
        0x0001 => "hardware error",
        0x0003 => "accessing the object is not allowed",
        0x0005 => "invalid address (out of range)",
        0x0006 => "data type not supported",
        0x0007 => "data type inconsistent",
        0x000A => "object does not exist",
        0x8001 => "the service cannot be performed while the block is in its current status",
        0x8003 => "S7 protocol error: error occurred while transferring the block",
        0x8100 => "service unknown to the remote module",
        0x8104 => "this service is not implemented on the module or a frame error was reported",
        0x8204 => "the type specification for the object is inconsistent",
        0x8205 => "a copied block already exists and is not linked",
        0x8301 => "insufficient memory on the module",
        0x8302 => "too few resources available",
        0x8304 => "no further parallel job possible; there is a resource bottleneck",
        0x8305 => "function not available",
        0x8306 => "insufficient work memory",
        0x8307 => "not enough retentive work memory",
        0x8401 => "invalid service sequence",
        0x8402 => "the service cannot execute owing to the status of the addressed object",
        0x8404 => "the function cannot be performed",
        0x8500 => "wrong frames (the request exceeds the negotiated PDU size)",
        0x8503 => "service cancelled prematurely",
        0x8701 => "error addressing the object (for example an area length error)",
        0x8702 => "the requested service is not supported by the module",
        0x8703 => "access to the object refused",
        0x8704 => "access error: object damaged",
        0xD001 => "protocol error: illegal job number",
        0xD002 => "parameter error: illegal job variant",
        0xD004 => "parameter error: the block is not linked",
        0xD009 => "block not found or the coordination rules were violated",
        0xD201 => "syntax error in the block name",
        0xD202 => "syntax error in the function parameters",
        0xD203 => "syntax error in the block type",
        0xD204 => "no linked block in the storage medium",
        0xD205 => "the object already exists",
        0xD206 => "the object already exists",
        0xD207 => "the block exists in EPROM",
        0xD209 => "the block does not exist",
        0xD20E => "no block available",
        0xD210 => "invalid block number",
        0xD240 => "coordination rules were violated",
        0xD241 => "the function is not permitted in the current protection level",
        0xD242 => "protection violation while processing F-blocks",
        0xD401 => "information function unavailable",
        0xD602 => "invalid password",
        0xD604 => "there is no password to clear",
        0xD605 => "there is no password to set",
        0xDC01 => "invalid value",
        _ => return None,
    })
}

/// An error, with Snap7's code, the PLC's own code when the PLC refused,
/// and a detail where one helps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S7Error {
    kind: ErrorKind,
    cpu: Option<u16>,
    detail: Option<String>,
}

impl S7Error {
    /// An error of `kind`.
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            cpu: None,
            detail: None,
        }
    }

    /// An error of `kind` with a detail.
    pub fn with_detail(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            cpu: None,
            detail: Some(detail.into()),
        }
    }

    /// The PLC answered `code` (item return code or header error); the
    /// kind is Snap7's mapping of it.
    pub fn from_cpu(code: u16) -> Self {
        Self::cpu(ErrorKind::from_cpu(code), code)
    }

    /// The PLC answered `code` to a function that reports its failures
    /// as `kind` (for example [`ErrorKind::CannotStartPlc`]).
    pub fn cpu(kind: ErrorKind, code: u16) -> Self {
        Self {
            kind,
            cpu: Some(code),
            detail: None,
        }
    }

    /// The error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Snap7's numeric error code.
    pub fn code(&self) -> u32 {
        self.kind.code()
    }

    /// The code the PLC answered with, when the PLC refused: an item
    /// return code (below `0x100`) or a header / parameter error class
    /// and code (`0x8104`, `0xD241`, ..).
    pub fn cpu_code(&self) -> Option<u16> {
        self.cpu
    }

    /// Whether the PLC itself answered with this error — the connection
    /// is fine; the PLC refused.
    pub fn is_cpu(&self) -> bool {
        self.cpu.is_some()
    }

    /// Whether the error left the connection in an unknown state (a TCP
    /// or ISO error); the client has then closed it.
    pub fn is_link(&self) -> bool {
        self.kind.is_tcp() || self.kind.is_iso()
    }

    /// The detail, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// A PLC refusal reported as `kind` (the PLC's code kept); any other
    /// error unchanged.
    pub(crate) fn refused_as(mut self, kind: ErrorKind) -> Self {
        if self.cpu.is_some() {
            self.kind = kind;
        }
        self
    }

    pub(crate) fn detailed(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl fmt::Display for S7Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.text())?;
        if let Some(code) = self.cpu {
            match cpu_error_text(code) {
                Some(text) => write!(f, " ({text}, PLC code {code:#06x})")?,
                None => write!(f, " (PLC code {code:#06x})")?,
            }
        }
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for S7Error {}

impl From<ErrorKind> for S7Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

/// Snap7's error text for a numeric code (as `Cli_ErrorText` gives it):
/// the text of the kind with that code, or of each TCP / ISO / client
/// part of a combined code.
pub fn error_text(code: u32) -> String {
    if code == 0 {
        return "OK".to_string();
    }
    if let Some(kind) = ErrorKind::from_code(code) {
        return kind.text().to_string();
    }
    let parts: Vec<&str> = [code & 0x0000_FFFF, code & 0x000F_0000, code & 0xFFF0_0000]
        .into_iter()
        .filter(|part| *part != 0)
        .map(|part| ErrorKind::from_code(part).map_or("unknown error", ErrorKind::text))
        .collect();
    parts.join(", ")
}

/// Classifies an I/O error from a socket operation.
pub(crate) fn from_io(error: &io::Error, timeout: ErrorKind, other: ErrorKind) -> S7Error {
    let kind = match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => timeout,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => ErrorKind::TcpConnectionReset,
        io::ErrorKind::NotConnected => ErrorKind::TcpNotConnected,
        _ => other,
    };
    S7Error::with_detail(kind, error.to_string())
}
