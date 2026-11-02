// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! ISO-on-TCP: RFC 1006 TPKT framing and the ISO 8073 (RFC 905)
//! class-0 transport TPDUs it carries — CR, CC, DR, DT and ER.
//!
//! The codec half ([`Tpdu`], [`encode_tpkt`], [`tpkt_length`]) is pure
//! and public, so a simulated PLC can share it. The connection half
//! (`IsoTcp`) is what [`S7Client`](crate::S7Client) runs on: a TCP
//! stream, deadline-bounded reads, and S7 PDUs sent and reassembled as
//! DT TPDUs of the negotiated TPDU size.
//!
//! Sources: RFC 1006 §6 (TPKT: version 3, a reserved octet, a 16-bit
//! length counting the header), RFC 905 §13 (TPDU codes, CR/CC fixed
//! part, the `0xC0` TPDU-size, `0xC1` calling- and `0xC2` called-TSAP
//! parameters, the class-0 DT header `02 F0 80` with the EOT bit, DR
//! reason codes).

use crate::error::{from_io, ErrorKind, S7Error};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The TPKT version octet RFC 1006 fixes.
pub const TPKT_VERSION: u8 = 3;
/// The TPKT header length.
pub const TPKT_HEADER_LEN: usize = 4;
/// The smallest TPKT RFC 1006 admits (header plus a minimal TPDU).
pub const TPKT_MIN_LEN: usize = 7;
/// The class-0 DT header length (`LI`, `F0`, `EOT|NR`).
pub const DT_HEADER_LEN: usize = 3;
/// The TPDU size code for 1024 octets — what a connection request
/// proposes, as Snap7 does.
pub const TPDU_SIZE_1024: u8 = 0x0A;
/// The largest S7 PDU reassembled from DT TPDUs.
pub const MAX_PDU_REASSEMBLY: usize = 65_535;

const CODE_CR: u8 = 0xE0;
const CODE_CC: u8 = 0xD0;
const CODE_DR: u8 = 0x80;
const CODE_DT: u8 = 0xF0;
const CODE_ER: u8 = 0x70;
const PARAM_TPDU_SIZE: u8 = 0xC0;
const PARAM_CALLING_TSAP: u8 = 0xC1;
const PARAM_CALLED_TSAP: u8 = 0xC2;
/// The DT EOT bit: the last TPDU of a TSDU.
const EOT: u8 = 0x80;

fn invalid(detail: impl Into<String>) -> S7Error {
    S7Error::with_detail(ErrorKind::IsoInvalidPdu, detail)
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Wraps one TPDU in a TPKT.
pub fn encode_tpkt(tpdu: &[u8]) -> Result<Vec<u8>, S7Error> {
    let total = tpdu.len() + TPKT_HEADER_LEN;
    let length = u16::try_from(total).map_err(|_| {
        S7Error::with_detail(
            ErrorKind::IsoPduOverflow,
            format!("a TPKT carries at most 65535 octets; this one would be {total}"),
        )
    })?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&[TPKT_VERSION, 0]);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(tpdu);
    Ok(frame)
}

/// The total length a TPKT header announces, header included.
pub fn tpkt_length(header: &[u8; TPKT_HEADER_LEN]) -> Result<usize, S7Error> {
    if header[0] != TPKT_VERSION {
        return Err(invalid(format!(
            "TPKT version {:#04x}, expected 3 — the peer is not speaking ISO-on-TCP",
            header[0]
        )));
    }
    let length = usize::from(be16(header, 2));
    if length < TPKT_MIN_LEN {
        return Err(S7Error::with_detail(
            ErrorKind::IsoShortPacket,
            format!("TPKT length {length} is below the minimum of {TPKT_MIN_LEN}"),
        ));
    }
    Ok(length)
}

/// The TPDU size a size code stands for, for the codes class 0 admits
/// (7 = 128 … 11 = 2048 octets).
pub fn tpdu_size(code: u8) -> Option<usize> {
    (7..=11).contains(&code).then(|| 1usize << code)
}

/// The text RFC 905 gives a DR reason code.
pub fn disconnect_reason(reason: u8) -> &'static str {
    match reason {
        0 => "reason not specified",
        1 => "congestion at TSAP",
        2 => "session entity not attached to TSAP",
        3 => "address unknown",
        128 => "normal disconnect initiated by the session entity",
        129 => "remote transport entity congestion at connect request time",
        130 => "connection negotiation failed",
        131 => "duplicate source reference",
        132 => "mismatched references",
        133 => "protocol error",
        135 => "reference overflow",
        136 => "connection request refused on this network connection",
        138 => "header or parameter length invalid",
        _ => "unknown reason",
    }
}

/// The variable part of a CR or CC TPDU.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CotpParams {
    /// The TPDU size code (`0xC0`), when present.
    pub tpdu_size: Option<u8>,
    /// The calling TSAP (`0xC1`).
    pub calling_tsap: Option<Vec<u8>>,
    /// The called TSAP (`0xC2`).
    pub called_tsap: Option<Vec<u8>>,
}

impl CotpParams {
    fn encode(&self, out: &mut Vec<u8>) {
        if let Some(code) = self.tpdu_size {
            out.extend_from_slice(&[PARAM_TPDU_SIZE, 1, code]);
        }
        for (code, value) in [
            (PARAM_CALLING_TSAP, &self.calling_tsap),
            (PARAM_CALLED_TSAP, &self.called_tsap),
        ] {
            if let Some(value) = value {
                out.push(code);
                out.push(value.len() as u8);
                out.extend_from_slice(value);
            }
        }
    }

    fn decode(mut bytes: &[u8]) -> Result<Self, S7Error> {
        let mut params = Self::default();
        while !bytes.is_empty() {
            if bytes.len() < 2 {
                return Err(invalid("a COTP parameter is cut off after its code"));
            }
            let (code, length) = (bytes[0], usize::from(bytes[1]));
            let Some(value) = bytes.get(2..2 + length) else {
                return Err(invalid(format!(
                    "COTP parameter {code:#04x} announces {length} octets but {} remain",
                    bytes.len() - 2
                )));
            };
            match code {
                PARAM_TPDU_SIZE if length == 1 => params.tpdu_size = Some(value[0]),
                PARAM_TPDU_SIZE => {
                    return Err(invalid(format!(
                        "the COTP TPDU-size parameter has length {length}, expected 1"
                    )))
                }
                PARAM_CALLING_TSAP => params.calling_tsap = Some(value.to_vec()),
                PARAM_CALLED_TSAP => params.called_tsap = Some(value.to_vec()),
                // Other parameters (version, checksum, ..) do not apply
                // to class 0 and are skipped.
                _ => {}
            }
            bytes = &bytes[2 + length..];
        }
        Ok(params)
    }
}

/// One ISO 8073 TPDU, as far as a class-0 S7 connection uses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tpdu {
    /// CR — connection request.
    ConnectionRequest {
        /// The initiator's reference.
        src_ref: u16,
        /// The class and option octet (`0x00` for class 0).
        class: u8,
        /// The variable part.
        params: CotpParams,
    },
    /// CC — connection confirm.
    ConnectionConfirm {
        /// The initiator's reference, echoed.
        dst_ref: u16,
        /// The responder's reference.
        src_ref: u16,
        /// The selected class and option.
        class: u8,
        /// The variable part.
        params: CotpParams,
    },
    /// DR — disconnect request: the responder refuses or ends the
    /// connection.
    DisconnectRequest {
        /// The peer's reference.
        dst_ref: u16,
        /// The sender's reference.
        src_ref: u16,
        /// The RFC 905 reason code.
        reason: u8,
    },
    /// DT — one data TPDU of a TSDU.
    Data {
        /// Whether this TPDU ends the TSDU.
        eot: bool,
        /// The user data.
        payload: Vec<u8>,
    },
    /// ER — TPDU error: the peer could not parse a TPDU.
    Error {
        /// The peer's reference.
        dst_ref: u16,
        /// The reject cause.
        cause: u8,
    },
}

impl Tpdu {
    /// The TPDU's bytes, length indicator first.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8];
        match self {
            Self::ConnectionRequest {
                src_ref,
                class,
                params,
            } => {
                out.push(CODE_CR);
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&src_ref.to_be_bytes());
                out.push(*class);
                params.encode(&mut out);
            }
            Self::ConnectionConfirm {
                dst_ref,
                src_ref,
                class,
                params,
            } => {
                out.push(CODE_CC);
                out.extend_from_slice(&dst_ref.to_be_bytes());
                out.extend_from_slice(&src_ref.to_be_bytes());
                out.push(*class);
                params.encode(&mut out);
            }
            Self::DisconnectRequest {
                dst_ref,
                src_ref,
                reason,
            } => {
                out.push(CODE_DR);
                out.extend_from_slice(&dst_ref.to_be_bytes());
                out.extend_from_slice(&src_ref.to_be_bytes());
                out.push(*reason);
            }
            Self::Data { eot, payload } => {
                out.push(CODE_DT);
                out.push(if *eot { EOT } else { 0 });
                out[0] = (out.len() - 1) as u8;
                out.extend_from_slice(payload);
                return out;
            }
            Self::Error { dst_ref, cause } => {
                out.push(CODE_ER);
                out.extend_from_slice(&dst_ref.to_be_bytes());
                out.push(*cause);
            }
        }
        out[0] = (out.len() - 1) as u8;
        out
    }

    /// Reads one TPDU — the bytes a TPKT carried after its header.
    pub fn decode(bytes: &[u8]) -> Result<Self, S7Error> {
        if bytes.len() < 2 {
            return Err(S7Error::with_detail(
                ErrorKind::IsoShortPacket,
                "a TPDU needs at least a length indicator and a code",
            ));
        }
        let header_len = usize::from(bytes[0]) + 1;
        if header_len < 2 {
            return Err(invalid(
                "a COTP length indicator of 0 leaves no room for the TPDU code",
            ));
        }
        if header_len > bytes.len() {
            return Err(invalid(format!(
                "the COTP length indicator announces a {header_len}-octet header in a {}-octet TPDU",
                bytes.len()
            )));
        }
        let header = &bytes[..header_len];
        let code = header[1];
        let need = |len: usize, what: &str| {
            if header_len < len {
                Err(invalid(format!(
                    "a COTP {what} header needs {len} octets, found {header_len}"
                )))
            } else {
                Ok(())
            }
        };
        match code & 0xF0 {
            CODE_CR => {
                need(7, "CR")?;
                Ok(Self::ConnectionRequest {
                    src_ref: be16(header, 4),
                    class: header[6],
                    params: CotpParams::decode(&header[7..])?,
                })
            }
            CODE_CC => {
                need(7, "CC")?;
                Ok(Self::ConnectionConfirm {
                    dst_ref: be16(header, 2),
                    src_ref: be16(header, 4),
                    class: header[6],
                    params: CotpParams::decode(&header[7..])?,
                })
            }
            _ if code == CODE_DR => {
                need(7, "DR")?;
                Ok(Self::DisconnectRequest {
                    dst_ref: be16(header, 2),
                    src_ref: be16(header, 4),
                    reason: header[6],
                })
            }
            _ if code == CODE_DT => {
                need(DT_HEADER_LEN, "DT")?;
                Ok(Self::Data {
                    eot: header[2] & EOT != 0,
                    payload: bytes[header_len..].to_vec(),
                })
            }
            _ if code == CODE_ER => {
                need(5, "ER")?;
                Ok(Self::Error {
                    dst_ref: be16(header, 2),
                    cause: header[4],
                })
            }
            _ => Err(invalid(format!(
                "COTP TPDU code {code:#04x} is not one a class-0 connection uses"
            ))),
        }
    }
}

/// Fills `buf` or fails once `deadline` passes: nothing at all is a
/// receive timeout, a part is a packet that broke off.
fn read_exact_until(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), S7Error> {
    let mut filled = 0;
    let wanted = buf.len();
    let broke_off = |filled: usize| {
        if filled == 0 {
            S7Error::new(ErrorKind::TcpReceiveTimeout)
        } else {
            S7Error::with_detail(
                ErrorKind::IsoRecvPacket,
                format!("the packet broke off after {filled} of {wanted} octets"),
            )
        }
    };
    while filled < wanted {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(broke_off(filled));
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| from_io(&e, ErrorKind::TcpDataReceive, ErrorKind::TcpDataReceive))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(S7Error::with_detail(
                    ErrorKind::TcpConnectionReset,
                    "the peer closed the connection",
                ))
            }
            Ok(read) => filled += read,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(broke_off(filled))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(from_io(
                    &e,
                    ErrorKind::TcpReceiveTimeout,
                    ErrorKind::TcpDataReceive,
                ))
            }
        }
    }
    Ok(())
}

/// Reads one TPKT and returns its TPDU. Once a header is in, running out
/// of time is a packet that broke off.
fn read_tpdu(stream: &mut TcpStream, deadline: Instant) -> Result<Tpdu, S7Error> {
    let mut header = [0u8; TPKT_HEADER_LEN];
    read_exact_until(stream, &mut header, deadline)?;
    let length = tpkt_length(&header)?;
    let mut body = vec![0u8; length - TPKT_HEADER_LEN];
    read_exact_until(stream, &mut body, deadline).map_err(|e| {
        if e.kind() == ErrorKind::TcpReceiveTimeout {
            S7Error::with_detail(
                ErrorKind::IsoRecvPacket,
                "the packet broke off after its TPKT header",
            )
        } else {
            e
        }
    })?;
    Tpdu::decode(&body)
}

/// Resolves `host` (a name, an IPv4 address, or an IPv6 address with or
/// without brackets) on `port`.
fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, S7Error> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let addresses: Vec<SocketAddr> = (bare, port)
        .to_socket_addrs()
        .map_err(|e| {
            S7Error::with_detail(
                ErrorKind::TcpUnreachableHost,
                format!("cannot resolve {host}: {e}"),
            )
        })?
        .collect();
    if addresses.is_empty() {
        return Err(S7Error::with_detail(
            ErrorKind::TcpUnreachableHost,
            format!("{host} resolves to no address"),
        ));
    }
    Ok(addresses)
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub(crate) struct IsoParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub local_tsap: u16,
    pub remote_tsap: u16,
    pub connect_timeout: Duration,
    pub recv_timeout: Duration,
    pub send_timeout: Duration,
}

/// An ISO-on-TCP connection: TCP plus the negotiated TPDU size.
#[derive(Debug)]
pub(crate) struct IsoTcp {
    stream: TcpStream,
    tpdu_size: usize,
}

impl IsoTcp {
    /// Connects over TCP (trying each address `host` resolves to) and
    /// runs the CR/CC exchange, each step bounded by its timeout.
    pub fn connect(params: &IsoParams<'_>) -> Result<Self, S7Error> {
        let mut last = None;
        let mut stream = None;
        for address in resolve(params.host, params.port)? {
            match TcpStream::connect_timeout(&address, params.connect_timeout) {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(e) => {
                    let kind = match e.kind() {
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                            ErrorKind::TcpConnectionTimeout
                        }
                        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                            ErrorKind::TcpUnreachableHost
                        }
                        _ => ErrorKind::TcpConnectionFailed,
                    };
                    last = Some(S7Error::with_detail(kind, format!("{address}: {e}")));
                }
            }
        }
        let Some(mut stream) = stream else {
            return Err(last.unwrap_or_else(|| S7Error::new(ErrorKind::TcpConnectionFailed)));
        };
        // A job is a few dozen octets; Nagle would hold it back.
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(params.send_timeout));
        let request = Tpdu::ConnectionRequest {
            src_ref: 1,
            class: 0,
            params: CotpParams {
                tpdu_size: Some(TPDU_SIZE_1024),
                calling_tsap: Some(params.local_tsap.to_be_bytes().to_vec()),
                called_tsap: Some(params.remote_tsap.to_be_bytes().to_vec()),
            },
        };
        stream
            .write_all(&encode_tpkt(&request.encode())?)
            .map_err(|e| from_io(&e, ErrorKind::TcpSendTimeout, ErrorKind::TcpDataSend))?;
        let tsaps = format!(
            "local TSAP {:#06x}, remote TSAP {:#06x}",
            params.local_tsap, params.remote_tsap
        );
        let answer = read_tpdu(&mut stream, Instant::now() + params.recv_timeout).map_err(|e| {
            if e.kind() == ErrorKind::TcpConnectionReset {
                // A PLC that does not serve the TSAP typically drops the
                // TCP connection instead of answering.
                S7Error::with_detail(
                    ErrorKind::IsoConnect,
                    format!(
                        "the peer closed the connection during the connection request ({tsaps})"
                    ),
                )
            } else {
                e
            }
        })?;
        let tpdu_size = match answer {
            Tpdu::ConnectionConfirm { params: cc, .. } => {
                let code = cc.tpdu_size.unwrap_or(7);
                let size = tpdu_size(code).ok_or_else(|| {
                    invalid(format!(
                        "the connection confirm selects TPDU size code {code:#04x}, which class 0 does not admit"
                    ))
                })?;
                size.min(1024)
            }
            Tpdu::DisconnectRequest { reason, .. } => {
                return Err(S7Error::with_detail(
                    ErrorKind::IsoConnect,
                    format!(
                        "{} (COTP DR reason {reason}; {tsaps})",
                        disconnect_reason(reason)
                    ),
                ));
            }
            other => {
                return Err(S7Error::with_detail(
                    ErrorKind::IsoConnect,
                    format!("expected a COTP connection confirm, found {other:?}"),
                ));
            }
        };
        Ok(Self { stream, tpdu_size })
    }

    /// Sends one S7 PDU as DT TPDUs no larger than the TPDU size.
    pub fn send(&mut self, pdu: &[u8]) -> Result<(), S7Error> {
        let room = self.tpdu_size - DT_HEADER_LEN;
        let chunks: Vec<&[u8]> = if pdu.is_empty() {
            vec![pdu]
        } else {
            pdu.chunks(room).collect()
        };
        let mut frames =
            Vec::with_capacity(pdu.len() + chunks.len() * (TPKT_HEADER_LEN + DT_HEADER_LEN));
        for (index, chunk) in chunks.iter().enumerate() {
            let tpdu = Tpdu::Data {
                eot: index + 1 == chunks.len(),
                payload: chunk.to_vec(),
            };
            frames.extend(encode_tpkt(&tpdu.encode())?);
        }
        self.stream
            .write_all(&frames)
            .map_err(|e| from_io(&e, ErrorKind::TcpSendTimeout, ErrorKind::TcpDataSend))
    }

    /// Receives one S7 PDU, reassembling DT TPDUs up to the EOT, by
    /// `deadline`.
    pub fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, S7Error> {
        let mut payload = Vec::new();
        loop {
            match read_tpdu(&mut self.stream, deadline)? {
                Tpdu::Data { eot, payload: part } => {
                    payload.extend_from_slice(&part);
                    if eot {
                        return Ok(payload);
                    }
                    if payload.len() > MAX_PDU_REASSEMBLY {
                        return Err(S7Error::with_detail(
                            ErrorKind::IsoTooManyFragments,
                            "a PDU of more than 65535 octets without an end",
                        ));
                    }
                }
                Tpdu::DisconnectRequest { reason, .. } => {
                    return Err(S7Error::with_detail(
                        ErrorKind::IsoDisconnect,
                        format!("{} (COTP DR reason {reason})", disconnect_reason(reason)),
                    ));
                }
                other => {
                    return Err(invalid(format!("expected a COTP DT, found {other:?}")));
                }
            }
        }
    }

    /// Closes the connection.
    pub fn close(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
