// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! The S7 PDU codec: the S7comm header, Setup Communication, the S7ANY
//! item address, Read Var / Write Var in both directions, and the
//! UserData parameter and data framing.
//!
//! The codec is pure and public: [`S7Client`](crate::S7Client) builds on
//! it, and a simulated PLC can use the server half ([`Job::decode`],
//! [`read_var_response`], [`write_var_response`]).
//!
//! Sources: the Wireshark S7comm dissector
//! (`epan/dissectors/packet-s7comm.c`) for the header layout, ROSCTR,
//! error class and code, the S7ANY address, area codes, transport sizes
//! and which count their length in bits, the fill byte after an
//! odd-length data item that is not the last, item return codes and the
//! UserData parameter head. Constants only; no code was copied.

use crate::error::{ErrorKind, S7Error};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The S7comm protocol identifier.
pub const S7_ID: u8 = 0x32;
/// A Job or UserData header: no error field.
pub const JOB_HEADER_LEN: usize = 10;
/// An Ack / Ack_Data header: with the error class and code.
pub const ACK_HEADER_LEN: usize = 12;
/// One S7ANY item specification.
pub const ITEM_SPEC_LEN: usize = 12;
/// The header of one data item (return code, transport size, length).
pub const DATA_ITEM_HEADER_LEN: usize = 4;
/// The most items one Read or Write Var job carries (Snap7's `MaxVars`).
pub const MAX_VARS: usize = 20;
/// Bytes a Read Var request costs before its items.
pub const READ_REQUEST_FIXED: usize = JOB_HEADER_LEN + 2;
/// Bytes a Read Var response costs before its data items.
pub const READ_RESPONSE_FIXED: usize = ACK_HEADER_LEN + 2;
/// Bytes a Write Var request costs before its items.
pub const WRITE_REQUEST_FIXED: usize = JOB_HEADER_LEN + 2;
/// The largest byte offset the 24-bit S7ANY bit address can carry.
pub const MAX_BYTE_ADDRESS: u32 = 0x1F_FFFF;

/// Process inputs (I / E).
pub const S7_AREA_PE: u8 = 0x81;
/// Process outputs (Q / A).
pub const S7_AREA_PA: u8 = 0x82;
/// Merkers / bit memory (M).
pub const S7_AREA_MK: u8 = 0x83;
/// Data blocks (DB).
pub const S7_AREA_DB: u8 = 0x84;
/// Counters (C / Z).
pub const S7_AREA_CT: u8 = 0x1C;
/// Timers (T).
pub const S7_AREA_TM: u8 = 0x1D;

/// Bit.
pub const S7_WL_BIT: u8 = 0x01;
/// Byte.
pub const S7_WL_BYTE: u8 = 0x02;
/// Char.
pub const S7_WL_CHAR: u8 = 0x03;
/// Word (2 bytes).
pub const S7_WL_WORD: u8 = 0x04;
/// Int (2 bytes).
pub const S7_WL_INT: u8 = 0x05;
/// Double word (4 bytes).
pub const S7_WL_DWORD: u8 = 0x06;
/// Double int (4 bytes).
pub const S7_WL_DINT: u8 = 0x07;
/// Real (4 bytes).
pub const S7_WL_REAL: u8 = 0x08;
/// Counter (2 bytes).
pub const S7_WL_COUNTER: u8 = 0x1C;
/// Timer (2 bytes).
pub const S7_WL_TIMER: u8 = 0x1D;

/// The size in bytes of one element of word length `word_len`, or
/// `None` for an unknown word length.
pub fn word_size(word_len: u8) -> Option<usize> {
    Some(match word_len {
        S7_WL_BIT | S7_WL_BYTE | S7_WL_CHAR => 1,
        S7_WL_WORD | S7_WL_INT | S7_WL_COUNTER | S7_WL_TIMER => 2,
        S7_WL_DWORD | S7_WL_DINT | S7_WL_REAL => 4,
        _ => return None,
    })
}

/// Whether `area` is one of the areas Read / Write Var address.
pub fn is_area(area: u8) -> bool {
    matches!(
        area,
        S7_AREA_PE | S7_AREA_PA | S7_AREA_MK | S7_AREA_DB | S7_AREA_CT | S7_AREA_TM
    )
}

/// Function codes of Job PDUs.
pub mod function {
    /// Setup Communication.
    pub const SETUP: u8 = 0xF0;
    /// Read Var.
    pub const READ_VAR: u8 = 0x04;
    /// Write Var.
    pub const WRITE_VAR: u8 = 0x05;
    /// Request download.
    pub const REQUEST_DOWNLOAD: u8 = 0x1A;
    /// Download block (sent by the PLC).
    pub const DOWNLOAD_BLOCK: u8 = 0x1B;
    /// Download ended (sent by the PLC).
    pub const DOWNLOAD_ENDED: u8 = 0x1C;
    /// Start upload.
    pub const START_UPLOAD: u8 = 0x1D;
    /// Upload.
    pub const UPLOAD: u8 = 0x1E;
    /// End upload.
    pub const END_UPLOAD: u8 = 0x1F;
    /// PI service (start, copy RAM to ROM, compress, insert, delete).
    pub const PI_SERVICE: u8 = 0x28;
    /// PLC stop.
    pub const PLC_STOP: u8 = 0x29;
}

/// Data-item transport sizes (in a Read Var response or a Write Var
/// request's data).
pub mod transport {
    /// No data (an error item).
    pub const NULL: u8 = 0x00;
    /// Bit; the length counts bits.
    pub const BIT: u8 = 0x03;
    /// Byte, word or double word; the length counts bits.
    pub const BYTE: u8 = 0x04;
    /// Integer; the length counts bits.
    pub const INT: u8 = 0x05;
    /// Double integer; the length counts bytes.
    pub const DINT: u8 = 0x06;
    /// Real; the length counts bytes.
    pub const REAL: u8 = 0x07;
    /// Octet string (counters, timers); the length counts bytes.
    pub const OCTET: u8 = 0x09;
}

/// Item return codes.
pub mod item {
    /// Reserved — what a Write Var request's data items carry.
    pub const RESERVED: u8 = 0x00;
    /// Hardware error.
    pub const HARDWARE_FAULT: u8 = 0x01;
    /// Accessing the object is not allowed.
    pub const ACCESS_DENIED: u8 = 0x03;
    /// Invalid address (out of range).
    pub const OUT_OF_RANGE: u8 = 0x05;
    /// Data type not supported.
    pub const TYPE_NOT_SUPPORTED: u8 = 0x06;
    /// Data type inconsistent.
    pub const TYPE_INCONSISTENT: u8 = 0x07;
    /// Object does not exist.
    pub const NOT_FOUND: u8 = 0x0A;
    /// Success.
    pub const SUCCESS: u8 = 0xFF;
}

/// The data-item transport size Snap7 sends for word length `word_len`.
pub fn data_transport(word_len: u8) -> u8 {
    match word_len {
        S7_WL_BIT => transport::BIT,
        S7_WL_INT | S7_WL_DINT => transport::INT,
        S7_WL_REAL => transport::REAL,
        S7_WL_COUNTER | S7_WL_TIMER => transport::OCTET,
        _ => transport::BYTE,
    }
}

/// The byte length of a data item's payload from its transport size and
/// announced length.
pub fn data_len(transport_size: u8, length: u16) -> Result<usize, S7Error> {
    let length = usize::from(length);
    match transport_size {
        transport::BIT | transport::BYTE | transport::INT => Ok(length.div_ceil(8)),
        transport::DINT | transport::REAL | transport::OCTET => Ok(length),
        other => Err(answer(format!(
            "data item transport size {other:#04x} is not known"
        ))),
    }
}

fn length_field(transport_size: u8, len: usize) -> u16 {
    match transport_size {
        transport::BIT => len.min(1) as u16,
        transport::BYTE | transport::INT => (len * 8) as u16,
        _ => len as u16,
    }
}

pub(crate) fn answer(detail: impl Into<String>) -> S7Error {
    S7Error::with_detail(ErrorKind::InvalidPlcAnswer, detail)
}

pub(crate) fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

pub(crate) fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Bytes as spaced hex, for messages.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// The S7comm header
// ---------------------------------------------------------------------------

/// The S7comm message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rosctr {
    /// `0x01` — a request.
    Job,
    /// `0x02` — an acknowledgement without data.
    Ack,
    /// `0x03` — an acknowledgement with parameters and data.
    AckData,
    /// `0x07` — user data (SZL, clock, blocks, security).
    UserData,
}

impl Rosctr {
    /// The wire value.
    pub fn code(self) -> u8 {
        match self {
            Self::Job => 0x01,
            Self::Ack => 0x02,
            Self::AckData => 0x03,
            Self::UserData => 0x07,
        }
    }

    /// The type for a wire value.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x01 => Self::Job,
            0x02 => Self::Ack,
            0x03 => Self::AckData,
            0x07 => Self::UserData,
            _ => return None,
        })
    }

    /// The header length of a PDU of this type.
    pub fn header_len(self) -> usize {
        match self {
            Self::Ack | Self::AckData => ACK_HEADER_LEN,
            Self::Job | Self::UserData => JOB_HEADER_LEN,
        }
    }
}

/// One S7comm PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// The message type.
    pub rosctr: Rosctr,
    /// The PDU reference that pairs a response with its request.
    pub pdu_ref: u16,
    /// An Ack / Ack_Data's error class and code (`0` when none).
    pub error: u16,
    /// The parameter part.
    pub param: Vec<u8>,
    /// The data part.
    pub data: Vec<u8>,
}

impl Pdu {
    /// A request of type `rosctr`.
    pub fn request(rosctr: Rosctr, pdu_ref: u16, param: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            rosctr,
            pdu_ref,
            error: 0,
            param,
            data,
        }
    }

    /// The PDU's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACK_HEADER_LEN + self.param.len() + self.data.len());
        out.push(S7_ID);
        out.push(self.rosctr.code());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.pdu_ref.to_be_bytes());
        out.extend_from_slice(&(self.param.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        if self.rosctr.header_len() == ACK_HEADER_LEN {
            out.extend_from_slice(&self.error.to_be_bytes());
        }
        out.extend_from_slice(&self.param);
        out.extend_from_slice(&self.data);
        out
    }

    /// Reads one PDU — the payload of a TSDU. Octets beyond the lengths
    /// the header announces are ignored.
    pub fn decode(bytes: &[u8]) -> Result<Self, S7Error> {
        if bytes.len() < JOB_HEADER_LEN {
            return Err(S7Error::with_detail(
                ErrorKind::IsoShortPacket,
                format!(
                    "an S7 PDU needs a {JOB_HEADER_LEN}-octet header, found {} octets",
                    bytes.len()
                ),
            ));
        }
        if bytes[0] != S7_ID {
            return Err(answer(format!(
                "S7 protocol id {:#04x}, expected 0x32",
                bytes[0]
            )));
        }
        let rosctr = Rosctr::from_code(bytes[1])
            .ok_or_else(|| answer(format!("unknown S7 ROSCTR {:#04x}", bytes[1])))?;
        let header_len = rosctr.header_len();
        if bytes.len() < header_len {
            return Err(S7Error::with_detail(
                ErrorKind::IsoShortPacket,
                format!(
                    "an S7 response needs a {header_len}-octet header, found {} octets",
                    bytes.len()
                ),
            ));
        }
        let param_len = usize::from(be16(bytes, 6));
        let data_len = usize::from(be16(bytes, 8));
        if bytes.len() < header_len + param_len + data_len {
            return Err(S7Error::with_detail(
                ErrorKind::IsoInvalidDataSize,
                format!(
                    "the S7 header announces {param_len} parameter and {data_len} data octets, \
                     but {} follow the header",
                    bytes.len() - header_len
                ),
            ));
        }
        Ok(Self {
            rosctr,
            pdu_ref: be16(bytes, 4),
            error: if header_len == ACK_HEADER_LEN {
                be16(bytes, 10)
            } else {
                0
            },
            param: bytes[header_len..header_len + param_len].to_vec(),
            data: bytes[header_len + param_len..header_len + param_len + data_len].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Setup Communication
// ---------------------------------------------------------------------------

/// Setup Communication's parameters, in a request or its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// Parallel jobs the calling side may have outstanding.
    pub max_amq_calling: u16,
    /// Parallel jobs the called side may have outstanding.
    pub max_amq_called: u16,
    /// The PDU length — proposed in the request, negotiated in the answer.
    pub pdu_length: u16,
}

impl Setup {
    /// The parameter part.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![function::SETUP, 0];
        out.extend_from_slice(&self.max_amq_calling.to_be_bytes());
        out.extend_from_slice(&self.max_amq_called.to_be_bytes());
        out.extend_from_slice(&self.pdu_length.to_be_bytes());
        out
    }

    /// Reads the parameter part.
    pub fn decode(param: &[u8]) -> Result<Self, S7Error> {
        if param.len() < 8 || param[0] != function::SETUP {
            return Err(answer(format!(
                "a Setup Communication parameter is 8 octets starting 0xF0, found {}",
                hex(param)
            )));
        }
        Ok(Self {
            max_amq_calling: be16(param, 2),
            max_amq_called: be16(param, 4),
            pdu_length: be16(param, 6),
        })
    }
}

// ---------------------------------------------------------------------------
// Read Var / Write Var
// ---------------------------------------------------------------------------

/// One S7ANY item: where a Read or Write Var item points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemSpec {
    /// The request transport size — the word length (`S7_WL_*`).
    pub word_len: u8,
    /// How many elements of `word_len`.
    pub count: u16,
    /// The DB number, `0` outside the DB area.
    pub db: u16,
    /// The area code (`S7_AREA_*`).
    pub area: u8,
    /// The 24-bit address: a bit address (`byte * 8 + bit`) for every
    /// word length except counters and timers, which carry the element
    /// number.
    pub address: u32,
}

impl ItemSpec {
    /// The item for `amount` elements of `word_len` at `start` — a bit
    /// number (`byte * 8 + bit`) for [`S7_WL_BIT`], an element number for
    /// counters and timers, a byte offset otherwise.
    pub fn new(area: u8, db: u16, start: u32, amount: u16, word_len: u8) -> Self {
        let address = match word_len {
            S7_WL_BIT | S7_WL_COUNTER | S7_WL_TIMER => start,
            _ => start << 3,
        };
        Self {
            word_len,
            count: amount,
            db: if area == S7_AREA_DB { db } else { 0 },
            area,
            address: address & 0x00FF_FFFF,
        }
    }

    /// The first byte the item addresses (the element number for
    /// counters and timers).
    pub fn byte(&self) -> u32 {
        match self.word_len {
            S7_WL_COUNTER | S7_WL_TIMER => self.address,
            _ => self.address >> 3,
        }
    }

    /// The bit within [`byte`](Self::byte) (meaningful for a bit item).
    pub fn bit(&self) -> u8 {
        (self.address & 7) as u8
    }

    /// The bytes the item's data spans.
    pub fn byte_len(&self) -> usize {
        match self.word_len {
            S7_WL_BIT => 1,
            word_len => usize::from(self.count) * word_size(word_len).unwrap_or(1),
        }
    }

    /// Appends the 12 octets.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[0x12, 0x0A, 0x10, self.word_len]);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.db.to_be_bytes());
        out.push(self.area);
        out.extend_from_slice(&self.address.to_be_bytes()[1..]);
    }

    /// Reads 12 octets.
    pub fn decode(bytes: &[u8]) -> Result<Self, S7Error> {
        if bytes.len() < ITEM_SPEC_LEN || bytes[0] != 0x12 || bytes[1] != 0x0A || bytes[2] != 0x10 {
            return Err(answer(format!(
                "an item specification must be 12 octets starting 12 0A 10 (S7ANY), found {}",
                hex(&bytes[..bytes.len().min(ITEM_SPEC_LEN)])
            )));
        }
        Ok(Self {
            word_len: bytes[3],
            count: be16(bytes, 4),
            db: be16(bytes, 6),
            area: bytes[8],
            address: u32::from_be_bytes([0, bytes[9], bytes[10], bytes[11]]),
        })
    }
}

/// How one Read Var item was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemResult {
    /// The item's bytes.
    Data(Vec<u8>),
    /// A return code other than success.
    Error(u8),
}

/// Appends one data item; `last` suppresses the fill byte after an
/// odd-length payload.
pub fn encode_data_item(out: &mut Vec<u8>, code: u8, transport_size: u8, bytes: &[u8], last: bool) {
    out.extend_from_slice(&[code, transport_size]);
    out.extend_from_slice(&length_field(transport_size, bytes.len()).to_be_bytes());
    out.extend_from_slice(bytes);
    if bytes.len() % 2 == 1 && !last {
        out.push(0);
    }
}

/// Reads `count` data items — a Read Var response's data part, or a
/// Write Var request's. An item whose return code is neither success nor
/// reserved is its four header octets alone, whatever its length says.
pub fn decode_data_items(data: &[u8], count: usize) -> Result<Vec<(u8, Vec<u8>)>, S7Error> {
    let mut items = Vec::with_capacity(count);
    let mut at = 0;
    for index in 0..count {
        let Some(header) = data.get(at..at + DATA_ITEM_HEADER_LEN) else {
            return Err(answer(format!(
                "data item {} of {count} is cut off",
                index + 1
            )));
        };
        let code = header[0];
        at += DATA_ITEM_HEADER_LEN;
        if code != item::SUCCESS && code != item::RESERVED {
            items.push((code, Vec::new()));
            continue;
        }
        let len = data_len(header[1], be16(header, 2))?;
        let Some(bytes) = data.get(at..at + len) else {
            return Err(answer(format!(
                "data item {} of {count} announces {len} octets but {} remain",
                index + 1,
                data.len() - at
            )));
        };
        items.push((code, bytes.to_vec()));
        at += len;
        if len % 2 == 1 && index + 1 < count {
            at += 1;
        }
    }
    if at < data.len() {
        return Err(answer(format!(
            "{} octets follow the last of {count} data items",
            data.len() - at
        )));
    }
    Ok(items)
}

/// A Read Var job's parameter part.
pub fn read_var_param(items: &[ItemSpec]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + items.len() * ITEM_SPEC_LEN);
    out.extend_from_slice(&[function::READ_VAR, items.len() as u8]);
    for spec in items {
        spec.encode(&mut out);
    }
    out
}

/// A Write Var job's parameter and data parts.
pub fn write_var_request(items: &[(ItemSpec, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut param = vec![function::WRITE_VAR, items.len() as u8];
    let mut data = Vec::new();
    for (index, (spec, bytes)) in items.iter().enumerate() {
        spec.encode(&mut param);
        encode_data_item(
            &mut data,
            item::RESERVED,
            data_transport(spec.word_len),
            bytes,
            index + 1 == items.len(),
        );
    }
    (param, data)
}

fn item_count(param: &[u8], function: u8, what: &str) -> Result<usize, S7Error> {
    if param.len() != 2 || param[0] != function {
        return Err(answer(format!(
            "a {what} response's parameter is {function:02x} plus an item count, found {}",
            hex(param)
        )));
    }
    Ok(usize::from(param[1]))
}

/// Reads a Read Var response for a request of `expected` items.
pub fn decode_read_var_response(pdu: &Pdu, expected: usize) -> Result<Vec<ItemResult>, S7Error> {
    let count = item_count(&pdu.param, function::READ_VAR, "Read Var")?;
    if count != expected {
        return Err(answer(format!(
            "the Read Var response answers {count} items; the request asked {expected}"
        )));
    }
    Ok(decode_data_items(&pdu.data, count)?
        .into_iter()
        .map(|(code, bytes)| match code {
            item::SUCCESS => ItemResult::Data(bytes),
            code => ItemResult::Error(code),
        })
        .collect())
}

/// Reads a Write Var response for a request of `expected` items: each
/// item's return code.
pub fn decode_write_var_response(pdu: &Pdu, expected: usize) -> Result<Vec<u8>, S7Error> {
    let count = item_count(&pdu.param, function::WRITE_VAR, "Write Var")?;
    if count != expected || pdu.data.len() != count {
        return Err(answer(format!(
            "the Write Var response answers {count} items in {} octets; the request wrote {expected}",
            pdu.data.len()
        )));
    }
    Ok(pdu.data.clone())
}

/// The bytes a Read Var request of `items` items occupies.
pub fn read_request_len(items: usize) -> usize {
    READ_REQUEST_FIXED + items * ITEM_SPEC_LEN
}

/// The bytes a Read Var response for items of `lengths` bytes occupies.
pub fn read_response_len(lengths: &[usize]) -> usize {
    READ_RESPONSE_FIXED + data_items_len(lengths)
}

/// The bytes a Write Var request carrying items of `lengths` bytes
/// occupies.
pub fn write_request_len(lengths: &[usize]) -> usize {
    WRITE_REQUEST_FIXED + lengths.len() * ITEM_SPEC_LEN + data_items_len(lengths)
}

fn data_items_len(lengths: &[usize]) -> usize {
    let last = lengths.len().saturating_sub(1);
    lengths
        .iter()
        .enumerate()
        .map(|(i, len)| DATA_ITEM_HEADER_LEN + len + usize::from(len % 2 == 1 && i < last))
        .sum()
}

/// A Job as a PLC receives it — the server half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    /// Setup Communication.
    Setup(Setup),
    /// Read Var.
    ReadVar(Vec<ItemSpec>),
    /// Write Var, each item with the bytes it carries.
    WriteVar(Vec<(ItemSpec, Vec<u8>)>),
    /// Any other function, by code.
    Other(u8),
}

impl Job {
    /// Reads a Job PDU's parameter and data parts.
    pub fn decode(pdu: &Pdu) -> Result<Self, S7Error> {
        if pdu.rosctr != Rosctr::Job {
            return Err(answer(format!("expected a Job, found {:?}", pdu.rosctr)));
        }
        let Some(&code) = pdu.param.first() else {
            return Err(answer("a Job carries no parameter"));
        };
        match code {
            function::SETUP => Ok(Self::Setup(Setup::decode(&pdu.param)?)),
            function::READ_VAR | function::WRITE_VAR => {
                let Some(&count) = pdu.param.get(1) else {
                    return Err(answer("a Read/Write Var job carries no item count"));
                };
                let count = usize::from(count);
                if pdu.param.len() != 2 + count * ITEM_SPEC_LEN {
                    return Err(answer(format!(
                        "{count} items need {} parameter octets, found {}",
                        2 + count * ITEM_SPEC_LEN,
                        pdu.param.len()
                    )));
                }
                let specs = (0..count)
                    .map(|i| ItemSpec::decode(&pdu.param[2 + i * ITEM_SPEC_LEN..]))
                    .collect::<Result<Vec<_>, _>>()?;
                if code == function::READ_VAR {
                    return Ok(Self::ReadVar(specs));
                }
                let data = decode_data_items(&pdu.data, count)?;
                Ok(Self::WriteVar(
                    specs
                        .into_iter()
                        .zip(data)
                        .map(|(spec, (_, bytes))| (spec, bytes))
                        .collect(),
                ))
            }
            other => Ok(Self::Other(other)),
        }
    }
}

/// A Read Var response's parameter and data parts, each item answered
/// with the transport size Snap7's server uses for its word length.
pub fn read_var_response(results: &[(ItemSpec, ItemResult)]) -> (Vec<u8>, Vec<u8>) {
    let param = vec![function::READ_VAR, results.len() as u8];
    let mut data = Vec::new();
    for (index, (spec, result)) in results.iter().enumerate() {
        match result {
            ItemResult::Data(bytes) => encode_data_item(
                &mut data,
                item::SUCCESS,
                data_transport(spec.word_len),
                bytes,
                index + 1 == results.len(),
            ),
            ItemResult::Error(code) => data.extend_from_slice(&[*code, 0, 0, 0]),
        }
    }
    (param, data)
}

/// A Write Var response's parameter and data parts.
pub fn write_var_response(codes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (vec![function::WRITE_VAR, codes.len() as u8], codes.to_vec())
}

// ---------------------------------------------------------------------------
// UserData
// ---------------------------------------------------------------------------

/// UserData function groups (the low nibble of the type/group octet).
pub mod group {
    /// Block functions: list blocks, list of type, block info.
    pub const BLOCK: u8 = 0x03;
    /// CPU functions: read SZL.
    pub const CPU: u8 = 0x04;
    /// Security: session password.
    pub const SECURITY: u8 = 0x05;
    /// Time functions: read and set the clock.
    pub const TIME: u8 = 0x07;
}

/// UserData subfunctions.
pub mod subfunction {
    /// Block functions: list blocks.
    pub const LIST_BLOCKS: u8 = 0x01;
    /// Block functions: list blocks of type.
    pub const LIST_BLOCKS_OF_TYPE: u8 = 0x02;
    /// Block functions: block info.
    pub const BLOCK_INFO: u8 = 0x03;
    /// CPU functions: read SZL.
    pub const READ_SZL: u8 = 0x01;
    /// Security: set the session password.
    pub const SET_PASSWORD: u8 = 0x01;
    /// Security: clear the session password.
    pub const CLEAR_PASSWORD: u8 = 0x02;
    /// Time functions: read the clock.
    pub const READ_CLOCK: u8 = 0x01;
    /// Time functions: set the clock.
    pub const SET_CLOCK: u8 = 0x02;
}

/// The data part of a UserData request that carries no payload.
pub const USERDATA_EMPTY: [u8; 4] = [0x0A, 0x00, 0x00, 0x00];

/// The parameter part of a UserData request: the first of a sequence
/// (`sequence == None`) or a follow-up asking for the next part of an
/// answer that came in several (`Some(seq)`, the sequence number the
/// previous part carried).
pub fn userdata_request_param(group: u8, subfunction: u8, sequence: Option<u8>) -> Vec<u8> {
    match sequence {
        None => vec![
            0x00,
            0x01,
            0x12,
            0x04,
            0x11,
            0x40 | group,
            subfunction,
            0x00,
        ],
        Some(seq) => vec![
            0x00,
            0x01,
            0x12,
            0x08,
            0x12,
            0x40 | group,
            subfunction,
            seq,
            0x00,
            0x00,
            0x00,
            0x00,
        ],
    }
}

/// The data part of a UserData request carrying `payload` (octet string).
pub fn userdata_request_data(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![item::SUCCESS, transport::OCTET];
    data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// A UserData parameter part, as a response carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDataParam {
    /// `0x11` request, `0x12` response.
    pub method: u8,
    /// The type nibble (`0x4` request, `0x8` response).
    pub kind: u8,
    /// The function group.
    pub group: u8,
    /// The subfunction.
    pub subfunction: u8,
    /// The sequence number.
    pub sequence: u8,
    /// The data unit reference.
    pub data_unit_ref: u8,
    /// Whether this is the last part of the answer.
    pub last: bool,
    /// The error code (`0` when none).
    pub error: u16,
}

impl UserDataParam {
    /// Reads a UserData parameter part (the 8-octet request form or the
    /// 12-octet response form).
    pub fn decode(param: &[u8]) -> Result<Self, S7Error> {
        if param.len() < 8 || param[0] != 0x00 || param[1] != 0x01 || param[2] != 0x12 {
            return Err(answer(format!(
                "a UserData parameter starts 00 01 12, found {}",
                hex(param)
            )));
        }
        let long = param.len() >= 12;
        Ok(Self {
            method: param[4],
            kind: param[5] >> 4,
            group: param[5] & 0x0F,
            subfunction: param[6],
            sequence: param[7],
            data_unit_ref: if long { param[8] } else { 0 },
            last: !long || param[9] == 0,
            error: if long { be16(param, 10) } else { 0 },
        })
    }

    /// The response parameter part (for a simulated PLC).
    pub fn encode_response(&self) -> Vec<u8> {
        let mut out = vec![
            0x00,
            0x01,
            0x12,
            0x08,
            0x12,
            0x80 | self.group,
            self.subfunction,
            self.sequence,
            self.data_unit_ref,
            u8::from(!self.last),
        ];
        out.extend_from_slice(&self.error.to_be_bytes());
        out
    }
}

/// Splits a UserData data part into its return code and payload.
pub fn userdata_payload(data: &[u8]) -> Result<(u8, &[u8]), S7Error> {
    if data.len() < 4 {
        return Err(answer(format!(
            "a UserData data part needs 4 header octets, found {}",
            data.len()
        )));
    }
    let code = data[0];
    if code != item::SUCCESS {
        return Ok((code, &[]));
    }
    let len = usize::from(be16(data, 2));
    let payload = data.get(4..4 + len).ok_or_else(|| {
        answer(format!(
            "a UserData data part announces {len} octets but {} follow",
            data.len() - 4
        ))
    })?;
    Ok((code, payload))
}
