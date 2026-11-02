// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! Block functions: directory, block info, upload, download, delete.
//!
//! # Telegrams
//!
//! - Directory and block info are UserData of the block-functions group:
//!   subfunction 1 (list blocks, no payload; answer: per type `30 <type>
//!   <count:2>`), 2 (list of type, payload `30 <type>`; answer: per block
//!   `<number:2> <flags> <language>`, in as many parts as needed), 3
//!   (block info, payload `30 <type> <number: 5 ASCII digits> 41`).
//! - A block is named by a 9-character file name: `_`, `0`, the block
//!   type as a character (`8` OB, `A` DB, `B` SDB, `C` FC, `D` SFC, `E`
//!   FB, `F` SFB), the number in 5 digits, and the file system: `A`
//!   (active) for upload, `P` (passive) for download, `B` (both) for
//!   delete.
//! - Upload: Start upload (`0x1D`, the file name; answer: an upload id
//!   and the length as ASCII digits), Upload (`0x1E`, the id; answer:
//!   `<len:2> 00 FB <bytes>` with more to come while the second
//!   parameter octet is 1), End upload (`0x1F`, the id).
//! - Download: Request download (`0x1A`, the file name and `1` + load
//!   length + MC7 length in 6 digits each); then the PLC sends Download
//!   block jobs (`0x1B`), each answered with the next part, and Download
//!   ended (`0x1C`); then the PI service `_INSE` activates the block.
//! - Delete: the PI service `_DELE`.
//! - A block as uploaded or downloaded is a 36-octet header (`70 70`,
//!   flags, language, sub block type, number, load length, security,
//!   code and interface timestamps, SBB, ADD, local data and MC7
//!   lengths), the MC7 code, and a 36-octet footer whose first 24 octets
//!   are author, family and name.

use super::{elapsed_ms, S7Client};
use crate::error::{ErrorKind, S7Error};
use crate::proto::{answer, be16, be32, function, group, subfunction, Pdu, Rosctr};
use crate::proto::{S7_AREA_DB, S7_WL_BYTE};
use crate::types::{
    block_type_of_sub_block, is_block_type, s7_date, text, S7BlockEntry, S7BlockInfo, S7BlocksList,
    BLOCK_DB, BLOCK_TYPES,
};
use std::time::Instant;

/// The length of a block's header.
pub const BLOCK_HEADER_LEN: usize = 36;
/// The length of a block's footer.
pub const BLOCK_FOOTER_LEN: usize = 36;
/// The most parts an upload may come in.
const MAX_UPLOAD_PARTS: usize = 65_536;

/// A block's 9-character file name.
fn file_name(block_type: u8, number: u16, file_system: u8) -> Vec<u8> {
    let mut name = vec![b'_', b'0', block_type];
    name.extend_from_slice(format!("{number:05}").as_bytes());
    name.push(file_system);
    name
}

/// The parameter part of a PI service call.
pub(crate) fn pi_service(parameter_block: &[u8], service: &str) -> Vec<u8> {
    let mut param = vec![function::PI_SERVICE, 0, 0, 0, 0, 0, 0, 0xFD];
    param.extend_from_slice(&(parameter_block.len() as u16).to_be_bytes());
    param.extend_from_slice(parameter_block);
    param.push(service.len() as u8);
    param.extend_from_slice(service.as_bytes());
    param
}

/// The PI parameter block naming one block: count 1, then `0`, the type,
/// the number, and the file system.
fn pi_block(block_type: u8, number: u16, file_system: u8) -> Vec<u8> {
    let mut block = vec![0x01, 0x00, b'0', block_type];
    block.extend_from_slice(format!("{number:05}").as_bytes());
    block.push(file_system);
    block
}

fn check_block_type(block_type: u8) -> Result<(), S7Error> {
    if is_block_type(block_type) {
        Ok(())
    } else {
        Err(ErrorKind::InvalidBlockType.into())
    }
}

/// The parameter part of an upload job carrying the upload id.
fn upload_param(code: u8, id: u32) -> Vec<u8> {
    let mut param = vec![code, 0, 0, 0];
    param.extend_from_slice(&id.to_be_bytes());
    param
}

impl S7Client {
    /// ### Counts the blocks of each type (Snap7's `ListBlocks`)
    pub fn list_blocks(&mut self) -> Result<S7BlocksList, S7Error> {
        let parts = self
            .userdata(group::BLOCK, subfunction::LIST_BLOCKS, None)
            .map_err(|e| e.refused_as(ErrorKind::ItemNotAvailable))?;
        let payload = parts.concat();
        let mut list = S7BlocksList::default();
        for entry in payload.chunks_exact(4) {
            if entry[0] == 0x30 && BLOCK_TYPES.contains(&entry[1]) {
                list.set(entry[1], be16(entry, 2));
            }
        }
        Ok(list)
    }

    /// ### Lists the blocks of one type (Snap7's `ListBlocksOfType`)
    ///
    /// `block_type` is one of `BLOCK_OB`, `BLOCK_DB`, `BLOCK_SDB`,
    /// `BLOCK_FC`, `BLOCK_SFC`, `BLOCK_FB`, `BLOCK_SFB`. The answer may
    /// come in several parts; all are fetched.
    ///
    /// ### Errors
    /// - `InvalidBlockType`.
    /// - `ItemNotAvailable` (with the PLC's code) when the PLC reports no
    ///   block of the type.
    pub fn list_blocks_of_type(&mut self, block_type: u8) -> Result<Vec<S7BlockEntry>, S7Error> {
        check_block_type(block_type)?;
        let parts = self
            .userdata(
                group::BLOCK,
                subfunction::LIST_BLOCKS_OF_TYPE,
                Some(&[0x30, block_type]),
            )
            .map_err(|e| e.refused_as(ErrorKind::ItemNotAvailable))?;
        Ok(parts
            .concat()
            .chunks_exact(4)
            .map(|entry| S7BlockEntry {
                number: be16(entry, 0),
                flags: entry[2],
                language: entry[3],
            })
            .collect())
    }

    /// ### Reads a block's properties from the PLC (Snap7's `GetAgBlockInfo`)
    pub fn get_ag_block_info(
        &mut self,
        block_type: u8,
        block_number: u16,
    ) -> Result<S7BlockInfo, S7Error> {
        check_block_type(block_type)?;
        let mut request = vec![0x30, block_type];
        request.extend_from_slice(format!("{block_number:05}").as_bytes());
        request.push(b'A');
        let info = self
            .userdata(group::BLOCK, subfunction::BLOCK_INFO, Some(&request))
            .map_err(|e| e.refused_as(ErrorKind::ItemNotAvailable))?
            .concat();
        if info.len() < 70 {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidDataSizeReceived,
                format!("a block info answer of {} octets", info.len()),
            ));
        }
        Ok(S7BlockInfo {
            block_type: info[11],
            block_number: be16(&info, 12),
            block_lang: info[10],
            block_flags: info[9],
            mc7_size: be16(&info, 40),
            load_size: be32(&info, 14),
            local_data: be16(&info, 38),
            sbb_length: be16(&info, 34),
            checksum: be16(&info, 68),
            version: info[66],
            code_date: s7_date(be16(&info, 26)),
            intf_date: s7_date(be16(&info, 32)),
            author: text(&info[42..50]),
            family: text(&info[50..58]),
            header: text(&info[58..66]),
        })
    }

    /// ### Reads a block's properties from an uploaded block (Snap7's `GetPgBlockInfo`)
    ///
    /// `block` is a block as [`full_upload`](Self::full_upload) returns
    /// it; nothing is sent. The version and checksum are not part of
    /// what this reports (0), as in Snap7.
    ///
    /// ### Errors
    /// - `InvalidBlockSize`: shorter than header and footer, or the
    ///   header's load length is not the buffer's length.
    pub fn get_pg_block_info(&self, block: &[u8]) -> Result<S7BlockInfo, S7Error> {
        let header = check_block(block)?;
        let footer = &block[block.len() - BLOCK_FOOTER_LEN..];
        Ok(S7BlockInfo {
            block_type: header[5],
            block_number: be16(header, 6),
            block_lang: header[4],
            block_flags: header[3],
            mc7_size: be16(header, 34),
            load_size: be32(header, 8),
            local_data: be16(header, 32),
            sbb_length: be16(header, 28),
            checksum: 0,
            version: 0,
            code_date: s7_date(be16(header, 20)),
            intf_date: s7_date(be16(header, 26)),
            author: text(&footer[0..8]),
            family: text(&footer[8..16]),
            header: text(&footer[16..24]),
        })
    }

    /// ### Uploads a whole block — header, body and footer (Snap7's `FullUpload`)
    ///
    /// The result can be passed to [`get_pg_block_info`](Self::get_pg_block_info)
    /// or [`download`](Self::download).
    pub fn full_upload(&mut self, block_type: u8, block_number: u16) -> Result<Vec<u8>, S7Error> {
        check_block_type(block_type)?;
        self.require_connected()?;
        let started = Instant::now();
        let mut param = vec![function::START_UPLOAD, 0, 0, 0, 0, 0, 0, 0, 9];
        param.extend_from_slice(&file_name(block_type, block_number, b'A'));
        let reply = self.job(param, Vec::new())?;
        if reply.error != 0 {
            return Err(S7Error::from_cpu(reply.error));
        }
        if reply.param.len() < 8 {
            return Err(S7Error::with_detail(
                ErrorKind::UploadSequenceFailed,
                "the start upload answer carries no upload id",
            ));
        }
        let id = be32(&reply.param, 4);
        // The block's total length, as ASCII digits after a length octet.
        let announced = reply.param.get(8).and_then(|&n| {
            let digits = reply.param.get(9..9 + usize::from(n))?;
            std::str::from_utf8(digits)
                .ok()?
                .trim()
                .parse::<usize>()
                .ok()
        });
        let result = self.upload_parts(id, announced);
        if !matches!(&result, Err(e) if e.is_link()) {
            let end = self.job(upload_param(function::END_UPLOAD, id), Vec::new());
            if result.is_ok() {
                let reply = end?;
                if reply.error != 0 {
                    return Err(S7Error::cpu(ErrorKind::UploadSequenceFailed, reply.error));
                }
            }
        }
        let block = result?;
        self.last_time = elapsed_ms(started);
        Ok(block)
    }

    /// Collects the upload's parts; with the length Start upload
    /// announced, more or fewer octets than announced fail.
    fn upload_parts(&mut self, id: u32, announced: Option<usize>) -> Result<Vec<u8>, S7Error> {
        let mut block = Vec::new();
        for _ in 0..MAX_UPLOAD_PARTS {
            let reply = self.job(upload_param(function::UPLOAD, id), Vec::new())?;
            if reply.error != 0 {
                return Err(S7Error::cpu(ErrorKind::UploadSequenceFailed, reply.error));
            }
            let more = reply.param.get(1).copied().unwrap_or(0) == 0x01;
            if reply.data.len() < 4 {
                return Err(S7Error::with_detail(
                    ErrorKind::UploadSequenceFailed,
                    "an upload answer without its data header",
                ));
            }
            let len = usize::from(be16(&reply.data, 0));
            let part = reply.data.get(4..4 + len).ok_or_else(|| {
                S7Error::with_detail(
                    ErrorKind::InvalidDataSizeReceived,
                    format!(
                        "an upload part announces {len} octets, {} follow",
                        reply.data.len() - 4
                    ),
                )
            })?;
            block.extend_from_slice(part);
            let size_error = || {
                S7Error::with_detail(
                    ErrorKind::InvalidDataSizeReceived,
                    format!(
                        "the PLC announced a {} octet block and sent {}{}",
                        announced.unwrap_or_default(),
                        block.len(),
                        if more { " so far" } else { "" }
                    ),
                )
            };
            match announced {
                Some(total) if block.len() > total || (!more && block.len() != total) => {
                    return Err(size_error());
                }
                _ if !more => return Ok(block),
                _ => {}
            }
        }
        Err(answer("an upload that never ends"))
    }

    /// ### Uploads a block's body — its MC7 code, or a DB's data (Snap7's `Upload`)
    pub fn upload(&mut self, block_type: u8, block_number: u16) -> Result<Vec<u8>, S7Error> {
        let block = self.full_upload(block_type, block_number)?;
        let header = check_block(&block)?;
        let mc7 = usize::from(be16(header, 34));
        block
            .get(BLOCK_HEADER_LEN..BLOCK_HEADER_LEN + mc7)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| ErrorKind::InvalidBlockSize.into())
    }

    /// ### Downloads a block to the PLC and activates it (Snap7's `Download`)
    ///
    /// `block` is a whole block (header, body, footer), as
    /// [`full_upload`](Self::full_upload) returns it. With
    /// `block_number` `Some(n)` the block is stored as number `n`;
    /// `None` keeps the number in its header.
    ///
    /// ### Errors
    /// - `InvalidBlockSize`, `InvalidBlockType`: the buffer is not a block.
    /// - `DownloadSequenceFailed` (with the PLC's code where it refused).
    /// - `InsertRefused`: the PLC took the block but refused to activate it.
    pub fn download(&mut self, block_number: Option<u16>, block: &[u8]) -> Result<(), S7Error> {
        let header = check_block(block)?;
        let block_type = block_type_of_sub_block(header[5]).ok_or(ErrorKind::InvalidBlockType)?;
        let mut block = block.to_vec();
        let number = match block_number {
            Some(number) => {
                block[6..8].copy_from_slice(&number.to_be_bytes());
                number
            }
            None => be16(&block, 6),
        };
        let load = block.len();
        let mc7 = usize::from(be16(&block, 34));
        if load > 999_999 {
            return Err(ErrorKind::InvalidBlockSize.into());
        }
        self.require_connected()?;
        let started = Instant::now();
        let name = file_name(block_type, number, b'P');
        let mut param = vec![function::REQUEST_DOWNLOAD, 0, 1, 0, 0, 0, 0, 0, 9];
        param.extend_from_slice(&name);
        param.push(13);
        param.extend_from_slice(format!("1{load:06}{mc7:06}").as_bytes());
        let reply = self.job(param, Vec::new())?;
        if reply.error != 0 {
            return Err(S7Error::cpu(ErrorKind::DownloadSequenceFailed, reply.error));
        }
        self.serve_download(&block)?;
        let reply = self.job(
            pi_service(&pi_block(block_type, number, b'P'), "_INSE"),
            Vec::new(),
        )?;
        if reply.error != 0 {
            return Err(S7Error::cpu(ErrorKind::InsertRefused, reply.error));
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    /// Answers the PLC's Download block jobs with the block's parts until
    /// it sends Download ended.
    fn serve_download(&mut self, block: &[u8]) -> Result<(), S7Error> {
        let room = usize::from(self.pdu_length).saturating_sub(18).max(1);
        let mut sent = 0;
        loop {
            let deadline = Instant::now() + self.recv_timeout();
            let job = self.receive_pdu(deadline)?;
            if job.rosctr != Rosctr::Job {
                let detail = format!("the PLC sent a {:?} during the download", job.rosctr);
                return Err(if job.error != 0 {
                    S7Error::cpu(ErrorKind::DownloadSequenceFailed, job.error)
                } else {
                    S7Error::with_detail(ErrorKind::DownloadSequenceFailed, detail)
                });
            }
            match job.param.first().copied() {
                Some(function::DOWNLOAD_BLOCK) if sent < block.len() => {
                    let part = &block[sent..block.len().min(sent + room)];
                    sent += part.len();
                    let mut data = (part.len() as u16).to_be_bytes().to_vec();
                    data.extend_from_slice(&[0x00, 0xFB]);
                    data.extend_from_slice(part);
                    let more = u8::from(sent < block.len());
                    self.answer_plc(&job, vec![function::DOWNLOAD_BLOCK, more], data)?;
                }
                Some(function::DOWNLOAD_ENDED) => {
                    self.answer_plc(&job, vec![function::DOWNLOAD_ENDED], Vec::new())?;
                    // Download ended carries the PLC's error code after its
                    // status octet.
                    let error = if job.param.len() >= 4 {
                        be16(&job.param, 2)
                    } else {
                        0
                    };
                    if error != 0 {
                        return Err(S7Error::cpu(ErrorKind::DownloadSequenceFailed, error));
                    }
                    if sent < block.len() {
                        return Err(S7Error::with_detail(
                            ErrorKind::DownloadSequenceFailed,
                            format!(
                                "the PLC ended the download after {sent} of {} octets",
                                block.len()
                            ),
                        ));
                    }
                    return Ok(());
                }
                other => {
                    return Err(S7Error::with_detail(
                        ErrorKind::DownloadSequenceFailed,
                        format!(
                            "unexpected PLC job {other:?} after {sent} of {} octets",
                            block.len()
                        ),
                    ));
                }
            }
        }
    }

    fn answer_plc(&mut self, job: &Pdu, param: Vec<u8>, data: Vec<u8>) -> Result<(), S7Error> {
        let reply = Pdu {
            rosctr: Rosctr::AckData,
            pdu_ref: job.pdu_ref,
            error: 0,
            param,
            data,
        };
        self.send_pdu(&reply)
    }

    /// ### Deletes a block (Snap7's `Delete`)
    ///
    /// ### Errors
    /// - `DeleteRefused` with the PLC's code.
    pub fn delete(&mut self, block_type: u8, block_number: u16) -> Result<(), S7Error> {
        check_block_type(block_type)?;
        let started = Instant::now();
        let reply = self.job(
            pi_service(&pi_block(block_type, block_number, b'B'), "_DELE"),
            Vec::new(),
        )?;
        if reply.error != 0 {
            return Err(S7Error::cpu(ErrorKind::DeleteRefused, reply.error));
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    /// ### Reads a whole DB, sized by its block info (Snap7's `DBGet`)
    pub fn db_get(&mut self, db_number: u16) -> Result<Vec<u8>, S7Error> {
        let size = usize::from(self.get_ag_block_info(BLOCK_DB, db_number)?.mc7_size);
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut data = vec![0u8; size];
        self.read_area(S7_AREA_DB, db_number, 0, S7_WL_BYTE, &mut data)?;
        Ok(data)
    }

    /// ### Fills a whole DB with one byte value (Snap7's `DBFill`)
    pub fn db_fill(&mut self, db_number: u16, value: u8) -> Result<(), S7Error> {
        let size = usize::from(self.get_ag_block_info(BLOCK_DB, db_number)?.mc7_size);
        if size == 0 {
            return Ok(());
        }
        self.write_area(S7_AREA_DB, db_number, 0, S7_WL_BYTE, &vec![value; size])
    }
}

/// Checks that `block` is a whole block and returns its header.
fn check_block(block: &[u8]) -> Result<&[u8], S7Error> {
    if block.len() < BLOCK_HEADER_LEN + BLOCK_FOOTER_LEN {
        return Err(S7Error::with_detail(
            ErrorKind::InvalidBlockSize,
            format!(
                "{} octets cannot hold a block's header and footer",
                block.len()
            ),
        ));
    }
    let load = be32(block, 8) as usize;
    if load != block.len() {
        return Err(S7Error::with_detail(
            ErrorKind::InvalidBlockSize,
            format!(
                "the header announces {load} octets, the buffer holds {}",
                block.len()
            ),
        ));
    }
    Ok(&block[..BLOCK_HEADER_LEN])
}
