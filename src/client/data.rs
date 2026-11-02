// Rust7 - Native Rust S7 client (Snap7‑style) for Siemens PLCs.
// Copyright 2025 - Davide Nardella

//! Data I/O: areas, the per-area helpers, and multi-variable access.

use super::{elapsed_ms, S7Client};
use crate::error::{ErrorKind, S7Error};
use crate::proto::{
    self, is_area, read_request_len, read_response_len, read_var_param, word_size,
    write_request_len, write_var_request, ItemResult, ItemSpec, DATA_ITEM_HEADER_LEN,
    ITEM_SPEC_LEN, MAX_BYTE_ADDRESS, MAX_VARS, READ_RESPONSE_FIXED, S7_AREA_CT, S7_AREA_DB,
    S7_AREA_MK, S7_AREA_PA, S7_AREA_PE, S7_AREA_TM, S7_WL_BIT, S7_WL_BYTE, S7_WL_COUNTER,
    S7_WL_TIMER, WRITE_REQUEST_FIXED,
};
use crate::types::S7DataItem;
use std::time::Instant;

/// Checks an area and word length and returns the word length the wire
/// uses (counters and timers for their areas).
fn check_area(area: u8, word_len: u8) -> Result<u8, S7Error> {
    if !is_area(area) {
        return Err(S7Error::with_detail(
            ErrorKind::InvalidParams,
            format!("unknown area {area:#04x}"),
        ));
    }
    let word_len = match area {
        S7_AREA_CT => S7_WL_COUNTER,
        S7_AREA_TM => S7_WL_TIMER,
        _ => word_len,
    };
    if word_size(word_len).is_none() {
        return Err(ErrorKind::InvalidWordLen.into());
    }
    Ok(word_len)
}

/// Checks that an item starting at `start` and spanning `elements`
/// elements is addressable by the 24-bit S7ANY address.
fn check_address(word_len: u8, start: u32, elements: usize) -> Result<(), S7Error> {
    let size = word_size(word_len).unwrap_or(1);
    let (last, limit) = match word_len {
        S7_WL_BIT => (u64::from(start), 0x00FF_FFFF),
        S7_WL_COUNTER | S7_WL_TIMER => (u64::from(start) + elements as u64, 0xFFFF),
        _ => (
            u64::from(start) + (elements * size) as u64,
            u64::from(MAX_BYTE_ADDRESS) + 1,
        ),
    };
    if last > limit {
        return Err(S7Error::with_detail(
            ErrorKind::InvalidParams,
            format!("start {start} is beyond what an S7 address can carry"),
        ));
    }
    Ok(())
}

impl S7DataItem {
    fn spec(&self) -> ItemSpec {
        ItemSpec::new(
            self.area,
            self.db_number,
            self.start,
            self.amount,
            self.effective_word_len(),
        )
    }

    /// Validates the item and returns its data length.
    fn check(&self) -> Result<usize, S7Error> {
        let word_len = check_area(self.area, self.word_len)?;
        let len = self.byte_len()?;
        check_address(word_len, self.start, usize::from(self.amount))?;
        Ok(len)
    }
}

impl S7Client {
    /// The most data bytes one Read Var item can return in one PDU.
    pub fn read_capacity(&self) -> usize {
        usize::from(self.pdu_length).saturating_sub(READ_RESPONSE_FIXED + DATA_ITEM_HEADER_LEN)
    }

    /// The most data bytes one Write Var item can carry in one PDU.
    pub fn write_capacity(&self) -> usize {
        usize::from(self.pdu_length)
            .saturating_sub(WRITE_REQUEST_FIXED + ITEM_SPEC_LEN + DATA_ITEM_HEADER_LEN)
    }

    /// ### Reads data from an S7 memory area (Snap7's `ReadArea`)
    ///
    /// ### Parameters
    /// - `area`: `S7_AREA_PE`, `S7_AREA_PA`, `S7_AREA_MK`, `S7_AREA_DB`,
    ///   `S7_AREA_CT`, or `S7_AREA_TM`.
    /// - `db_number`: the DB number (ignored outside the DB area).
    /// - `start`: a byte offset; a bit number (`byte * 8 + bit`) for
    ///   `S7_WL_BIT`; a counter or timer number in those areas.
    /// - `word_len`: `S7_WL_BIT`, `S7_WL_BYTE`, `S7_WL_CHAR`,
    ///   `S7_WL_WORD`, `S7_WL_INT`, `S7_WL_DWORD`, `S7_WL_DINT`,
    ///   `S7_WL_REAL`; the counter and timer areas always use
    ///   `S7_WL_COUNTER` / `S7_WL_TIMER` (2 bytes each).
    /// - `buffer`: the destination; its length sets how much is read and
    ///   must be a multiple of the element size. Bit access reads one bit
    ///   into `buffer[0]` (0 or 1).
    ///
    /// Large reads are split into as many Read Var jobs as the
    /// negotiated PDU requires ([`chunks`](Self::chunks) tells how many).
    ///
    /// ### Errors
    /// - `InvalidParams`, `InvalidWordLen`: invalid arguments.
    /// - `TcpNotConnected` and other TCP / ISO errors (the connection is
    ///   then closed).
    /// - The PLC's refusal with its code: `ItemNotAvailable` (`0x0A`, a
    ///   DB that does not exist), `AddressOutOfRange` (`0x05`, beyond the
    ///   area or an optimized DB), `FunNotAvailable` (`0x8104`, PUT/GET
    ///   not permitted on an S7-1200/1500), ...
    pub fn read_area(
        &mut self,
        area: u8,
        db_number: u16,
        start: u32,
        word_len: u8,
        buffer: &mut [u8],
    ) -> Result<(), S7Error> {
        self.last_time = 0.0;
        self.chunks = 0;
        let word_len = check_area(area, word_len)?;
        let size = word_size(word_len).unwrap_or(1);
        let elements = if word_len == S7_WL_BIT {
            1
        } else {
            buffer.len() / size
        };
        if buffer.is_empty() || (word_len != S7_WL_BIT && buffer.len() % size != 0) {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                format!("a buffer of {} bytes for elements of {size}", buffer.len()),
            ));
        }
        check_address(word_len, start, elements)?;
        self.require_connected()?;
        let started = Instant::now();
        let per_job = (self.read_capacity() / size).max(1);
        let mut done = 0;
        while done < elements {
            let count = (elements - done).min(per_job);
            let element_start = advance(word_len, start, done, size);
            let spec = ItemSpec::new(area, db_number, element_start, count as u16, word_len);
            let bytes = self.read_one(spec)?;
            let at = done * size;
            buffer[at..at + bytes.len()].copy_from_slice(&bytes);
            done += count;
            self.chunks += 1;
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    /// One single-item Read Var job.
    fn read_one(&mut self, spec: ItemSpec) -> Result<Vec<u8>, S7Error> {
        let reply = self.job(read_var_param(&[spec]), Vec::new())?;
        if reply.error != 0 {
            return Err(S7Error::from_cpu(reply.error));
        }
        match proto::decode_read_var_response(&reply, 1)?.remove(0) {
            ItemResult::Data(bytes) if bytes.len() == spec.byte_len() => Ok(bytes),
            ItemResult::Data(bytes) => Err(S7Error::with_detail(
                ErrorKind::InvalidDataSizeReceived,
                format!(
                    "asked for {} bytes, received {}",
                    spec.byte_len(),
                    bytes.len()
                ),
            )),
            ItemResult::Error(code) => Err(S7Error::from_cpu(u16::from(code))),
        }
    }

    /// ### Writes data to an S7 memory area (Snap7's `WriteArea`)
    ///
    /// The parameters are those of [`read_area`](Self::read_area);
    /// `buffer` holds the data to write. A bit write sets or clears only
    /// that bit (`buffer[0] != 0` sets it).
    ///
    /// Large writes are split into as many Write Var jobs as the PDU
    /// requires; a refusal in a later job leaves the earlier ones
    /// written.
    pub fn write_area(
        &mut self,
        area: u8,
        db_number: u16,
        start: u32,
        word_len: u8,
        buffer: &[u8],
    ) -> Result<(), S7Error> {
        self.last_time = 0.0;
        self.chunks = 0;
        let word_len = check_area(area, word_len)?;
        let size = word_size(word_len).unwrap_or(1);
        let elements = if word_len == S7_WL_BIT {
            1
        } else {
            buffer.len() / size
        };
        if buffer.is_empty() || (word_len != S7_WL_BIT && buffer.len() % size != 0) {
            return Err(S7Error::with_detail(
                ErrorKind::InvalidParams,
                format!("a buffer of {} bytes for elements of {size}", buffer.len()),
            ));
        }
        check_address(word_len, start, elements)?;
        self.require_connected()?;
        let started = Instant::now();
        let per_job = (self.write_capacity() / size).max(1);
        let mut done = 0;
        while done < elements {
            let count = (elements - done).min(per_job);
            let element_start = advance(word_len, start, done, size);
            let spec = ItemSpec::new(area, db_number, element_start, count as u16, word_len);
            let bytes: Vec<u8> = if word_len == S7_WL_BIT {
                vec![u8::from(buffer[0] != 0)]
            } else {
                buffer[done * size..(done + count) * size].to_vec()
            };
            self.write_one(spec, &bytes)?;
            done += count;
            self.chunks += 1;
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    /// One single-item Write Var job.
    fn write_one(&mut self, spec: ItemSpec, bytes: &[u8]) -> Result<(), S7Error> {
        let (param, data) = write_var_request(&[(spec, bytes)]);
        let reply = self.job(param, data)?;
        if reply.error != 0 {
            return Err(S7Error::from_cpu(reply.error));
        }
        match proto::decode_write_var_response(&reply, 1)?[0] {
            proto::item::SUCCESS => Ok(()),
            code => Err(S7Error::from_cpu(u16::from(code))),
        }
    }

    /// ### Reads bytes from a data block (Snap7's `DBRead`)
    pub fn read_db(
        &mut self,
        db_number: u16,
        start: u32,
        buffer: &mut [u8],
    ) -> Result<(), S7Error> {
        self.read_area(S7_AREA_DB, db_number, start, S7_WL_BYTE, buffer)
    }

    /// ### Writes bytes to a data block (Snap7's `DBWrite`)
    pub fn write_db(&mut self, db_number: u16, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_DB, db_number, start, S7_WL_BYTE, buffer)
    }

    /// ### Reads merker (bit memory) bytes (Snap7's `MBRead`)
    pub fn read_mb(&mut self, start: u32, buffer: &mut [u8]) -> Result<(), S7Error> {
        self.read_area(S7_AREA_MK, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Writes merker (bit memory) bytes (Snap7's `MBWrite`)
    pub fn write_mb(&mut self, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_MK, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Reads process-input bytes (Snap7's `EBRead`)
    pub fn read_eb(&mut self, start: u32, buffer: &mut [u8]) -> Result<(), S7Error> {
        self.read_area(S7_AREA_PE, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Writes process-input bytes (Snap7's `EBWrite`)
    pub fn write_eb(&mut self, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_PE, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Reads process-output bytes (Snap7's `ABRead`)
    pub fn read_ab(&mut self, start: u32, buffer: &mut [u8]) -> Result<(), S7Error> {
        self.read_area(S7_AREA_PA, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Writes process-output bytes (Snap7's `ABWrite`)
    ///
    /// The PLC program usually rewrites the output image every cycle.
    pub fn write_ab(&mut self, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_PA, 0, start, S7_WL_BYTE, buffer)
    }

    /// ### Reads timers (Snap7's `TMRead`): 2 bytes per timer from timer `start`
    pub fn read_tm(&mut self, start: u32, buffer: &mut [u8]) -> Result<(), S7Error> {
        self.read_area(S7_AREA_TM, 0, start, S7_WL_TIMER, buffer)
    }

    /// ### Writes timers (Snap7's `TMWrite`): 2 bytes per timer from timer `start`
    pub fn write_tm(&mut self, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_TM, 0, start, S7_WL_TIMER, buffer)
    }

    /// ### Reads counters (Snap7's `CTRead`): 2 bytes per counter from counter `start`
    pub fn read_ct(&mut self, start: u32, buffer: &mut [u8]) -> Result<(), S7Error> {
        self.read_area(S7_AREA_CT, 0, start, S7_WL_COUNTER, buffer)
    }

    /// ### Writes counters (Snap7's `CTWrite`): 2 bytes per counter from counter `start`
    pub fn write_ct(&mut self, start: u32, buffer: &[u8]) -> Result<(), S7Error> {
        self.write_area(S7_AREA_CT, 0, start, S7_WL_COUNTER, buffer)
    }

    /// ### Reads one bit
    ///
    /// For example `DB10.DBX71.4`: `read_bit(S7_AREA_DB, 10, 71, 4)`.
    ///
    /// ### Errors
    /// - `InvalidParams`: `bit_idx` above 7.
    /// - Any error of [`read_area`](Self::read_area).
    pub fn read_bit(
        &mut self,
        area: u8,
        db_number: u16,
        byte_num: u32,
        bit_idx: u8,
    ) -> Result<bool, S7Error> {
        if bit_idx > 7 {
            return Err(ErrorKind::InvalidParams.into());
        }
        let mut buffer = [0u8; 1];
        self.read_area(
            area,
            db_number,
            byte_num * 8 + u32::from(bit_idx),
            S7_WL_BIT,
            &mut buffer,
        )?;
        Ok(buffer[0] != 0)
    }

    /// ### Writes one bit, leaving its neighbours unchanged
    ///
    /// For example to set `DB10.DBX71.4`: `write_bit(S7_AREA_DB, 10, 71, 4, true)`.
    pub fn write_bit(
        &mut self,
        area: u8,
        db_number: u16,
        byte_num: u32,
        bit_idx: u8,
        value: bool,
    ) -> Result<(), S7Error> {
        if bit_idx > 7 {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.write_area(
            area,
            db_number,
            byte_num * 8 + u32::from(bit_idx),
            S7_WL_BIT,
            &[u8::from(value)],
        )
    }

    /// ### Reads several variables (Snap7's `ReadMultiVars`)
    ///
    /// Each item names an area, a word length, a start and an amount;
    /// on return its `data` holds what was read and its `result` the
    /// item's outcome.
    ///
    /// Unlike Snap7, the items are not limited to one PDU: they are
    /// packed, in order, into as few Read Var jobs as the negotiated PDU
    /// allows — at most [`MAX_VARS`] items each, with both the request
    /// and the response (header, 4 octets per item, the data, and a fill
    /// byte after each odd-length item but the last) fitting the PDU. An
    /// item whose data alone exceeds one PDU gets `SizeOverPdu`; read it
    /// with [`read_area`](Self::read_area), which splits.
    ///
    /// A job the PLC refuses as a whole (a header error, for example
    /// class `0x83` when it has no resources) gives that refusal to each
    /// of its items; the other jobs still run.
    ///
    /// ### Returns
    /// `Ok(())` when every job was answered — look at each item's
    /// `result` — or the TCP / ISO error that broke the connection off,
    /// which every item not yet answered also carries.
    pub fn read_multi_vars(&mut self, items: &mut [S7DataItem]) -> Result<(), S7Error> {
        self.last_time = 0.0;
        self.chunks = 0;
        if items.is_empty() {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.require_connected()?;
        let started = Instant::now();
        let pdu = usize::from(self.pdu_length);
        let mut jobs: Vec<Vec<(usize, usize)>> = Vec::new();
        for (index, item) in items.iter_mut().enumerate() {
            item.data.clear();
            item.result = match item.check() {
                Ok(len) if read_request_len(1) > pdu || read_response_len(&[len]) > pdu => {
                    Err(ErrorKind::SizeOverPdu.into())
                }
                Ok(len) => {
                    let fits = jobs.last().is_some_and(|job| {
                        let mut lengths: Vec<usize> = job.iter().map(|&(_, l)| l).collect();
                        lengths.push(len);
                        job.len() < MAX_VARS
                            && read_request_len(lengths.len()) <= pdu
                            && read_response_len(&lengths) <= pdu
                    });
                    if fits {
                        jobs.last_mut().expect("checked").push((index, len));
                    } else {
                        jobs.push(vec![(index, len)]);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            };
        }
        for (number, job) in jobs.iter().enumerate() {
            if let Err(e) = self.read_job(items, job) {
                for &(index, _) in jobs[number..].iter().flatten() {
                    items[index].result = Err(e.clone());
                }
                return Err(e);
            }
            self.chunks += 1;
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    fn read_job(
        &mut self,
        items: &mut [S7DataItem],
        job: &[(usize, usize)],
    ) -> Result<(), S7Error> {
        let specs: Vec<ItemSpec> = job.iter().map(|&(index, _)| items[index].spec()).collect();
        let reply = self.job(read_var_param(&specs), Vec::new())?;
        if reply.error != 0 {
            for &(index, _) in job {
                items[index].result = Err(S7Error::from_cpu(reply.error));
            }
            return Ok(());
        }
        let results = proto::decode_read_var_response(&reply, specs.len())?;
        for (&(index, len), result) in job.iter().zip(&results) {
            if let ItemResult::Data(bytes) = result {
                if bytes.len() != len {
                    return Err(S7Error::with_detail(
                        ErrorKind::InvalidDataSizeReceived,
                        format!(
                            "item {} asked for {len} bytes, received {}",
                            index + 1,
                            bytes.len()
                        ),
                    ));
                }
            }
        }
        for (&(index, _), result) in job.iter().zip(results) {
            items[index].result = match result {
                ItemResult::Data(bytes) => {
                    items[index].data = bytes;
                    Ok(())
                }
                ItemResult::Error(code) => Err(S7Error::from_cpu(u16::from(code))),
            };
        }
        Ok(())
    }

    /// ### Writes several variables (Snap7's `WriteMultiVars`)
    ///
    /// Each item's `data` is written (its length must equal `amount`
    /// elements of the word length; one byte for a bit); on return its
    /// `result` holds the item's outcome. Items are packed into as few
    /// Write Var jobs as the PDU allows, as
    /// [`read_multi_vars`](Self::read_multi_vars) does; the jobs are not
    /// atomic together.
    pub fn write_multi_vars(&mut self, items: &mut [S7DataItem]) -> Result<(), S7Error> {
        self.last_time = 0.0;
        self.chunks = 0;
        if items.is_empty() {
            return Err(ErrorKind::InvalidParams.into());
        }
        self.require_connected()?;
        let started = Instant::now();
        let pdu = usize::from(self.pdu_length);
        let mut jobs: Vec<Vec<(usize, usize)>> = Vec::new();
        for (index, item) in items.iter_mut().enumerate() {
            item.result = match item.check() {
                Ok(len) if item.data.len() != len => Err(S7Error::with_detail(
                    ErrorKind::InvalidParams,
                    format!(
                        "the item carries {} bytes for {len} bytes of elements",
                        item.data.len()
                    ),
                )),
                Ok(len) if write_request_len(&[len]) > pdu => Err(ErrorKind::SizeOverPdu.into()),
                Ok(len) => {
                    let fits = jobs.last().is_some_and(|job| {
                        let mut lengths: Vec<usize> = job.iter().map(|&(_, l)| l).collect();
                        lengths.push(len);
                        job.len() < MAX_VARS && write_request_len(&lengths) <= pdu
                    });
                    if fits {
                        jobs.last_mut().expect("checked").push((index, len));
                    } else {
                        jobs.push(vec![(index, len)]);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            };
        }
        for (number, job) in jobs.iter().enumerate() {
            if let Err(e) = self.write_job(items, job) {
                for &(index, _) in jobs[number..].iter().flatten() {
                    items[index].result = Err(e.clone());
                }
                return Err(e);
            }
            self.chunks += 1;
        }
        self.last_time = elapsed_ms(started);
        Ok(())
    }

    fn write_job(
        &mut self,
        items: &mut [S7DataItem],
        job: &[(usize, usize)],
    ) -> Result<(), S7Error> {
        let parts: Vec<(ItemSpec, &[u8])> = job
            .iter()
            .map(|&(index, _)| (items[index].spec(), items[index].data.as_slice()))
            .collect();
        let (param, data) = write_var_request(&parts);
        let reply = self.job(param, data)?;
        if reply.error != 0 {
            for &(index, _) in job {
                items[index].result = Err(S7Error::from_cpu(reply.error));
            }
            return Ok(());
        }
        let codes = proto::decode_write_var_response(&reply, job.len())?;
        for (&(index, _), code) in job.iter().zip(codes) {
            items[index].result = match code {
                proto::item::SUCCESS => Ok(()),
                code => Err(S7Error::from_cpu(u16::from(code))),
            };
        }
        Ok(())
    }
}

/// The start of the element `done` elements after `start`.
fn advance(word_len: u8, start: u32, done: usize, size: usize) -> u32 {
    match word_len {
        S7_WL_BIT => start,
        S7_WL_COUNTER | S7_WL_TIMER => start + done as u32,
        _ => start + (done * size) as u32,
    }
}
