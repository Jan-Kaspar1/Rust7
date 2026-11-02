//! Block, system-information, control, clock and security functions
//! against the scripted PLC. The request bytes asserted here are those
//! Snap7's client sends for the same calls.

mod common;

use common::{ud_data, Options, Plc};
use rust7::proto::{self, Pdu, Rosctr, UserDataParam};
use rust7::*;

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// An SZL answer's payload: the header and the records.
fn szl(id: u16, index: u16, record_len: u16, records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for word in [id, index, record_len, records.len() as u16] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    for record in records {
        assert_eq!(record.len(), record_len as usize);
        out.extend_from_slice(record);
    }
    out
}

fn record(index: u16, body: &[u8], len: usize) -> Vec<u8> {
    let mut out = index.to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out.resize(len, 0);
    out
}

/// A PLC answering UserData requests from a table of (group,
/// subfunction, request payload) → answer payload; a missing entry is
/// refused with 0xD401.
type Table = Vec<((u8, u8, Vec<u8>), Vec<u8>)>;

fn userdata_plc(table: Table) -> Plc {
    Plc::start(Options::default(), move |session, pdu| {
        let param = UserDataParam::decode(&pdu.param).unwrap();
        let payload = proto::userdata_payload(&pdu.data).unwrap().1.to_vec();
        match table
            .iter()
            .find(|((g, s, p), _)| *g == param.group && *s == param.subfunction && *p == payload)
        {
            Some((_, answer)) => session.userdata(&pdu, 0, true, 0, ud_data(answer)),
            None => session.userdata(&pdu, 0, true, 0xD401, vec![0x0A, 0, 0, 0]),
        }
    })
}

#[test]
fn reads_an_szl_that_comes_in_several_parts() {
    let records: Vec<Vec<u8>> = (1..=12u16).map(|i| record(i, &[i as u8; 10], 34)).collect();
    let whole = szl(0x001C, 0, 34, &records);
    let server = Plc::start(Options::default(), move |session, pdu| {
        let param = UserDataParam::decode(&pdu.param).unwrap();
        let (part, last) = match pdu.param.len() {
            8 => (&whole[..200], false),
            _ if param.sequence == 0x31 => (&whole[200..], true),
            _ => panic!("unexpected follow-up {:02x?}", pdu.param),
        };
        session.userdata(&pdu, 0x31, last, 0, ud_data(part))
    });
    let mut client = server.client();
    let answer = client.read_szl(0x001C, 0).unwrap();
    assert_eq!(
        (answer.id, answer.record_len, answer.record_count),
        (0x001C, 34, 12)
    );
    assert_eq!(answer.record(7).unwrap()[2], 7);
    let requests = server.requests();
    assert_eq!(requests[0].param, hex("00 01 12 04 11 44 01 00"));
    assert_eq!(requests[0].data, hex("ff 09 00 04 00 1c 00 00"));
    assert_eq!(
        requests[1].param,
        hex("00 01 12 08 12 44 01 31 00 00 00 00")
    );
    assert_eq!(requests[1].data, hex("0a 00 00 00"));
}

#[test]
fn an_szl_the_plc_lacks_is_item_not_available() {
    let server = userdata_plc(Vec::new());
    let mut client = server.client();
    let error = client.read_szl(0x0999, 0).unwrap_err();
    assert_eq!(
        (error.kind(), error.cpu_code()),
        (ErrorKind::ItemNotAvailable, Some(0xD401))
    );
    assert!(client.connected);
}

#[test]
fn system_information() {
    let order = szl(
        0x0011,
        0,
        28,
        &[
            record(1, b"6ES7 315-2EH14-0AB0 \x00\xc0\x00\x04\x00\x01", 28),
            record(7, b"                    \x00\xc0\x56\x03\x02\x06", 28),
            record(0x81, b"Boot Loader         \x00\x00\x41\x20\x09\x09", 28),
        ],
    );
    let cpu = szl(
        0x001C,
        0,
        34,
        &[
            record(1, b"SNAP7-SERVER", 34),
            record(2, b"CPU 315-2 PN/DP", 34),
            record(4, b"Original Siemens Equipment", 34),
            record(5, b"S C-C2UR28922012", 34),
            record(7, b"CPU 315-2 PN/DP", 34),
        ],
    );
    let cp = szl(
        0x0131,
        1,
        40,
        &[record(1, &hex("00 f0 00 10 00 b7 1b 00 00 02 dc 6c"), 40)],
    );
    let protection = szl(
        0x0232,
        4,
        40,
        &[record(4, &hex("00 01 00 00 00 01 00 02 00 00"), 40)],
    );
    let status = szl(
        0x0424,
        0,
        20,
        &[hex(
            "51 44 ff 08 00 00 00 00 00 00 00 00 26 11 02 09 07 11 00 01",
        )],
    );
    let list = szl(0, 0, 2, &[hex("00 11"), hex("00 1c"), hex("01 31")]);
    let request = |id: u16, index: u16| {
        let mut payload = id.to_be_bytes().to_vec();
        payload.extend_from_slice(&index.to_be_bytes());
        (proto::group::CPU, 1, payload)
    };
    let server = userdata_plc(vec![
        (request(0x0011, 0), order),
        (request(0x001C, 0), cpu),
        (request(0x0131, 1), cp),
        (request(0x0232, 4), protection),
        (request(0x0424, 0), status),
        (request(0, 0), list),
    ]);
    let mut client = server.client();
    // The firmware record's version, not the last three octets (which
    // here belong to the boot loader record).
    assert_eq!(
        client.get_order_code().unwrap(),
        S7OrderCode {
            code: "6ES7 315-2EH14-0AB0".into(),
            v1: 3,
            v2: 2,
            v3: 6
        }
    );
    assert_eq!(
        client.get_cpu_info().unwrap(),
        S7CpuInfo {
            module_type_name: "CPU 315-2 PN/DP".into(),
            serial_number: "S C-C2UR28922012".into(),
            as_name: "SNAP7-SERVER".into(),
            copyright: "Original Siemens Equipment".into(),
            module_name: "CPU 315-2 PN/DP".into(),
        }
    );
    assert_eq!(
        client.get_cp_info().unwrap(),
        S7CpInfo {
            max_pdu_length: 240,
            max_connections: 16,
            max_mpi_rate: 12_000_000,
            max_bus_rate: 187_500
        }
    );
    assert_eq!(
        client.get_protection().unwrap(),
        S7Protection {
            sch_schal: 1,
            sch_par: 0,
            sch_rel: 1,
            bart_sch: 2,
            anl_sch: 0
        }
    );
    assert_eq!(client.get_plc_status().unwrap(), CpuStatus::Run);
    assert_eq!(
        client.read_szl_list().unwrap(),
        vec![0x0011, 0x001C, 0x0131]
    );
}

#[test]
fn blocks_directory_and_info() {
    let mut info = vec![0u8; 78];
    for (i, byte) in info.iter_mut().enumerate() {
        *byte = 0x10 + i as u8;
    }
    let server = userdata_plc(vec![
        (
            (proto::group::BLOCK, 1, Vec::new()),
            hex("30 38 00 01 30 45 00 02 30 43 00 03 30 41 00 04 30 42 00 05 30 44 00 06 30 46 00 07"),
        ),
        ((proto::group::BLOCK, 2, hex("30 41")), hex("00 01 22 05 00 02 22 05 01 00 22 05")),
        ((proto::group::BLOCK, 3, b"0E00012A".to_vec()), info),
    ]);
    let mut client = server.client();
    let list = client.list_blocks().unwrap();
    assert_eq!(
        list,
        S7BlocksList {
            ob_count: 1,
            fb_count: 2,
            fc_count: 3,
            db_count: 4,
            sdb_count: 5,
            sfc_count: 6,
            sfb_count: 7
        }
    );
    let dbs = client.list_blocks_of_type(BLOCK_DB).unwrap();
    assert_eq!(
        dbs.iter().map(|b| b.number).collect::<Vec<_>>(),
        vec![1, 2, 256]
    );
    assert_eq!((dbs[0].flags, dbs[0].language), (0x22, 5));
    let none = client.list_blocks_of_type(BLOCK_FC).unwrap_err();
    assert_eq!(none.kind(), ErrorKind::ItemNotAvailable);
    assert_eq!(
        client.list_blocks_of_type(0x99).unwrap_err().kind(),
        ErrorKind::InvalidBlockType
    );
    // The fields at the offsets Snap7 reads them from.
    let info = client.get_ag_block_info(BLOCK_FB, 12).unwrap();
    assert_eq!(
        info,
        S7BlockInfo {
            block_type: 27,
            block_number: 7197,
            block_lang: 26,
            block_flags: 25,
            mc7_size: 14393,
            load_size: 505_356_321,
            local_data: 13879,
            sbb_length: 12851,
            checksum: 21589,
            version: 82,
            code_date: "2013/07/22".into(),
            intf_date: "2017/10/11".into(),
            author: ":;<=>?@A".into(),
            family: "BCDEFGHI".into(),
            header: "JKLMNOPQ".into(),
        }
    );
    let requests = server.requests();
    assert_eq!(requests[0].param, hex("00 01 12 04 11 43 01 00"));
    assert_eq!(requests[0].data, hex("0a 00 00 00"));
    assert_eq!(requests[1].data, hex("ff 09 00 02 30 41"));
    assert_eq!(
        requests.last().unwrap().data,
        hex("ff 09 00 08 30 45 30 30 30 31 32 41")
    );
}

/// A block of `body` bytes: header, body, footer.
fn block(sub_block_type: u8, number: u16, body: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8; 36];
    block[0..2].copy_from_slice(b"pp");
    block[2] = 1;
    block[3] = 1;
    block[4] = 5;
    block[5] = sub_block_type;
    block[6..8].copy_from_slice(&number.to_be_bytes());
    block[20..22].copy_from_slice(&10795u16.to_be_bytes());
    block[26..28].copy_from_slice(&12337u16.to_be_bytes());
    block[28..30].copy_from_slice(&0x5C5Du16.to_be_bytes());
    block[32..34].copy_from_slice(&0x6061u16.to_be_bytes());
    block[34..36].copy_from_slice(&(body.len() as u16).to_be_bytes());
    block.extend_from_slice(body);
    let mut footer = b"AUTHOR  FAMILY  NAME    ".to_vec();
    footer.resize(36, 0);
    block.extend_from_slice(&footer);
    let len = block.len() as u32;
    block[8..12].copy_from_slice(&len.to_be_bytes());
    block
}

#[test]
fn uploads_a_block_in_parts() {
    let body: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let image = block(0x0A, 1, &body);
    let served = image.clone();
    let mut sent = 0;
    let server = Plc::start(Options::default(), move |session, pdu| match pdu.param[0] {
        0x1D => session.ack(
            &pdu,
            hex("1d 00 01 00 00 00 00 07 07 30 30 30 30 33 37 32"),
            Vec::new(),
        ),
        0x1E => {
            assert_eq!(pdu.param, hex("1e 00 00 00 00 00 00 07"));
            let part = &served[sent..served.len().min(sent + 150)];
            sent += part.len();
            let mut data = (part.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&[0, 0xFB]);
            data.extend_from_slice(part);
            let more = u8::from(sent < served.len());
            if !(sent < served.len()) {
                sent = 0;
            }
            session.ack(&pdu, vec![0x1E, more], data)
        }
        0x1F => session.ack(&pdu, vec![0x1F], Vec::new()),
        _ => session.refuse(&pdu, 0x8104),
    });
    let mut client = server.client();
    let whole = client.full_upload(BLOCK_DB, 1).unwrap();
    assert_eq!(whole, image);
    assert_eq!(client.upload(BLOCK_DB, 1).unwrap(), body);
    let requests = server.requests();
    assert_eq!(
        requests[0].param,
        hex("1d 00 00 00 00 00 00 00 09 5f 30 41 30 30 30 30 31 41")
    );
    assert_eq!(requests.iter().filter(|r| r.param[0] == 0x1E).count(), 6);
    assert_eq!(requests[4].param, hex("1f 00 00 00 00 00 00 07"));
    let info = client.get_pg_block_info(&whole).unwrap();
    assert_eq!(
        (
            info.block_type,
            info.block_number,
            info.block_lang,
            info.block_flags
        ),
        (0x0A, 1, 5, 1)
    );
    assert_eq!((info.mc7_size, info.load_size as usize), (300, image.len()));
    assert_eq!((info.local_data, info.sbb_length), (0x6061, 0x5C5D));
    assert_eq!(
        (info.code_date.as_str(), info.intf_date.as_str()),
        ("2013/07/22", "2017/10/11")
    );
    assert_eq!(
        (
            info.author.as_str(),
            info.family.as_str(),
            info.header.as_str()
        ),
        ("AUTHOR", "FAMILY", "NAME")
    );
    let mut broken = whole.clone();
    broken.pop();
    assert_eq!(
        client.get_pg_block_info(&broken).unwrap_err().kind(),
        ErrorKind::InvalidBlockSize
    );
}

#[test]
fn an_upload_the_plc_refuses() {
    let server = Plc::start(Options::default(), |session, pdu| {
        session.refuse(&pdu, 0xD241)
    });
    let mut client = server.client();
    let error = client.full_upload(BLOCK_OB, 1).unwrap_err();
    assert_eq!(
        (error.kind(), error.cpu_code()),
        (ErrorKind::NeedPassword, Some(0xD241))
    );
}

#[test]
fn downloads_a_block_as_the_plc_asks_for_it() {
    let body: Vec<u8> = (0..500u32).map(|i| (i * 3) as u8).collect();
    let image = block(0x0A, 9, &body);
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let store = std::sync::Arc::clone(&received);
    let server = Plc::start(
        Options {
            pdu_limit: 240,
            ..Options::default()
        },
        move |session, pdu| match pdu.param[0] {
            0x1A => {
                session.ack(&pdu, vec![0x1A], Vec::new())?;
                let name = pdu.param[9..18].to_vec();
                let mut job = vec![0x1B, 0, 0, 0, 0, 0, 0, 0, 9];
                job.extend_from_slice(&name);
                for reference in 0x100.. {
                    session.send(&Pdu::request(
                        Rosctr::Job,
                        reference,
                        job.clone(),
                        Vec::new(),
                    ))?;
                    let answer = session.recv()?;
                    assert_eq!(
                        (answer.rosctr, answer.pdu_ref),
                        (Rosctr::AckData, reference)
                    );
                    let len = u16::from_be_bytes([answer.data[0], answer.data[1]]) as usize;
                    assert_eq!(&answer.data[2..4], &[0x00, 0xFB]);
                    assert!(answer.encode().len() <= 240);
                    store
                        .lock()
                        .unwrap()
                        .extend_from_slice(&answer.data[4..4 + len]);
                    if answer.param[1] == 0 {
                        break;
                    }
                }
                let mut end = job.clone();
                end[0] = 0x1C;
                session.send(&Pdu::request(Rosctr::Job, 0x200, end, Vec::new()))?;
                let answer = session.recv()?;
                assert_eq!(answer.param, vec![0x1C]);
                Ok(())
            }
            0x28 => session.ack(&pdu, vec![0x28], Vec::new()),
            _ => session.refuse(&pdu, 0x8104),
        },
    );
    let mut client = server.client_with(240);
    client.download(Some(12), &image).unwrap();
    let mut expected = image.clone();
    expected[6..8].copy_from_slice(&12u16.to_be_bytes());
    assert_eq!(*received.lock().unwrap(), expected);
    let requests = server.requests();
    let load = image.len();
    let mut request = hex("1a 00 01 00 00 00 00 00 09 5f 30 41 30 30 30 31 32 50 0d");
    request.extend_from_slice(format!("1{load:06}000500").as_bytes());
    assert_eq!(requests[0].param, request);
    assert_eq!(
        requests.last().unwrap().param,
        hex("28 00 00 00 00 00 00 fd 00 0a 01 00 30 41 30 30 30 31 32 50 05 5f 49 4e 53 45")
    );
    assert_eq!(
        client.download(None, &image[..50]).unwrap_err().kind(),
        ErrorKind::InvalidBlockSize
    );
}

#[test]
fn deletes_and_controls_the_plc() {
    let replies = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::VecDeque::<Vec<u8>>::new(),
    ));
    let queue = std::sync::Arc::clone(&replies);
    let server = Plc::start(Options::default(), move |session, pdu| {
        match queue.lock().unwrap().pop_front() {
            Some(param) if param.is_empty() => session.refuse(&pdu, 0x8402),
            Some(param) => session.ack(&pdu, param, Vec::new()),
            None => session.ack(&pdu, vec![pdu.param[0]], Vec::new()),
        }
    });
    let mut client = server.client();
    client.delete(BLOCK_DB, 7).unwrap();
    client.plc_hot_start().unwrap();
    client.plc_cold_start().unwrap();
    client.plc_stop().unwrap();
    client.copy_ram_to_rom(5000).unwrap();
    client.compress(5000).unwrap();
    let params: Vec<Vec<u8>> = server.requests().into_iter().map(|r| r.param).collect();
    assert_eq!(
        params,
        vec![
            hex("28 00 00 00 00 00 00 fd 00 0a 01 00 30 41 30 30 30 30 37 42 05 5f 44 45 4c 45"),
            hex("28 00 00 00 00 00 00 fd 00 00 09 50 5f 50 52 4f 47 52 41 4d"),
            hex("28 00 00 00 00 00 00 fd 00 02 43 20 09 50 5f 50 52 4f 47 52 41 4d"),
            hex("29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d"),
            hex("28 00 00 00 00 00 00 fd 00 02 45 50 05 5f 4d 4f 44 55"),
            hex("28 00 00 00 00 00 00 fd 00 00 05 5f 47 41 52 42"),
        ]
    );
    replies
        .lock()
        .unwrap()
        .extend([vec![0x28, 0x02], vec![0x29, 0x07], Vec::new(), Vec::new()]);
    assert_eq!(
        client.plc_hot_start().unwrap_err().kind(),
        ErrorKind::AlreadyRun
    );
    assert_eq!(
        client.plc_stop().unwrap_err().kind(),
        ErrorKind::AlreadyStop
    );
    let error = client.plc_cold_start().unwrap_err();
    assert_eq!(
        (error.kind(), error.cpu_code()),
        (ErrorKind::CannotStartPlc, Some(0x8402))
    );
    assert_eq!(
        client.delete(BLOCK_DB, 7).unwrap_err().kind(),
        ErrorKind::DeleteRefused
    );
    assert_eq!(
        client.compress(0).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
}

#[test]
fn reads_and_sets_the_clock() {
    let server = userdata_plc(vec![
        (
            (proto::group::TIME, 1, Vec::new()),
            hex("00 20 26 11 02 13 45 56 78 92"),
        ),
        (
            (proto::group::TIME, 2, hex("00 19 26 11 02 13 45 56 78 92")),
            Vec::new(),
        ),
    ]);
    let mut client = server.client();
    let time = client.get_plc_date_time().unwrap();
    assert_eq!(
        time,
        S7DateTime {
            year: 2026,
            month: 11,
            day: 2,
            hour: 13,
            minute: 45,
            second: 56,
            millisecond: 789,
            weekday: 2
        }
    );
    // The weekday is computed from the date (2026-11-02 is a Monday).
    client
        .set_plc_date_time(&S7DateTime { weekday: 0, ..time })
        .unwrap();
    let bad = S7DateTime { month: 13, ..time };
    assert_eq!(
        client.set_plc_date_time(&bad).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    let wrong_day = S7DateTime { day: 3, ..time };
    assert_eq!(
        client.set_plc_date_time(&wrong_day).unwrap_err().cpu_code(),
        Some(0xD401)
    );
    assert_eq!(
        S7DateTime::from_unix(1_793_623_556, 789),
        S7DateTime { hour: 12, ..time }
    );
}

#[test]
fn sends_and_clears_the_session_password() {
    let server = userdata_plc(vec![
        (
            (proto::group::SECURITY, 1, hex("34 37 02 06 66 61 00 00")),
            Vec::new(),
        ),
        ((proto::group::SECURITY, 2, Vec::new()), Vec::new()),
    ]);
    let mut client = server.client();
    client.set_session_password("abcd1234").unwrap();
    client.clear_session_password().unwrap();
    let error = client.set_session_password("wrong").unwrap_err();
    assert_eq!(error.cpu_code(), Some(0xD401));
    assert_eq!(
        client.set_session_password("toolong12").unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    let server = Plc::start(Options::default(), |session, pdu| {
        session.userdata(&pdu, 0, true, 0xD602, vec![0x0A, 0, 0, 0])
    });
    let mut client = server.client();
    assert_eq!(
        client.set_session_password("x").unwrap_err().kind(),
        ErrorKind::InvalidPassword
    );
}

#[test]
fn a_download_the_plc_ends_with_an_error_fails() {
    let image = block(0x0A, 3, &[1, 2, 3, 4]);
    let server = Plc::start(Options::default(), move |session, pdu| match pdu.param[0] {
        0x1A => {
            session.ack(&pdu, vec![0x1A], Vec::new())?;
            let mut job = vec![0x1B, 0, 0, 0, 0, 0, 0, 0, 9];
            job.extend_from_slice(&pdu.param[9..18]);
            session.send(&Pdu::request(Rosctr::Job, 0x100, job.clone(), Vec::new()))?;
            session.recv()?;
            // Download ended with error code 0x8003.
            job[0] = 0x1C;
            job[2] = 0x80;
            job[3] = 0x03;
            session.send(&Pdu::request(Rosctr::Job, 0x101, job, Vec::new()))?;
            session.recv()?;
            Ok(())
        }
        _ => session.ack(&pdu, vec![pdu.param[0]], Vec::new()),
    });
    let mut client = server.client();
    let error = client.download(None, &image).unwrap_err();
    assert_eq!(
        (error.kind(), error.cpu_code()),
        (ErrorKind::DownloadSequenceFailed, Some(0x8003))
    );
    // No insert was attempted.
    assert!(server.requests().iter().all(|r| r.param[0] != 0x28));
}

#[test]
fn an_upload_shorter_than_announced_fails() {
    let server = Plc::start(Options::default(), |session, pdu| match pdu.param[0] {
        0x1D => session.ack(
            &pdu,
            hex("1d 00 01 00 00 00 00 07 07 30 30 30 30 33 37 32"),
            Vec::new(),
        ),
        0x1E => session.ack(&pdu, vec![0x1E, 0], hex("00 02 00 fb 01 02")),
        _ => session.ack(&pdu, vec![pdu.param[0]], Vec::new()),
    });
    let mut client = server.client();
    let error = client.full_upload(BLOCK_DB, 1).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidDataSizeReceived);
}
