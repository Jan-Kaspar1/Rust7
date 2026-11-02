//! Connection, areas, and multi-variable access against the scripted PLC.

mod common;

use common::{memory_plc, Memory, Options, Plc};
use rust7::proto::{self, Job, Pdu};
use rust7::*;
use std::time::{Duration, Instant};

fn plc(options: Options) -> (Plc, Memory) {
    let memory = Memory::with(&[
        ((S7_AREA_DB, 1), 2000),
        ((S7_AREA_DB, 2), 16),
        ((S7_AREA_MK, 0), 64),
        ((S7_AREA_PE, 0), 64),
        ((S7_AREA_PA, 0), 64),
        ((S7_AREA_CT, 0), 64),
        ((S7_AREA_TM, 0), 64),
    ]);
    (memory_plc(options, memory.clone()), memory)
}

#[test]
fn negotiates_the_pdu_never_above_the_proposal() {
    let (server, _) = plc(Options {
        pdu_limit: 960,
        ..Options::default()
    });
    assert_eq!(server.client_with(480).pdu_length, 480);
    let (server, _) = plc(Options {
        pdu_limit: 240,
        ..Options::default()
    });
    let client = server.client_with(960);
    assert_eq!(client.pdu_length(), 240);
    assert!(client.connected());
}

#[test]
fn a_refused_tsap_is_an_iso_connect_error_naming_the_reason() {
    let server = Plc::start(
        Options {
            refuse: Some(2),
            ..Options::default()
        },
        |_, _| Ok(()),
    );
    let mut client = S7Client::new();
    client.set_connection_port(server.address.port()).unwrap();
    let error = client.connect_rack_slot("127.0.0.1", 0, 3).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IsoConnect);
    assert_eq!(error.code(), 0x0001_0000);
    let text = error.to_string();
    assert!(
        text.contains("session entity not attached to TSAP"),
        "{text}"
    );
    assert!(text.contains("remote TSAP 0x0103"), "{text}");
    assert!(!client.connected());
}

#[test]
fn connection_types_and_tsaps_shape_the_connection_request() {
    let (server, _) = plc(Options::default());
    let mut client = S7Client::new();
    client.set_connection_port(server.address.port()).unwrap();
    client.set_connection_type(CT_OP).unwrap();
    client.connect_rack_slot("127.0.0.1", 1, 4).unwrap();
    assert_eq!(client.remote_tsap(), 0x0224);
    assert_eq!(client.local_tsap(), 0x0100);
    assert!(client.set_connection_type(4).is_err());
    client.connect_tsap("127.0.0.1", 0x1000, 0x2000).unwrap();
    assert_eq!(client.remote_tsap(), 0x2000);
    // Reconnect with the stored parameters.
    client.disconnect();
    assert_eq!(
        client.read_db(1, 0, &mut [0; 1]).unwrap_err().kind(),
        ErrorKind::TcpNotConnected
    );
    client.connect().unwrap();
    client.read_db(1, 0, &mut [0; 1]).unwrap();
}

#[test]
fn reads_and_writes_split_across_pdus() {
    let (server, memory) = plc(Options {
        pdu_limit: 240,
        ..Options::default()
    });
    let mut client = server.client_with(240);
    let mut buffer = vec![0u8; 1000];
    client.read_db(1, 100, &mut buffer).unwrap();
    assert_eq!(buffer, memory.get((S7_AREA_DB, 1), 100, 1000));
    assert_eq!(client.chunks, 1000usize.div_ceil(240 - 18));
    let data: Vec<u8> = (0..900u32).map(|i| (i * 7) as u8).collect();
    client.write_db(1, 3, &data).unwrap();
    assert_eq!(memory.get((S7_AREA_DB, 1), 3, 900), data);
    assert_eq!(client.chunks, 900usize.div_ceil(240 - 28));
    for request in server.requests() {
        assert!(request.encode().len() <= 240);
    }
}

#[test]
fn word_lengths_counters_and_timers() {
    let (server, memory) = plc(Options::default());
    let mut client = server.client();
    let mut words = [0u8; 8];
    client
        .read_area(S7_AREA_DB, 1, 10, S7_WL_WORD, &mut words)
        .unwrap();
    assert_eq!(words.to_vec(), memory.get((S7_AREA_DB, 1), 10, 8));
    assert_eq!(
        client
            .read_area(S7_AREA_DB, 1, 10, S7_WL_REAL, &mut [0u8; 6])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidParams
    );
    assert_eq!(
        client
            .read_area(S7_AREA_DB, 1, 0, 0x42, &mut [0u8; 2])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidWordLen
    );
    let mut counters = [0u8; 6];
    client.read_ct(4, &mut counters).unwrap();
    assert_eq!(counters.to_vec(), memory.get((S7_AREA_CT, 0), 8, 6));
    client.write_tm(2, &[0x12, 0x34]).unwrap();
    assert_eq!(memory.get((S7_AREA_TM, 0), 4, 2), vec![0x12, 0x34]);
    // A counter item addresses the element, not a bit address, and is
    // written as an octet string.
    let requests = server.requests();
    let write = requests.last().unwrap();
    assert_eq!(
        &write.param[2..14],
        &[0x12, 0x0A, 0x10, 0x1D, 0, 1, 0, 0, 0x1D, 0, 0, 2]
    );
    assert_eq!(&write.data, &[0x00, 0x09, 0x00, 0x02, 0x12, 0x34]);
    for (read, write) in [
        (
            S7Client::read_mb as fn(&mut S7Client, u32, &mut [u8]) -> _,
            S7_AREA_MK,
        ),
        (S7Client::read_eb, S7_AREA_PE),
        (S7Client::read_ab, S7_AREA_PA),
    ] {
        let mut bytes = [0u8; 3];
        read(&mut client, 5, &mut bytes).unwrap();
        assert_eq!(bytes.to_vec(), memory.get((write, 0), 5, 3));
    }
    client.write_mb(1, &[9]).unwrap();
    client.write_ab(2, &[8]).unwrap();
    client.write_eb(3, &[7]).unwrap();
    assert_eq!(memory.get((S7_AREA_MK, 0), 1, 1), [9]);
    assert_eq!(memory.get((S7_AREA_PA, 0), 2, 1), [8]);
    assert_eq!(memory.get((S7_AREA_PE, 0), 3, 1), [7]);
}

#[test]
fn bits_touch_only_their_bit() {
    let (server, memory) = plc(Options::default());
    let mut client = server.client();
    let before = memory.get((S7_AREA_MK, 0), 7, 1)[0];
    client
        .write_bit(S7_AREA_MK, 0, 7, 3, before & 0x08 == 0)
        .unwrap();
    assert_eq!(memory.get((S7_AREA_MK, 0), 7, 1)[0], before ^ 0x08);
    assert_eq!(
        client.read_bit(S7_AREA_MK, 0, 7, 3).unwrap(),
        before & 0x08 == 0
    );
    assert_eq!(
        client.read_bit(S7_AREA_MK, 0, 7, 8).unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    let request = server
        .requests()
        .into_iter()
        .find(|r| r.param[0] == 0x05)
        .unwrap();
    // Bit transport, bit address 7 * 8 + 3, data transport 0x03 of 1 bit.
    assert_eq!(
        &request.param[2..14],
        &[0x12, 0x0A, 0x10, 0x01, 0, 1, 0, 0, 0x83, 0, 0, 59]
    );
    assert_eq!(&request.data[..4], &[0x00, 0x03, 0x00, 0x01]);
}

#[test]
fn refusals_carry_the_plc_code() {
    let (server, _) = plc(Options::default());
    let mut client = server.client();
    let missing = client.read_db(9, 0, &mut [0; 4]).unwrap_err();
    assert_eq!(
        (missing.kind(), missing.cpu_code()),
        (ErrorKind::ItemNotAvailable, Some(0x0A))
    );
    assert_eq!(missing.code(), 0x00C0_0000);
    let beyond = client.write_db(2, 14, &[1, 2, 3, 4]).unwrap_err();
    assert_eq!(
        (beyond.kind(), beyond.cpu_code()),
        (ErrorKind::AddressOutOfRange, Some(0x05))
    );
    assert!(beyond.is_cpu() && !beyond.is_link());
    // A refusal keeps the connection.
    assert!(client.connected);
    client.read_db(1, 0, &mut [0; 4]).unwrap();
}

#[test]
fn multi_vars_pack_into_jobs_that_fit_the_pdu() {
    let (server, memory) = plc(Options {
        pdu_limit: 240,
        ..Options::default()
    });
    let mut client = server.client_with(240);
    let mut items: Vec<S7DataItem> = (0..45)
        .map(|i| S7DataItem::read(S7_AREA_DB, 1, i * 11, 1 + (i % 7) as u16, S7_WL_BYTE))
        .collect();
    items.push(S7DataItem::read(S7_AREA_DB, 9, 0, 2, S7_WL_BYTE));
    items.push(S7DataItem::read(S7_AREA_DB, 1, 0, 300, S7_WL_BYTE));
    items.push(S7DataItem::read(S7_AREA_MK, 0, 8 * 2 + 5, 1, S7_WL_BIT));
    items.push(S7DataItem::read(S7_AREA_DB, 1, 0, 2, 0x55));
    client.read_multi_vars(&mut items).unwrap();
    for (i, item) in items[..45].iter().enumerate() {
        assert_eq!(item.result, Ok(()));
        assert_eq!(item.data, memory.get((S7_AREA_DB, 1), i * 11, 1 + i % 7));
    }
    assert_eq!(
        items[45].result.as_ref().unwrap_err().cpu_code(),
        Some(0x0A)
    );
    assert_eq!(
        items[46].result.as_ref().unwrap_err().kind(),
        ErrorKind::SizeOverPdu
    );
    assert_eq!(
        items[47].data,
        vec![memory.get((S7_AREA_MK, 0), 2, 1)[0] >> 5 & 1]
    );
    assert_eq!(
        items[48].result.as_ref().unwrap_err().kind(),
        ErrorKind::InvalidWordLen
    );
    let reads: Vec<Pdu> = server
        .requests()
        .into_iter()
        .filter(|r| r.param[0] == 0x04)
        .collect();
    assert_eq!(reads.len(), client.chunks);
    assert!(reads.len() >= 3);
    for read in &reads {
        assert!(read.param[1] as usize <= MAX_VARS);
        assert!(read.encode().len() <= 240);
    }
}

#[test]
fn multi_var_writes_report_each_item() {
    let (server, memory) = plc(Options::default());
    let mut client = server.client();
    let mut items = vec![
        S7DataItem::write(S7_AREA_DB, 1, 4, S7_WL_BYTE, vec![1, 2, 3]),
        S7DataItem::write(S7_AREA_DB, 1, 9, S7_WL_WORD, vec![4, 5]),
        S7DataItem::write(S7_AREA_DB, 2, 15, S7_WL_WORD, vec![6, 7]),
        S7DataItem::write(S7_AREA_MK, 0, 8 * 3 + 1, S7_WL_BIT, vec![1]),
        S7DataItem::write(S7_AREA_DB, 1, 0, S7_WL_REAL, vec![1, 2]),
    ];
    let mk = memory.get((S7_AREA_MK, 0), 3, 1)[0];
    client.write_multi_vars(&mut items).unwrap();
    assert_eq!(items[0].result, Ok(()));
    assert_eq!(items[1].result, Ok(()));
    assert_eq!(items[2].result.as_ref().unwrap_err().cpu_code(), Some(0x05));
    assert_eq!(items[3].result, Ok(()));
    assert_eq!(
        items[4].result.as_ref().unwrap_err().kind(),
        ErrorKind::InvalidParams
    );
    assert_eq!(memory.get((S7_AREA_DB, 1), 4, 3), vec![1, 2, 3]);
    assert_eq!(memory.get((S7_AREA_DB, 1), 9, 2), vec![4, 5]);
    assert_eq!(memory.get((S7_AREA_MK, 0), 3, 1)[0], mk | 0x02);
    // One job: the odd-length item is followed by a fill byte, the word
    // item travels as a byte transport counted in bits.
    let write = server
        .requests()
        .into_iter()
        .find(|r| r.param[0] == 0x05)
        .unwrap();
    assert_eq!(write.param[1], 4);
    assert_eq!(
        &write.data[..12],
        &[0, 0x04, 0, 24, 1, 2, 3, 0, 0, 0x04, 0, 16]
    );
}

#[test]
fn a_header_error_refuses_each_item_of_its_job_only() {
    let memory = Memory::with(&[((S7_AREA_DB, 1), 2000)]);
    let mut jobs = 0;
    let server = Plc::start(Options::default(), move |session, pdu| {
        jobs += 1;
        if jobs == 2 {
            return session.refuse(&pdu, 0x8304);
        }
        memory.answer(session, &pdu)
    });
    let mut client = server.client();
    let mut items: Vec<S7DataItem> = (0..30)
        .map(|i| S7DataItem::read(S7_AREA_DB, 1, i * 4, 2, S7_WL_BYTE))
        .collect();
    client.read_multi_vars(&mut items).unwrap();
    assert!(items[..20].iter().all(|i| i.result.is_ok()));
    for item in &items[20..] {
        let error = item.result.as_ref().unwrap_err();
        assert_eq!(
            (error.kind(), error.cpu_code()),
            (ErrorKind::FunctionRefused, Some(0x8304))
        );
    }
}

#[test]
fn pdus_travel_in_small_tpdus_both_ways() {
    let (server, memory) = plc(Options {
        tpdu_code: 7,
        pdu_limit: 480,
        ..Options::default()
    });
    let mut client = server.client_with(480);
    let mut buffer = vec![0u8; 400];
    client.read_db(1, 0, &mut buffer).unwrap();
    assert_eq!(buffer, memory.get((S7_AREA_DB, 1), 0, 400));
    let data = vec![0x5A; 400];
    client.write_db(1, 0, &data).unwrap();
    assert_eq!(memory.get((S7_AREA_DB, 1), 0, 400), data);
}

#[test]
fn a_silent_plc_times_out_and_closes_the_connection() {
    let server = Plc::start(Options::default(), |_, _| Ok(()));
    let mut client = server.client();
    let started = Instant::now();
    let error = client.read_db(1, 0, &mut [0; 2]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TcpReceiveTimeout);
    assert!(error.is_link());
    assert!(started.elapsed() >= Duration::from_millis(450));
    assert!(!client.connected);
    assert_eq!(
        client.read_db(1, 0, &mut [0; 2]).unwrap_err().kind(),
        ErrorKind::TcpNotConnected
    );
}

#[test]
fn a_reply_to_another_request_closes_the_connection() {
    let server = Plc::start(Options::default(), |session, mut pdu| {
        pdu.pdu_ref = pdu.pdu_ref.wrapping_add(7);
        let (param, data) = proto::read_var_response(&[]);
        session.ack(&pdu, param, data)
    });
    let mut client = server.client();
    let error = client.read_db(1, 0, &mut [0; 2]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidPlcAnswer);
    assert!(error.to_string().contains("PDU reference"));
    assert!(!client.connected);
}

#[test]
fn a_reply_cut_off_mid_frame_is_a_receive_error() {
    let server = Plc::start(Options::default(), |session, pdu| {
        let bytes = common::ack(&pdu, vec![4, 1], vec![0xFF, 4, 0, 16, 1, 2]).encode();
        // A TPKT announcing the whole reply, then only half of it.
        let mut frame = vec![3, 0];
        frame.extend_from_slice(&((bytes.len() + 7) as u16).to_be_bytes());
        frame.extend_from_slice(&[2, 0xF0, 0x80]);
        frame.extend_from_slice(&bytes[..bytes.len() / 2]);
        session.send_raw_tpkt(&frame)
    });
    let mut client = server.client();
    let error = client.read_db(1, 0, &mut [0; 2]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IsoRecvPacket);
    assert!(!client.connected);
}

#[test]
fn iso_exchange_buffer_passes_pdus_through() {
    let (server, memory) = plc(Options::default());
    let mut client = server.client();
    let request = Pdu::request(
        proto::Rosctr::Job,
        0x4242,
        proto::read_var_param(&[proto::ItemSpec::new(S7_AREA_DB, 1, 5, 3, S7_WL_BYTE)]),
        Vec::new(),
    );
    let reply = Pdu::decode(&client.iso_exchange_buffer(&request.encode()).unwrap()).unwrap();
    assert_eq!(reply.pdu_ref, 0x4242);
    let results = proto::decode_read_var_response(&reply, 1).unwrap();
    assert_eq!(
        results,
        vec![proto::ItemResult::Data(memory.get((S7_AREA_DB, 1), 5, 3))]
    );
    assert!(matches!(Job::decode(&request), Ok(Job::ReadVar(_))));
}

#[test]
fn error_codes_and_texts_follow_snap7() {
    assert_eq!(ErrorKind::TcpReceiveTimeout.code(), 0x0000_0004);
    assert_eq!(ErrorKind::IsoInvalidPdu.code(), 0x0003_0000);
    assert_eq!(ErrorKind::FunctionRefused.code(), 0x0230_0000);
    assert_eq!(
        ErrorKind::from_code(0x01D0_0000),
        Some(ErrorKind::NeedPassword)
    );
    assert_eq!(ErrorKind::from_cpu(0xD241), ErrorKind::NeedPassword);
    assert_eq!(ErrorKind::from_cpu(0x8104), ErrorKind::FunNotAvailable);
    assert_eq!(ErrorKind::from_cpu(0x0001), ErrorKind::FunctionRefused);
    assert_eq!(error_text(0), "OK");
    assert_eq!(
        error_text(0x000A_0004),
        "TCP : no reply within the receive timeout, ISO : receive packet error"
    );
    assert_eq!(
        cpu_error_text(0x8104),
        Some("this service is not implemented on the module or a frame error was reported")
    );
    let error = S7Error::from_cpu(0x8104);
    assert!(error.to_string().contains("PLC code 0x8104"));
}

#[test]
fn a_plc_granting_no_parallel_job_is_refused() {
    let (server, _) = plc(Options {
        jobs: 0,
        ..Options::default()
    });
    let mut client = S7Client::new();
    client.set_connection_port(server.address.port()).unwrap();
    let error = client.connect_rack_slot("127.0.0.1", 0, 1).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NegotiatingPdu);
    assert!(!client.connected);
}

#[test]
fn a_malformed_answer_closes_the_connection() {
    // A write acknowledged with an extra octet after the item codes.
    let server = Plc::start(Options::default(), |session, pdu| {
        session.ack(&pdu, vec![0x05, 1], vec![0xFF, 0x05])
    });
    let mut client = server.client();
    let error = client.write_db(1, 0, &[1]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidPlcAnswer);
    assert!(!client.connected);
}

#[test]
fn a_zero_cotp_length_indicator_is_an_error() {
    assert_eq!(
        rust7::iso::Tpdu::decode(&[0x00, 0xF0, 0x80])
            .unwrap_err()
            .kind(),
        ErrorKind::IsoInvalidPdu
    );
}

#[test]
fn octets_beyond_the_announced_lengths_close_the_connection() {
    let server = Plc::start(Options::default(), |session, pdu| {
        let mut bytes = common::ack(&pdu, vec![0x05, 1], vec![0xFF]).encode();
        bytes.push(0x00);
        session.send_raw(&bytes)
    });
    let mut client = server.client();
    let error = client.write_db(1, 0, &[1]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IsoInvalidDataSize);
    assert!(!client.connected);
}
