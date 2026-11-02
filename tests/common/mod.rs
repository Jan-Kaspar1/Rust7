//! A scripted PLC over loopback TCP for the client tests: it speaks the
//! ISO handshake and Setup Communication, then hands every other PDU to
//! the test's handler, which answers (or sends its own jobs) through
//! [`Session`].

#![allow(dead_code)]

use rust7::iso::{self, CotpParams, Tpdu, TPKT_HEADER_LEN};
use rust7::proto::{
    self, ItemResult, ItemSpec, Job, Pdu, Rosctr, Setup, UserDataParam, S7_AREA_CT, S7_AREA_TM,
};
use rust7::S7Client;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// How the PLC accepts connections.
#[derive(Clone)]
pub struct Options {
    /// The largest PDU it negotiates.
    pub pdu_limit: u16,
    /// The TPDU size code its connection confirm selects.
    pub tpdu_code: u8,
    /// Refuse the ISO connection with this DR reason.
    pub refuse: Option<u8>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            pdu_limit: 480,
            tpdu_code: iso::TPDU_SIZE_1024,
            refuse: None,
        }
    }
}

/// One connection, as the handler sees it.
pub struct Session {
    stream: TcpStream,
    tpdu_size: usize,
    /// The negotiated PDU size.
    pub pdu: u16,
    /// Every PDU the client sent, raw.
    pub log: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn read_tpdu(stream: &mut TcpStream) -> io::Result<Tpdu> {
    let mut header = [0u8; TPKT_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let len = iso::tpkt_length(&header).map_err(|e| io::Error::other(e.to_string()))?;
    let mut body = vec![0u8; len - TPKT_HEADER_LEN];
    stream.read_exact(&mut body)?;
    Tpdu::decode(&body).map_err(|e| io::Error::other(e.to_string()))
}

fn send_tpdu(stream: &mut TcpStream, tpdu: &Tpdu) -> io::Result<()> {
    stream.write_all(&iso::encode_tpkt(&tpdu.encode()).unwrap())
}

impl Session {
    /// Receives one PDU.
    pub fn recv(&mut self) -> io::Result<Pdu> {
        let mut payload = Vec::new();
        loop {
            match read_tpdu(&mut self.stream)? {
                Tpdu::Data { eot, payload: part } => {
                    payload.extend_from_slice(&part);
                    if eot {
                        break;
                    }
                }
                _ => return Err(io::Error::other("not a DT")),
            }
        }
        self.log.lock().unwrap().push(payload.clone());
        Pdu::decode(&payload).map_err(|e| io::Error::other(e.to_string()))
    }

    /// Sends raw PDU bytes, split into DT TPDUs of the negotiated size.
    pub fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let chunks: Vec<&[u8]> = bytes.chunks(self.tpdu_size - iso::DT_HEADER_LEN).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            send_tpdu(
                &mut self.stream,
                &Tpdu::Data {
                    eot: i + 1 == chunks.len(),
                    payload: chunk.to_vec(),
                },
            )?;
        }
        Ok(())
    }

    /// Writes raw bytes to the stream (for broken frames).
    pub fn send_raw_tpkt(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)
    }

    /// Sends one PDU.
    pub fn send(&mut self, pdu: &Pdu) -> io::Result<()> {
        self.send_raw(&pdu.encode())
    }

    /// Answers `request` with Ack_Data.
    pub fn ack(&mut self, request: &Pdu, param: Vec<u8>, data: Vec<u8>) -> io::Result<()> {
        self.send(&ack(request, param, data))
    }

    /// Answers `request` with a header error.
    pub fn refuse(&mut self, request: &Pdu, error: u16) -> io::Result<()> {
        self.send(&Pdu {
            rosctr: Rosctr::Ack,
            pdu_ref: request.pdu_ref,
            error,
            param: Vec::new(),
            data: Vec::new(),
        })
    }

    /// Answers a UserData request.
    pub fn userdata(
        &mut self,
        request: &Pdu,
        sequence: u8,
        last: bool,
        error: u16,
        data: Vec<u8>,
    ) -> io::Result<()> {
        let asked = UserDataParam::decode(&request.param).unwrap();
        let param = UserDataParam {
            method: 0x12,
            kind: 8,
            group: asked.group,
            subfunction: asked.subfunction,
            sequence,
            data_unit_ref: 0,
            last,
            error,
        }
        .encode_response();
        self.send(&Pdu {
            rosctr: Rosctr::UserData,
            pdu_ref: request.pdu_ref,
            error: 0,
            param,
            data,
        })
    }
}

/// Ack_Data for `request`.
pub fn ack(request: &Pdu, param: Vec<u8>, data: Vec<u8>) -> Pdu {
    Pdu {
        rosctr: Rosctr::AckData,
        pdu_ref: request.pdu_ref,
        error: 0,
        param,
        data,
    }
}

/// A UserData data part carrying `payload`.
pub fn ud_data(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0xFF, 0x09];
    data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// A running PLC.
pub struct Plc {
    pub address: SocketAddr,
    pub log: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Plc {
    /// Serves connections, handing each PDU after Setup Communication to
    /// `handler`.
    pub fn start<F>(options: Options, handler: F) -> Self
    where
        F: FnMut(&mut Session, Pdu) -> io::Result<()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let handler = Arc::new(Mutex::new(handler));
        let shared = Arc::clone(&log);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (options, handler, log) =
                    (options.clone(), Arc::clone(&handler), Arc::clone(&shared));
                thread::spawn(move || {
                    let _ = serve(stream, options, handler, log);
                });
            }
        });
        Self { address, log }
    }

    /// A client connected to this PLC.
    pub fn client(&self) -> S7Client {
        self.client_with(480)
    }

    /// A client proposing `pdu`, connected to this PLC.
    pub fn client_with(&self, pdu: u16) -> S7Client {
        let mut client = S7Client::new();
        client.set_connection_port(self.address.port()).unwrap();
        client.set_timeout(1000, 500, 500).unwrap();
        client.set_pdu_request(pdu).unwrap();
        client.connect_rack_slot("127.0.0.1", 0, 1).unwrap();
        client
    }

    /// The PDUs the client sent after Setup Communication.
    pub fn requests(&self) -> Vec<Pdu> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|bytes| Pdu::decode(bytes).ok())
            .filter(|pdu| pdu.param.first() != Some(&proto::function::SETUP))
            .collect()
    }
}

fn serve<F>(
    mut stream: TcpStream,
    options: Options,
    handler: Arc<Mutex<F>>,
    log: Arc<Mutex<Vec<Vec<u8>>>>,
) -> io::Result<()>
where
    F: FnMut(&mut Session, Pdu) -> io::Result<()>,
{
    let Tpdu::ConnectionRequest {
        src_ref, params, ..
    } = read_tpdu(&mut stream)?
    else {
        return Ok(());
    };
    if let Some(reason) = options.refuse {
        return send_tpdu(
            &mut stream,
            &Tpdu::DisconnectRequest {
                dst_ref: src_ref,
                src_ref: 0x44,
                reason,
            },
        );
    }
    send_tpdu(
        &mut stream,
        &Tpdu::ConnectionConfirm {
            dst_ref: src_ref,
            src_ref: 0x44,
            class: 0,
            params: CotpParams {
                tpdu_size: Some(options.tpdu_code),
                calling_tsap: params.calling_tsap,
                called_tsap: params.called_tsap,
            },
        },
    )?;
    let mut session = Session {
        stream,
        tpdu_size: iso::tpdu_size(options.tpdu_code).unwrap(),
        pdu: 240,
        log,
    };
    loop {
        let pdu = session.recv()?;
        if let Ok(Job::Setup(setup)) = Job::decode(&pdu) {
            session.pdu = setup.pdu_length.min(options.pdu_limit);
            let answer = Setup {
                max_amq_calling: 1,
                max_amq_called: 1,
                pdu_length: session.pdu,
            };
            session.ack(&pdu, answer.encode(), Vec::new())?;
            continue;
        }
        (handler.lock().unwrap())(&mut session, pdu)?;
    }
}

/// Areas by (area code, DB number).
pub type Areas = BTreeMap<(u8, u16), Vec<u8>>;

/// PLC memory answering Read / Write Var, as a handler.
#[derive(Clone, Default)]
pub struct Memory {
    pub areas: Arc<Mutex<Areas>>,
}

impl Memory {
    pub fn with(areas: &[((u8, u16), usize)]) -> Self {
        let memory = Self::default();
        for (key, size) in areas {
            let bytes = (0..*size).map(|i| i as u8).collect();
            memory.areas.lock().unwrap().insert(*key, bytes);
        }
        memory
    }

    pub fn get(&self, key: (u8, u16), at: usize, len: usize) -> Vec<u8> {
        self.areas.lock().unwrap()[&key][at..at + len].to_vec()
    }

    fn locate(&self, spec: &ItemSpec) -> Result<((u8, u16), usize, usize), u8> {
        let key = (spec.area, spec.db);
        let areas = self.areas.lock().unwrap();
        let memory = areas.get(&key).ok_or(proto::item::NOT_FOUND)?;
        let start = match spec.area {
            S7_AREA_CT | S7_AREA_TM => spec.byte() as usize * 2,
            _ => spec.byte() as usize,
        };
        let len = spec.byte_len();
        if start + len > memory.len() {
            return Err(proto::item::OUT_OF_RANGE);
        }
        Ok((key, start, len))
    }

    /// Answers a Read or Write Var job; anything else is refused 0x8104.
    pub fn answer(&self, session: &mut Session, pdu: &Pdu) -> io::Result<()> {
        match Job::decode(pdu) {
            Ok(Job::ReadVar(specs)) => {
                let results: Vec<(ItemSpec, ItemResult)> = specs
                    .iter()
                    .map(|spec| {
                        let result = match self.locate(spec) {
                            Ok((key, start, len)) => {
                                let areas = self.areas.lock().unwrap();
                                if spec.word_len == rust7::S7_WL_BIT {
                                    ItemResult::Data(vec![areas[&key][start] >> spec.bit() & 1])
                                } else {
                                    ItemResult::Data(areas[&key][start..start + len].to_vec())
                                }
                            }
                            Err(code) => ItemResult::Error(code),
                        };
                        (*spec, result)
                    })
                    .collect();
                let (param, data) = proto::read_var_response(&results);
                session.ack(pdu, param, data)
            }
            Ok(Job::WriteVar(items)) => {
                let codes: Vec<u8> = items
                    .iter()
                    .map(|(spec, bytes)| match self.locate(spec) {
                        Ok((key, start, len)) => {
                            let mut areas = self.areas.lock().unwrap();
                            let memory = areas.get_mut(&key).unwrap();
                            if spec.word_len == rust7::S7_WL_BIT {
                                if bytes[0] & 1 != 0 {
                                    memory[start] |= 1 << spec.bit();
                                } else {
                                    memory[start] &= !(1 << spec.bit());
                                }
                            } else if bytes.len() != len {
                                return proto::item::TYPE_INCONSISTENT;
                            } else {
                                memory[start..start + len].copy_from_slice(bytes);
                            }
                            proto::item::SUCCESS
                        }
                        Err(code) => code,
                    })
                    .collect();
                let (param, data) = proto::write_var_response(&codes);
                session.ack(pdu, param, data)
            }
            _ => session.refuse(pdu, 0x8104),
        }
    }
}

/// A PLC whose memory answers Read / Write Var.
pub fn memory_plc(options: Options, memory: Memory) -> Plc {
    Plc::start(options, move |session, pdu| memory.answer(session, &pdu))
}

/// Waits briefly — for a server thread to notice something.
pub fn settle() {
    thread::sleep(Duration::from_millis(50));
}
