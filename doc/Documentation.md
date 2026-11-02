# Rust7 manual
## Background

This project is directly derived from <a href="https://github.com/davenardella/snap7" target="_blank">Snap7</a>. For more information on data formatting (endianess), PLC areas, etc., I recommend referring to the original project documentation, available into /doc folder.

---
## Briefly
Communication with Siemens PLCs via the S7 protocovl occurs according to the classic client-server model, in which the PC is the client and the PLC is the server.

The mechanism is quite simple: to read or write data to a PLC, you must first connect to it and then send a read request, after which you will receive the data, or a write request containing the data to be written.
In both cases, you will receive a response containing the outcome of the operation.

![cli srv](img/cli-srv.png)

### Connection
The S7 protocol is encapsulated in TCP/IP, so the connection must first follow TCP/IP rules, meaning it must contain the IP address and port.
In reality, there are other parameters, such as Rack and Slot or TSAP records, but there are support methods that hide these details.

![s7 encapsulation](img/s7_encapsulation.png)

There are four connection methods available:

* `connect_s71200_1500()` 
* `connect_s7300()` 
* `connect_rack_slot()`
* `connect_tsap()`

The first two are fairly self-explanatory; the third is for use with **S7400**, **WinAC**, and **Sinamics**; the rack and slot parameters will be copied from the project's hardware configuration.
The fourth is for use with **LOGO!** or **S7200** only.
We'll explore these in detail in the API. 

---

### Workflow

**First consideration:**

The connection process is quite complex, and the PLC is not a web server, so the connection must be kept active at all times.

**Second consideration:**

There is no such thing as problem-free communication, and this case is no exception. The library reports two categories of errors: low-level errors such as TCP, corrupt headers due to fragmented packets, etc., and high-level errors, such as a read request from a non-existent database.
In the first case, it is **strongly recommended** to disconnect from the PLC and reconnect before performing any other operations. This behavior is the same as that adopted by WinCC and all other SCADA programs.

**Third consideration:**

Your software will almost certainly have a thread-loop for reading and writing data ciclically, and you'll also have to handle communication errors, such as a physical disconnection of the network cable, without reporting errors, pop-ups, or clogging the system with exceptions to handle.  
But above all, the software must be **pass-through** (non-blocking)

What should we do?

Over the years, this is the question I've been asked most frequently.
So I'll show you a workflow that's the same one we use (not just with Snap7).

First, since low-level error handling involves disconnecting and connecting, these two methods will become part of our loop. When we initialize the program, we'll simply create the Client object and optionally preset the connection (set a port other than 102, set timeouts, etc.).


![workflow](img/workflow.png)

A very simplistic pseudo-code would be this:

```rust
while !exit_request{
    
    if !Client.connected {
        let _ = client.connect_s71200_1500(ip_address);
    }
    
    if Client.connected {
        if !do_read_and_write() { // <-- returns false when severe error occurs
            Client.disconnect();
        }
    }

    thread::sleep(100);
}
```


# API
---

The client implements Snap7's `TS7Client` function set. Every method returns
`Result<_, S7Error>`; the rustdoc of each method (`cargo doc --open`) has the
details. The asynchronous `As*` variants of Snap7 are not provided: the client is
synchronous; run it on its own thread.

#### Connection setup

|Prototype|Snap7|Behaviour|
|---|---|---|
|`set_connection_type(u16)`|`SetConnectionType`|`CT_PG` (default), `CT_OP` or `CT_S7`: the high byte of the remote TSAP|
|`set_timeout(co, rd, wr)`|`SetParam` (timeouts)|TCP connect, reply, and send timeouts in ms (3000, 1000, 500)|
|`set_connection_port(u16)`|`SetParam(RemotePort)`|TCP port (102)|
|`set_pdu_request(u16)`|`SetParam(PDURequest)`|PDU size proposed when connecting, 240..=960 (480)|
|`set_connection_params(addr, local_tsap, remote_tsap)`|`SetConnectionParams`|Address and TSAPs for `connect()`|

#### Connection

|Prototype|Snap7|Behaviour|
|---|---|---|
|`connect_s71200_1500(ip)`|`ConnectTo(ip, 0, 0)`|Connects to an S7-1200/1500|
|`connect_s7300(ip)`|`ConnectTo(ip, 0, 2)`|Connects to an S7-300|
|`connect_rack_slot(ip, rack, slot)`|`ConnectTo`|Connects using rack and slot|
|`connect_tsap(ip, local_tsap, remote_tsap)`|`SetConnectionParams` + `Connect`|Connects using TSAPs (LOGO!, S7-200)|
|`connect()`|`Connect`|Connects (again) with the stored parameters|
|`disconnect()`|`Disconnect`|Closes the connection|

`ip` may be a host name, an IPv4 address, or an IPv6 address with or without
brackets.

#### Data I/O

|Prototype|Snap7|Behaviour|
|---|---|---|
|`read_area(area, db, start: u32, word_len, &mut [u8])`|`ReadArea`|Reads any area with any word length; split by PDU|
|`write_area(area, db, start: u32, word_len, &[u8])`|`WriteArea`|Writes any area with any word length; split by PDU|
|`read_db` / `write_db`|`DBRead` / `DBWrite`|DB bytes|
|`read_mb` / `write_mb`|`MBRead` / `MBWrite`|Merker bytes|
|`read_eb` / `write_eb`|`EBRead` / `EBWrite`|Process-input bytes|
|`read_ab` / `write_ab`|`ABRead` / `ABWrite`|Process-output bytes|
|`read_tm` / `write_tm`|`TMRead` / `TMWrite`|Timers (2 bytes each)|
|`read_ct` / `write_ct`|`CTRead` / `CTWrite`|Counters (2 bytes each)|
|`read_bit` / `write_bit`|—|One bit|
|`read_multi_vars(&mut [S7DataItem])`|`ReadMultiVars`|Several variables, packed into as few jobs as the PDU allows|
|`write_multi_vars(&mut [S7DataItem])`|`WriteMultiVars`|Several variables, packed likewise|

Areas: `S7_AREA_PE` (inputs), `S7_AREA_PA` (outputs), `S7_AREA_MK` (merkers),
`S7_AREA_DB`, `S7_AREA_CT` (counters), `S7_AREA_TM` (timers). Word lengths:
`S7_WL_BIT`, `S7_WL_BYTE`, `S7_WL_CHAR`, `S7_WL_WORD`, `S7_WL_INT`, `S7_WL_DWORD`,
`S7_WL_DINT`, `S7_WL_REAL`, `S7_WL_COUNTER`, `S7_WL_TIMER`. For bit access `start`
is `byte * 8 + bit`; for counters and timers it is the element number; otherwise
the byte offset.

Snap7 limits a multi-variable call to 20 items in one PDU. Rust7 packs the items
into as many jobs as needed (at most 20 items each, request and response within
the negotiated PDU); a job the PLC refuses as a whole gives its refusal to each of
its items. Each `S7DataItem` carries its own `result`.

#### Blocks

|Prototype|Snap7|Behaviour|
|---|---|---|
|`list_blocks()`|`ListBlocks`|Block count per type|
|`list_blocks_of_type(block_type)`|`ListBlocksOfType`|Numbers, flags and languages of one type|
|`get_ag_block_info(block_type, number)`|`GetAgBlockInfo`|A block's properties, from the PLC|
|`get_pg_block_info(&[u8])`|`GetPgBlockInfo`|A block's properties, from an uploaded block|
|`full_upload(block_type, number)`|`FullUpload`|The whole block: header, body, footer|
|`upload(block_type, number)`|`Upload`|The block's body|
|`download(Option<number>, &[u8])`|`Download`|Downloads a whole block and activates it|
|`delete(block_type, number)`|`Delete`|Deletes a block|
|`db_get(db)`|`DBGet`|A whole DB|
|`db_fill(db, value)`|`DBFill`|Fills a whole DB|

Block types: `BLOCK_OB`, `BLOCK_DB`, `BLOCK_SDB`, `BLOCK_FC`, `BLOCK_SFC`,
`BLOCK_FB`, `BLOCK_SFB`.

#### System information and control

|Prototype|Snap7|Behaviour|
|---|---|---|
|`read_szl(id, index)`|`ReadSZL`|A system status list, all parts|
|`read_szl_list()`|`ReadSZLList`|The SZL IDs available|
|`get_order_code()`|`GetOrderCode`|Order code and firmware version|
|`get_cpu_info()`|`GetCpuInfo`|Module and system names, serial number, copyright|
|`get_cp_info()`|`GetCpInfo`|PDU, connection and bus limits|
|`get_protection()`|`GetProtection`|Protection settings (SZL 0x0232)|
|`get_plc_status()`|`GetPlcStatus`|`CpuStatus::Run`, `Stop` or `Unknown`|
|`plc_hot_start()`, `plc_cold_start()`, `plc_stop()`|`PlcHotStart`, `PlcColdStart`, `PlcStop`|Operating mode|
|`copy_ram_to_rom(timeout_ms)`, `compress(timeout_ms)`|`CopyRamToRom`, `Compress`|Memory functions|
|`get_plc_date_time()`, `set_plc_date_time(&S7DateTime)`, `set_plc_system_date_time()`|`GetPlcDateTime`, `SetPlcDateTime`, `SetPlcSystemDateTime`|The PLC clock (the system time is taken as UTC)|
|`set_session_password(&str)`, `clear_session_password()`|`SetSessionPassword`, `ClearSessionPassword`|Session password|
|`iso_exchange_buffer(&[u8])`|`IsoExchangeBuffer`|Sends a raw S7 PDU and returns the raw reply|

#### Errors

`S7Error` carries an `ErrorKind` whose `code()` is Snap7's numeric error code
(`errTCP*` in the low 16 bits, `errIso*` in bits 16–19, `errCli*` above), the code
the PLC answered with when the PLC refused (`cpu_code()`: an item return code such
as `0x0A`, or a header error such as `0x8104`), and a detail. `error_text(code)`
gives Snap7's text for a numeric code.

A TCP or ISO error (`is_link()`), or a reply that does not answer the request,
closes the connection; reconnect with `connect()`. A refusal from the PLC
(`is_cpu()`) keeps it.

#### Low-level modules

`rust7::iso` (TPKT / COTP) and `rust7::proto` (S7 PDUs, items, Read/Write Var in
both directions, UserData framing) are public, so a test PLC can share the codec.

# Fields
---

```rust
pub connected: bool
```
#### The Client is connected to the PLC
#### Note
- This reflects the last operation: if the network cable is unplugged, the socket
  notices only at the next read or write, which then closes the connection.

---
```rust
pub pdu_length: u16
```
#### The PDU size negotiated (0 while disconnected)

---
```rust
pub last_time: f64
```
#### Last operation time (ms).
#### Note
- If an error occurred the value will be 0.0

---
```rust
pub chunks:  usize
```
#### How many jobs the last read or write took
#### Note
- If an error occurred the value will be 0
