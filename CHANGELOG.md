# Changelog

---

## [0.2.0] - 2026-11-02

### Added
- Snap7's client function set:
  - `read_multi_vars` / `write_multi_vars` (`S7DataItem`), packed into as many
    jobs as the negotiated PDU requires;
  - every area and word length: `S7_AREA_CT`, `S7_AREA_TM`, `S7_WL_CHAR`,
    `S7_WL_WORD`, `S7_WL_INT`, `S7_WL_DWORD`, `S7_WL_DINT`, `S7_WL_REAL`,
    `S7_WL_COUNTER`, `S7_WL_TIMER`; `read_mb`/`write_mb`, `read_eb`/`write_eb`,
    `read_ab`/`write_ab`, `read_tm`/`write_tm`, `read_ct`/`write_ct`;
  - blocks: `list_blocks`, `list_blocks_of_type`, `get_ag_block_info`,
    `get_pg_block_info`, `full_upload`, `upload`, `download`, `delete`,
    `db_get`, `db_fill`;
  - system: `read_szl`, `read_szl_list`, `get_order_code`, `get_cpu_info`,
    `get_cp_info`, `get_protection`, `get_plc_status`;
  - control: `plc_hot_start`, `plc_cold_start`, `plc_stop`,
    `copy_ram_to_rom`, `compress`;
  - clock: `get_plc_date_time`, `set_plc_date_time`, `set_plc_system_date_time`;
  - security: `set_session_password`, `clear_session_password`;
  - `iso_exchange_buffer`, `set_pdu_request`, `set_connection_params`,
    `connect`.
- Public `iso` and `proto` codec modules (both directions).
- COTP DT fragmentation and reassembly, deadline-bounded replies, PDU
  reference checks, IPv6 and host-name addresses.
- Integration tests against a scripted PLC.

### Changed
- `S7Error` is a struct with an `ErrorKind` carrying Snap7's numeric codes,
  the PLC's refusal code (`cpu_code`) and a detail; it replaces the former
  enum variants.
- `start` and `byte_num` are `u32` (the S7 address reaches 2 MiB).
- A TCP or ISO error, or a reply that does not answer the request, closes
  the connection.

## [0.1.2] - 2025-08-15

### Added
- Added parameter check
- Added `InvalidFunParam`

### Modified
- Excluded /target folder from deploy

## [0.1.1] - 2025-08-14
- Initial release
