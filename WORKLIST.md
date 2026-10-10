# Finishing worklist — mapping the rest (interactive Ghidra / GhidraMCP)

This is the part that headless batch analysis couldn't finish: the firmware is
scatter-loaded into multiple DDR run-regions with a **custom/compressed** region
format, so a single-base flat load mislinks any code→string reference that crosses a
region boundary. Everything below is tractable in the Ghidra GUI (or via GhidraMCP),
where you can follow references and define memory blocks as you learn them.

## 0. Setup
- Load `lsx_s0.bin`, processor `ARM:LE:32:v5t`. (Decompiler: on Apple Silicon build it
  with `make -C Ghidra/Features/Decompiler/src/decompile/cpp ghidra_opt` → copy to
  `os/mac_arm_64/decompile`; or use an official release that ships the mac native.)
- Create an initial block for the boot region at run base 0 (run addr == file offset).

## 1. Locate __scatterload, then decode the region format (the keystone)
- NOTE: `0x18b4` is **hardware init** (writes `0xe0007000` registers from descriptors at
  `0x40f39c`/`0x40f3b0` via `0x14e8`/`0x1210`), not the scatter-loader. Don't start there.
- From the C-runtime entry at file `0x6a`, follow the remaining `bl`/`blx` targets
  (`0x88`, `0x62`, `0xd2`, `0x66`, `0x434`, and `blx 0x1754`) to find the routine that
  does the region copy loop — look for the classic `LDMIA rX!,{r0-r3}` + `BLX r3`
  dispatch, or a `__scatterload_copy`/`__scatterload_decompress` LDR/STR loop.
- Once found, read its region table: per region **flash src, run dst, size**, and whether
  verbatim or decompressed. Two run bases already observed (`0x40400000`-class for the
  validator region, `0x40000000`-class for the `REMOTE_REGISTERS` string region).

## 2. Rebuild the memory map
- For each decoded region, create a Ghidra memory block mapping file bytes → run dst.
- After this, PC-relative literal loads resolve to the correct strings/functions, and
  cross-region xrefs appear. This is what unblocks everything else.

## 3. Finish the config-write audit
- `CommSetCneValue`, `JBLinkSetCneValue`: find via xrefs to their format strings
  (`"<name>: bad path(%s)."` etc.; JBLink strings at file `0x2e9cc8`+). Confirm whether
  each uses the same fixed allowlist as `iOSCommSetCneValue` (verified networking-only)
  or accepts broader paths.

## 4. Resolve the telnet-routing question
- Decompile `CommunicationSettingsServiceImpl::initialize` (references `/cfg/Communication
  Settings`, and the enum strings `REMOTE_REGISTERS` / `TELNET` clustered at file
  `0x54c1d0`–`0x54c230`). Determine exactly how `TCPIPTunnel = TELNET` maps to a
  transport, i.e. whether it routes the shell onto TCP 50001, and whether the path is
  boot-safe. This is the one gating unknown for a network-shell firmware patch.

## Notes
- Firmware is unsigned (CRC-32 only); recompute CRCs after any edit. Only ever modify the
  app segment, never the BSL. Recovery: `aspSetRebootInBSL`, the hardware rescue pin, and
  XModem — but whether a failed boot auto-enters recovery without the pin is unconfirmed.
