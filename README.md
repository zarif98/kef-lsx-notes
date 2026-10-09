# KEF LSX — Platform & Firmware Reverse-Engineering Notes

Independent reverse-engineering notes for the **original KEF LSX** (not the LSX II).
Everything here was derived from the publicly-distributed firmware image and from
read-only probing of a unit on the local network. No modifications were flashed.
Chip identifications are cross-checked against the
[Audio Science Review LSX teardown](https://www.audiosciencereview.com/forum/index.php?threads/kef-lsx-teardown-and-repair.55697/).

> Status: notes, not a how-to. Several conclusions are marked **unverified** where
> they rest on static analysis that wasn't confirmed on hardware. Corrections welcome.

## Platform

| Part | Role |
|------|------|
| Microchip **CY920-C** (DM920 core, ARM9) | Wi-Fi/BT streaming module — runs the networked firmware |
| Analog Devices **ADAU1451** | 32-bit audio DSP / crossover |
| **STM32F030** | housekeeping MCU |
| Cirrus **CS4272**, TI **PCM1754**, Cirrus **WM8805** | codec / DAC / S-PDIF |
| Qualcomm **CSRA64215** | Bluetooth 4.2 |
| TI **CC8520** | PurePath 2.4 GHz inter-speaker link |

The streaming module runs Microchip/BridgeCo **JukeBlox** firmware: **ThreadX** RTOS
(Express Logic, ARM9 build) with the **KnOS** middleware layer. The UPnP banner
reports `KnOS/3.2 ... DMP/3.5`; `AirPlay 2.0.2` and Spotify Connect are present.

## Network surface (as shipped)

- **mDNS**: `_airplay._tcp`, `_raop._tcp`, `_spotify-connect._tcp`
- **Web UI**: port 80, GoAhead-Webs, `index.asp` + `/goform/*` handlers (fixed-purpose)
- **UPnP/DLNA**: port 8080 — MediaRenderer with **AVTransport** (usable to push
  hi-res directly, bypassing the app), RenderingControl, plus Tencent QPlay
- **Control protocol**: port **50001** ("remote registers" tunnel). This is what the
  [`aiokef`](https://github.com/basnijholt/aiokef) library and the Home Assistant KEF
  integration drive (source, volume, DSP: desk/wall mode, treble, sub, etc.)

## Firmware

- **Manifest** (KEF CDN, undocumented but public):
  `https://assets.kef.com/pm/pm_firmware/lsx/LSXUpdate.json`
  → points to `KEF_LSX_V520_S270_D100.fw` (Wi-Fi v5.2.0 / DSP S27.0 / MCU D10.0).
- **Container format**: BridgeCo **`bCoD`** v1. Integrity is **CRC-32 only — the image
  is not cryptographically signed** (contrast the LSX II, which ships signed `.swu`
  Linux images). The header CRC and per-segment CRC-32s validate.
- **Segment map** (v5.2.0):

  | Seg | Load addr | Size | Contents |
  |-----|-----------|------|----------|
  | 0 | `0x003C0000` (flash) | ~8.3 MB | main ARM9 image: ThreadX + KnOS |
  | 1 | — | ~77 KB | **text CNE default config** (INI-style) |
  | 2 | `0x00D80000` | ~1.2 MB | FFS resources: web UI, service config |

- **Runtime layout**: seg0 is **scatter-loaded (RVCT)** and runs from DDR; code and
  rodata relocate to separate run regions (a code region resolves around
  `0x40400000`; string pools sit `0x400000` lower). Mixed ARM/Thumb. This makes a
  single-base disassembly incorrect — expect to rebuild the memory map per region.

## Debug shell

- A BridgeCo debug shell exists (`BridgeCo AG Telnet server`, `/dev/TelnetShell`).
- In the CNE defaults (seg1): `[UartSwitch] TelnetShellEnable=1`, `TelnetShellPort=8000`;
  but `[CommunicationSettings] Shell=UART1` and `TelnetPort_Obsolete=10000`.
- **Conclusion:** the shell is enabled but routed to the **physical UART1** pins;
  the TCP-telnet path is deprecated. Port 8000 is closed on a stock unit. Per the
  teardown there's no broken-out debug header, so UART1 means fine-pitch work on the
  CY920 module.

## Can the shell be put on the network via config? (No, through the audited paths)

The networked config-write entry points — `iOSCommSetCneValue`, `CommSetCneValue`,
`JBLinkSetCneValue` — validate the target path (`bad path` / `bad attribute name` /
`sanity error`). Decompiling `iOSCommSetCneValue` (ARM Thumb) shows it opens a
**hardcoded** path (`/cfg/Networking/DrvCfg/WlanCfg`) and checks the attribute against
a **fixed registered allowlist**, erroring out otherwise. So arbitrary CNE keys
(`/dev/TelnetShell`, `Shell/autoexec`) **cannot** be written over the network through it.
*(`CommSetCneValue` / `JBLinkSetCneValue`: not cleanly decompiled here — their
function entry points weren't isolated in headless analysis. They share the identical
`bad path`/`bad attribute name`/`sanity error` triad and SDS structure, so the same
restriction is **likely but unverified**.)*

## Recovery / bootloader (relevant if anyone patches the unsigned image)

Two-level bootloader separate from the app: `aspSetRebootInBSL` (software route into
the loader), a hardware **rescue pin** that erases CNE (`CnE Erased Successfully`), and
XModem re-flash. The web update form (port 80) is independent of the 50001 tunnel.
**Unverified** whether a failed app boot auto-enters recovery without the rescue pin.

## Open questions

- Does `[CommunicationSettings] TCPIPTunnel = TELNET` (the enum value exists alongside
  `REMOTE_REGISTERS`) route the shell onto TCP 50001? **Unverified** — this is the one
  handler not cleanly isolated; a wrong guess risks a boot loop.
- Full enumeration of the CNE write allowlist (trace the registration, not just the
  adjacent strings).

## Tooling note (Apple Silicon)

Ghidra 12.x ships decompiler binaries only for `linux_x86_64` / `win_x86_64`. On an
Apple-Silicon Mac, build it: `make -C Ghidra/Features/Decompiler/src/decompile/cpp
ghidra_opt`, then copy `ghidra_opt` to `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`
(runs under Rosetta). The headless project must define the scatter regions as separate
memory blocks or string references won't resolve.
