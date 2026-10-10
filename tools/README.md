# Tools — reproduce the analysis

Read-only analysis tooling to recreate the investigation in this repo. None of it
modifies or flashes firmware; it fetches, parses, and analyzes.

> Scope note: there is deliberately **no** firmware-patch or flash tool here. The
> network-shell patch discussed in the README/WORKLIST builds an image that stands up an
> unauthenticated shell (an RCE surface); building/flashing that is left to the device
> owner to do deliberately, by hand, on their own hardware.

## 1. Get the firmware (public KEF CDN)
```sh
curl -s https://assets.kef.com/pm/pm_firmware/lsx/LSXUpdate.json
# -> url for KEF_LSX_V520_S270_D100.fw  (Wi-Fi v5.2.0 / DSP S27.0 / MCU D10.0)
curl -sO https://assets.kef.com/pm/pm_firmware/lsx/KEF_LSX_V520_S270_D100.fw
```
The firmware is KEF's proprietary image and is **not redistributed here** — download it
from the official CDN above. Verify you have the same image this analysis used:
```
sha256  991b19704770cdcda2e5865a564ec5596b13e85bca78f57200e13fd5c8737179
        KEF_LSX_V520_S270_D100.fw
```

## 2. Parse / extract the bCoD container
```sh
python3 bcod.py info    KEF_LSX_V520_S270_D100.fw   # header, segments, CRC check
python3 bcod.py extract KEF_LSX_V520_S270_D100.fw out/   # -> out/seg0.bin, seg1.bin, seg2.bin
```
- `seg0.bin` — main ARM9 image (ThreadX + KnOS)
- `seg1.bin` — text CNE default config (INI-style, NUL-separated)
- `seg2.bin` — FFS resources (web UI, service config)

Inspect the config directly, e.g. the debug-shell defaults:
```sh
strings seg1.bin | grep -iE 'Telnet|Shell|TCPIPTunnel|UART'
```

## 3. Find seg0's run base, then load in Ghidra
```sh
python3 find_base.py out/seg0.bin        # prints a best-effort BinaryLoader base
```
Note: because seg0 is multi-region, `find_base` reports the *global-best* base, which can
differ from the base a *specific* function resolves at. In this session the validator
decompiled cleanly at `0x40400050` even though the global-best scores elsewhere — so if a
function looks wrong, try the `find_base` value and nearby round bases.

Then decompile a function (handles Thumb):
```sh
$GHIDRA/support/analyzeHeadless /tmp/proj lsx -import out/seg0.bin \
    -processor "ARM:LE:32:v5t" -loader BinaryLoader -loader-baseAddr 0x40400050 \
    -scriptPath . -postScript DecompileAt.java 0x404c576c
```
`0x404c576c` is the networked config-write validator (`iOSCommSetCneValue`) shown in the
README to enforce a networking-only path allowlist.

### Apple Silicon note
Some Ghidra builds ship no `mac_arm_64` decompiler. Build it:
```sh
make -C $GHIDRA/Ghidra/Features/Decompiler/src/decompile/cpp ghidra_opt
cp $GHIDRA/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt \
   $GHIDRA/Ghidra/Features/Decompiler/os/mac_arm_64/decompile
```

## Limits
seg0 is scatter-loaded into multiple DDR regions and the fine region map is not in the
`.fw` (it is applied by the first-stage bootloader). A single base resolves one region
cleanly; cross-region references need the full map — i.e. a hardware BSL/RAM dump. See
the top-level README for the full reasoning.
