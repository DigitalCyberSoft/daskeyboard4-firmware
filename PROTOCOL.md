# Das Keyboard 4 Professional - ISP/firmware HID protocol

Reverse-engineered (static only) from the macOS `HYKBUtility` (`DKFW-HYKBUtility.app`,
74 KB x86_64 Mach-O), cross-checked against the on-device HID report descriptor and
the firmware image bytes. **Nothing here has been exercised against hardware yet.**
Treat every "device returns X" as inferred from host code until the reader/flasher
confirms it live.

## USB / HID transport

- Device: VID `0x24F0` (Metadot), PID `0x204A`, runtime. Two HID interfaces.
- Vendor interface = the one whose top-level collection is **UsagePage 0x01 / Usage 0x80**
  (on this machine: `hidraw9`). The other interface is the boot keyboard (UsagePage1/Usage6).
- All commands ride a **FEATURE report, report id 1**, defined as 7 data bytes
  (8 bytes on the wire incl. the report-id byte). macOS strips the id byte on GET;
  Linux `HIDIOCGFEATURE` keeps it at `buf[0]`, so the response marker is at `buf[1]`.

### Request framing (`sendCommand:command:contents:length:`)

Logical packet, length `L+4`:

```
[0]=0xEA  [1]=L+2  [2]=cmd  [3 .. 2+L]=contents(L)  [3+L]=XOR of all preceding bytes
```

Fragment into 7-byte chunks; each chunk → 8-byte feature report `[0x01, <7 bytes>]`
(last chunk zero-padded). Send with `HIDIOCSFEATURE`.

### Response framing (`recvRepsonse:` - sic)

Poll `HIDIOCGFEATURE` (id 1, 8 bytes) until the first payload byte is `0xED`,
reassembling 7-byte fragments:

```
[0]=0xED  [1]=RL  [2]=cmd_echo  [3]=status  [4 .. RL]=payload (RL-3 bytes)  [RL+1]=XOR
```

`status == 0` means OK. (Host code polls with `sleep(10s)` between tries — a bug;
use millisecond delays.)

## Command opcodes

| Cmd | Name | Contents | Returns / notes |
|-----|------|----------|-----------------|
| `0xB0` | getFirmwareVersion (runtime) | none | payload = version text |
| `0xA6` | getFirmwareVersion (ISP mode) | none | same |
| `0xA0` | enterISP (APROM) | none | payload[0]=model, payload[1..2]=filesize16 |
| `0xAA` | enterLdromISP (LDROM) | none | same |
| `0xA5` | checkProfile | 10-byte profile blob from image tail | rejects wrong board/region |
| `0xA4` | eraseChip | none | |
| `0xA1` | writeFlash | `[addr_hi, addr_lo]` (16-bit big-endian byte addr) + data | host writes 16-byte blocks |
| `0xA8` | protectChip | none | |
| `0xAF` | resetKB | none | exit ISP, run firmware |

## Flash sequence (deferred - flasher not yet built)

`updateFirmware:withUrl:` then `updateFirmware2:callback:`:

1. Validate image; **filesize must == model*1024** (V33 image = 32768 = 32*1024).
2. `enterISP` (0xA0) / `enterLdromISP` (0xAA) → device re-enumerates into the bootloader
   (interpretation: VID `0x0A34` or `0x0F39`; the flasher must re-scan and reopen).
3. `checkProfile` (0xA5).
4. `eraseChip` (0xA4).
5. `writeFlash` (0xA1) per non-zero 16-byte block at byte address `block*16` (all-zero blocks skipped).
6. `protectChip` (0xA8) → `resetKB` (0xAF).

## Image format

- Trailing 16 bytes of a 32 KB APROM image: `[size-0x10]=0x7B`, `[size-0x0F]=0x6A`,
  10-byte profile blob at `[size-0x0E]`, image CRC in the last 4 bytes.
- 4 KB loader image: signature `7B 6A 6B CA FA` at `0xFF4`.

## Open risks before any flash

- Report-id framing differs macOS vs Linux (handled in `dk4_read.py`); confirm live.
- ISP-mode re-enumeration VID/PID is **inferred**, not observed.
- `checkProfile` is a guard, not a guarantee; PC vs Mac images share the profile blob,
  so it will not stop a Mac image from flashing a PC board. Wrong image = brick risk.
