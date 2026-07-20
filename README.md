# dk4-firmware — unofficial Linux firmware tool for the Das Keyboard 4 Professional

Read and (optionally) flash firmware on the Das Keyboard 4 Professional
(Metadot USB `24f0:204a`) from Linux, where no official updater exists. Das Keyboard
ships updaters only for Windows (`USB_FD2.abc`, a renamed `.exe`) and macOS
(`HYKBUtility.app`). This project reconstructs their USB protocol by static analysis
of **both** vendor tools — the macOS app and the Windows PE — so the same operations
can run on Linux. The two agree byte-for-byte on the wire; the recovered protocol is
documented in `PROTOCOL.md`.

## ⚠️ Read this before using it

> **Prefer the official Windows or macOS updater. Use this only as a last resort.**
>
> This tool is **unofficial**, **not supported by Das Keyboard**, and reconstructed
> from a disassembly. What has run on real hardware: the version read, entering the
> ISP bootloader, reconnecting after the board re-enumerates, and the `checkProfile`
> compatibility gate. What has **not** run on hardware: the actual **erase and write**
> (no profile-matching image has been available to test it end to end). A wrong or
> interrupted write **bricks the board**, and the protocol has no read-back or backup
> command, so a bad flash cannot be undone. Validate an image with
> `flash --stop-after-checkprofile` (which stops before erase) before any real write.
>
> **You SHOULD NOT run the `flash` command unless ALL of the following hold:**
>
> 1. A firmware update is genuinely necessary (there is a specific problem it fixes).
> 2. **No Windows or macOS machine is available** to run the official updater.
> 3. You have a firmware image confirmed correct for your **exact board model**
>    (see "Getting a correct image" below).
>
> If a Windows or Mac machine is within reach, use it instead. The official updaters
> do the same job over a supported, tested path.

Reading the firmware version is always safe: `status` (the default command) issues
only the get-version query and never writes. Run it as often as you like.

## Files

| File | Purpose |
|------|---------|
| `dk4.py` | The tool. `status` (read-only) and `flash` (guarded write). |
| `PROTOCOL.md` | The reverse-engineered HID/ISP protocol. |
| `images/` | Firmware images, with `SOURCES.md` (provenance) and `SHA256SUMS`. |
| `70-daskeyboard.rules` | udev rule for non-root access to the device. |

## Setup: non-root access

Without a rule, the HID device is root-only and every command needs `sudo`. To grant
access to members of the `wheel` group once:

```sh
sudo cp 70-daskeyboard.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=hidraw
```

Adjust the group in the rule file if your distribution does not use `wheel`.

## Usage

```sh
python3 dk4.py                    # status: device + image profiles/compatibility (read-only)
python3 dk4.py list               # catalog known firmware (flashable here vs Q-series reference)
python3 dk4.py fetch              # download this board's firmware from the vendor (verified)
python3 dk4.py flash IMAGE.bin --stop-after-checkprofile   # SAFE probe: test an image, stop before erase
python3 dk4.py flash IMAGE.bin    # guarded write; see the safety model below
```

`status` prints your board's model and firmware version, and lists the images in
`images/` with each one's decoded **profile tag** and whether its model matches the
attached board.

## How `flash` is gated

Before it changes anything on the device (all read-only, no writes):

1. Validates the image signature and structure; refuses a malformed image.
2. Reads the running firmware and compares board models. If the image's filename
   model number differs from your board's, it **warns loudly that this may be the
   wrong file** (a brick risk) but does not refuse: the filename model is only a
   heuristic, and a correct image (e.g. one support sends for your board) can carry
   a different number. The authoritative checks are the two device-side gates below.
3. Prints a brick-risk warning and requires you to type the image filename to proceed.

Then it enters the bootloader, with a hard abort before the first destructive step:

4. `enterISP` (the board re-enumerates; the tool reopens it and re-reads its report
   size), then checks the device's self-reported flash size against the image; aborts
   if they disagree.
5. `checkProfile` — the device compares the image's embedded **profile tag** (region +
   product) against itself and returns accept/reject; a reject aborts before erase.
   `--stop-after-checkprofile` stops here, so you can safely confirm an image matches
   your board before committing to a write.
6. `eraseChip` → `writeFlash` (per block) → `protectChip` → `resetKB`. **Point of no
   return.**

Steps 1–5 are exercised on hardware and abort cleanly. **Step 6 (erase/write) has not
been run on hardware** — no profile-matching image has been available to test it.

## Profiles: why "right model" isn't enough

Each image carries a 10-byte **profile tag** near its end, lightly obfuscated
(`not(rol(x,4))`). Decoded it reads as `<region><product>` — e.g. `GFD4215` is Global
Full, product "D4215"; `GFDK4USB2` is Global Full, product "DK4USB2". `dk4.py status`
decodes and shows this for every image. At flash time `checkProfile` has the **board
itself** accept or reject the image's tag, so an image can be the right size and still
be refused because its product tag doesn't match your board. The bootloader does **not**
report which tag it wants — so if your board rejects every image you have, only Das
Keyboard can supply the matching one. Give them your label's **Part No.** and **Serial**.

## If the keyboard gets stuck in "flashing"/bootloader mode

An aborted or interrupted ISP session can leave the board in its bootloader instead
of running firmware, so it stops acting as a keyboard. `resetKB` does not reliably
bring it back. **Unplug the keyboard, wait a few seconds, and plug it back in.** As
long as flash was never erased, it boots the existing firmware normally. Confirm with
`python3 dk4.py status`.

## Firmware images (included here)

The images in `images/` are bundled in this repository for convenience, so the tool has
something to flash. They are **not this project's work**: they are the copyrighted
firmware of **Heng Yu Technology (HK) Ltd** ("HY"), distributed under the Das Keyboard
brand, and each carries an "All rights reserved" notice. They are included unmodified.
No redistribution license is granted by this repository; all rights remain with the
copyright holder. See [`images/SOURCES.md`](images/SOURCES.md) for the copyright notice
and the origin of each file, and [`images/SHA256SUMS`](images/SHA256SUMS) to verify them.

The Windows updater program (`USB_FD2.abc`) and the original vendor `.zip`/app bundles
are **not** included: this Linux tool replaces the updater, and those packages are just
linked from `SOURCES.md` if you want the originals.

Firmware is board-specific in two ways the device enforces: **size** (the bootloader
reports the exact image size it expects) and **profile tag** (region + product, checked
on the device at `checkProfile`). Run `python3 dk4.py status` to see your board's model
and each image's profile. The bundled images fit only their own boards (models 1947 and
2175, plus the 60 KB `L2689V17.bin`); a board matching none of them rejects them at
`checkProfile`. If none pass, request the correct image from Das Keyboard support (give
them your label's Part No. and Serial), then confirm it with
`flash --stop-after-checkprofile` before a real write. Flashing a wrong image is the
primary way to brick the board.

## Fetching firmware automatically

`dk4.py fetch` downloads the correct image for your board from Das Keyboard's own
server, extracts it, and verifies its SHA-256 before saving to `~/.cache/dk4-firmware/`.
It fetches directly from the vendor to your machine, automating the official download
link, useful for a board whose image is not bundled here or to pull a fresh copy.

```sh
python3 dk4.py fetch                 # detect the board model and fetch its image
python3 dk4.py fetch --model 1947    # or fetch a specific model
python3 dk4.py flash ~/.cache/dk4-firmware/L1947V33.bin
```

Download sources are known for model **1947** (Windows package) and model **2175**
(macOS package). If your board is a model with no published source (run `status` to
check), `fetch` says so and points you to Das Keyboard support.

## Q-series firmware (reference only)

The 5-series and X50Q are a different product family (e.g. the 5Q is USB PID `2020`),
updated through the Das Keyboard Q software or a self-contained Windows `firmware.exe`.
They do **not** use the HY bootloader this tool flashes, so `flash`/`fetch` do not and
must not touch them. `dk4.py list` catalogs them for reference with their official URLs:

- **5Q**: 7.4.51 (latest), 7.4.48, 7.4.18 &nbsp;(~5 MB `.exe`, confirmed on the download server)
- **X50Q**: 64.0.0
- **5QS / 5QS Mark IIe**: listed in the changelog; updated via the Q software
- **4Q**: 24.31.0, 21.27.0 (Q software)

Base URL: `https://download.daskeyboard.com/q-software-releases/Firmware-releases/<MODEL>/<VERSION>/firmware.exe`.
Flashing a Q-series board from Linux would require reverse-engineering its (different)
update protocol, which this project has not done.

## Scope

This tool **flashes** only the **Das Keyboard 4 Professional** (USB `24f0:204a`), which
uses the "HY" ISP bootloader reversed in `PROTOCOL.md`. Q-series boards are cataloged for
reference (above) but are not flashable here. Do not point `flash` at a non-DK4 board.

## Project status

- **Protocol**: reconstructed from the macOS app and **cross-checked byte-for-byte
  against the Windows tool** — same framing, same feature-report transport, same
  command set.
- **Read path** (`status`, profile decode): confirmed on hardware.
- **ISP path** (`enterISP`, re-enumeration reconnect, `checkProfile`): confirmed on
  hardware; `flash --stop-after-checkprofile` exercises it and stops before erase.
- **Write path** (`eraseChip`/`writeFlash`/`protectChip`/`resetKB`): implemented from
  the disassembly and gated, but **not yet exercised on hardware** (awaiting a
  profile-matching image). Treat it as experimental.
