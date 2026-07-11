# dk4-firmware — unofficial Linux firmware tool for the Das Keyboard 4 Professional

Read and (optionally) flash firmware on the Das Keyboard 4 Professional
(Metadot USB `24f0:204a`) from Linux, where no official updater exists. Das Keyboard
ships updaters only for Windows (`USB_FD2.abc`, a renamed `.exe`) and macOS
(`HYKBUtility.app`). This project reconstructs their USB protocol by static analysis
of the macOS app so the same operations can run on Linux. The recovered protocol is
documented in `PROTOCOL.md`.

## ⚠️ Read this before using it

> **Prefer the official Windows or macOS updater. Use this only as a last resort.**
>
> This tool is **unofficial**, **not supported by Das Keyboard**, and reconstructed
> from a disassembly. The version-read path is confirmed working on real hardware,
> but **the write/erase path has never been run end to end against a keyboard.**
> A wrong or interrupted write **bricks the board**, and the protocol has no
> read-back or backup command, so a bad flash cannot be undone.
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
| `dk4_read.py`, `dk4_flash.py` | Earlier single-purpose tools, superseded by `dk4.py` (kept for reference). |

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
python3 dk4.py                    # status: device + image compatibility (read-only)
python3 dk4.py fetch              # download this board's firmware from the vendor (verified)
python3 dk4.py flash IMAGE.bin    # guarded write; see the safety model below
```

`status` prints your board's model and firmware version, lists the images in
`images/`, and states which (if any) are compatible with the attached board.

## How `flash` is gated

Before it changes anything on the device (all read-only, no writes):

1. Validates the image signature and size; refuses a malformed image.
2. Reads the running firmware and compares board models. If the image is for a
   different model than your board, it **refuses here, before entering ISP**.
3. Prints a brick-risk warning and requires you to type the image filename to proceed.

Then, with an abort-and-recover path up to the point of no return:

4. `enterISP`, then re-checks the device's self-reported flash size against the image;
   aborts if they disagree.
5. `checkProfile`; aborts if the device rejects the image's region/variant.
6. `eraseChip` → `writeFlash` (per block) → `protectChip` → `resetKB`.

Steps 1 to 3 are validated. **Steps 4 to 6 are not validated against hardware.**

## If the keyboard gets stuck in "flashing"/bootloader mode

An aborted or interrupted ISP session can leave the board in its bootloader instead
of running firmware, so it stops acting as a keyboard. `resetKB` does not reliably
bring it back. **Unplug the keyboard, wait a few seconds, and plug it back in.** As
long as flash was never erased, it boots the existing firmware normally. Confirm with
`python3 dk4.py status`.

## Firmware images (not hosted here)

This repository does not host Das Keyboard's firmware or updater binaries. It links to
the official source so you can download them yourself and decide whether to use them:

- **Windows updater + model-1947 image** (`USB_FD2_PC.zip`, which contains `L1947V33.bin`
  and the `USB_FD2.abc` updater): <https://download.daskeyboard.com/firmware-releases/DK4PRO/USB_FD2_PC.zip>
- **macOS updater + model-2175 images** (`DK4Mac FW app.zip`, containing `L2175V16.bin`,
  `A2175V13.bin`, and `HYKBUtility.app`): linked from the Das Keyboard support article
  *"Das Keyboard 4 Professional For Mac - How To Update Firmware"* (helpdesk article 261541).

See [`images/SOURCES.md`](images/SOURCES.md) for full provenance and direct links, and
[`images/SHA256SUMS`](images/SHA256SUMS) to verify whatever you download.

Firmware is model-specific: run `python3 dk4.py status` to see your board's model.
`L1947V33.bin` fits model 1947 only. If your board reports a different model, that image
will not fit it and there is no published image for it; request the correct one from Das
Keyboard support. Flashing a wrong-model image is the primary way to brick the board.

## Fetching firmware automatically

`dk4.py fetch` downloads the correct image for your board from Das Keyboard's own
server, extracts it, and verifies its SHA-256 before saving to `~/.cache/dk4-firmware/`.
Nothing is bundled or redistributed by this repository; your machine fetches directly
from the vendor, which is just automating the download link.

```sh
python3 dk4.py fetch                 # detect the board model and fetch its image
python3 dk4.py fetch --model 1947    # or fetch a specific model
python3 dk4.py flash ~/.cache/dk4-firmware/L1947V33.bin
```

Download sources are known for model **1947** (Windows package) and model **2175**
(macOS package). If your board is a model with no published source (run `status` to
check), `fetch` says so and points you to Das Keyboard support.

## Scope

This tool targets the **Das Keyboard 4 Professional** (USB `24f0:204a`), which uses the
"HY" ISP bootloader reversed in `PROTOCOL.md`. The Q-series boards (5Q, 5QS, X50Q) are
different products updated through the Das Keyboard Q software, not this protocol, and
are deliberately out of scope. Do not point this tool at a non-DK4 board.

## Project status

- **Read path** (`status`): confirmed on hardware.
- **Write path** (`flash`): implemented from the disassembly and gated, but not
  exercised on hardware. Treat it as experimental.
