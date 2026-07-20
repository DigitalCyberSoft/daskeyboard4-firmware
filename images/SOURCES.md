# Das Keyboard 4 firmware images - provenance

All images that exist for this board, and where each came from. The official
download server hosts exactly ONE image for the DK4 Professional; the Mac-variant
images exist only inside a support-ticket attachment.

## Copyright / attribution

These images and the vendor updater are the copyrighted work of **Heng Yu Technology
(HK) Ltd** ("HY"), distributed under the Das Keyboard brand. The macOS app and the
Windows updater both carry the notice *"Copyright (c) 2014 Heng Yu Technology (HK)
Limited. All rights reserved."* The `.bin` files here are included **unmodified** for use
with this tool; no license to redistribute them is granted by this repository, and all
rights remain with the copyright holder. The Windows updater program and the original
vendor archives are **not** included here.

## Available images

| File | Bytes | SHA-256 (prefix) | Board / role | Source |
|------|-------|------------------|--------------|--------|
| `L1947V33.bin` | 32768 | `2746e17b…980934` | DK4 **Professional (PC)** main image, version tag **V33** | `https://download.daskeyboard.com/firmware-releases/DK4PRO/USB_FD2_PC.zip` |
| `L2175V16.bin` | 32768 | `cc0b5efb…d34b45a` | DK4 Professional **for Mac** main image, version tag V16 | mojohelpdesk blob `5957943` (`DK4Mac FW app.zip`), linked from article 261541 |
| `A2175V13.bin` | 4096  | `8125d499…8953fd` | DK4 Pro for Mac **loader/LDROM** image (V13); flashed via the LDROM ISP path | same Mac zip |
| `L2689V17.bin` | 61440 | `e9f1e555…9f4679` | 60 KB image; profile tag `GFDK4USB2`; matches this board's size gate but **rejected at `checkProfile`** | community-contributed; not on the vendor's public server; original source unknown |
| `USB_FD2.abc.exe` | 1719296 | (PE32 i386) | Windows flasher (`USB_FD2.abc` renamed; it is an ordinary .exe) | `USB_FD2_PC.zip` |

Full hashes in `SHA256SUMS`.

## What is NOT available

Confirmed by direct probing on 2026-07-10:
- `download.daskeyboard.com/firmware-releases/DK4PRO/` directory listing → **403**.
- `USB_FD2_MAC.zip`, `.dmg`, and sibling model dirs (`DK4/`, `DK4C/`, `DK4Q/`, `DK4PROMAC/`) → **404**.
- Wayback CDX for `firmware-releases*` has exactly one successful capture ever: this same `USB_FD2_PC.zip`.
- The official firmware changelog (`daskeyboard.io/updates/changelog-firmware/`) covers Q-series only. There are **no published release notes** for L1947/USB_FD2. "V33" is the newest and only public version for the classic DK4 Professional.

## Notes

- `L1947V33.bin` (PC) and `L2175V16.bin` (Mac) carry the **same 10-byte profile blob**
  (`8b 9b bb bc dc ec ac ff ff ff`) in their trailing 16 bytes, so the flasher's
  `checkProfile` (0xA5) keys on board/region, not on OS. The last 4 bytes of each
  image differ (image CRC).
- `A2175V13.bin` carries the `7B 6A 6B CA FA` signature at offset `0xFF4` that the
  flasher uses to recognise a loader image.
- Which SKU **your** board is (PC `204A` vs Mac variant) is resolved by reading the
  running version with `dk4.py status`, not by the USB id alone.
