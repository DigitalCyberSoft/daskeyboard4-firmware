#!/usr/bin/env python3
"""
dk4_flash.py - firmware flasher for the Das Keyboard 4 Professional
(Metadot VID 0x24F0 PID 0x204A), reimplementing the reversed HYKBUtility
ISP sequence for Linux (hidraw feature reports). See PROTOCOL.md.

  ==================================================================
  THIS TOOL WRITES FLASH. A wrong or interrupted write BRICKS the board.
  There is no read-back / backup command in the protocol, so a bad flash
  is not recoverable by this tool.
  ==================================================================

SAFETY MODEL (per requirement: warn before ANY change):
  * Default run makes NO device-state changes at all. It validates the image,
    reads the current version, prints the plan, and exits.
  * The mutating path runs only with `--flash`, and only AFTER a printed
    warning and an interactive typed confirmation. The confirmation gate sits
    BEFORE `enterISP` (0xA0) - the first command that changes device state.
  * Post-ISP suitability checks (device size self-report, checkProfile) abort
    BEFORE erase and attempt `resetKB` recovery, so a mismatch does not strand
    the board in the bootloader.
  * Every command checks the device status byte; any failure aborts non-zero.
    No failure is swallowed.

STATUS: the write path has NOT been exercised end-to-end against hardware.
The version read (0xB0) is confirmed working; erase/write/ISP and the
bootloader re-enumeration (VID 0x0A34/0x0F39) are inferred from static RE.
Run at your own risk on a board you can afford to lose.
"""
import sys, os, glob, time, fcntl, argparse, hashlib

VID, PID = 0x24F0, 0x204A
ISP_VIDS = (0x24F0, 0x0A34, 0x0F39)      # runtime + inferred bootloader identities
REPORT_ID = 1
WIRE_LEN = 8
DATA_LEN = WIRE_LEN - 1                    # 7 payload bytes per feature report
HDR_REQ, HDR_RESP = 0xEA, 0xED

# ISP command opcodes (see PROTOCOL.md)
CMD_GET_VER_RUN   = 0xB0
CMD_GET_VER_ISP   = 0xA6
CMD_ENTER_ISP     = 0xA0
CMD_ENTER_LDROM   = 0xAA
CMD_CHECK_PROFILE = 0xA5
CMD_ERASE         = 0xA4
CMD_WRITE_FLASH   = 0xA1
CMD_PROTECT       = 0xA8
CMD_RESET         = 0xAF

def _IOC(d, t, nr, size): return (d << 30) | (size << 16) | (t << 8) | nr
def HIDIOCSFEATURE(l): return _IOC(3, 0x48, 0x06, l)
def HIDIOCGFEATURE(l): return _IOC(3, 0x48, 0x07, l)


# --------------------------------------------------------------------------
# HID transport (identical framing to the confirmed-working dk4_read.py)
# --------------------------------------------------------------------------
def _packet(cmd, contents=b""):
    L = len(contents)
    pkt = bytearray([HDR_REQ, (L + 2) & 0xFF, cmd]) + bytearray(contents)
    chk = 0
    for b in pkt:
        chk ^= b
    pkt.append(chk)
    return bytes(pkt)

def _fragments(pkt):
    out = []
    for i in range(0, len(pkt), DATA_LEN):
        chunk = pkt[i:i + DATA_LEN].ljust(DATA_LEN, b"\0")
        out.append(bytes([REPORT_ID]) + chunk)
    return out

def send_command(fd, cmd, contents=b""):
    for rep in _fragments(_packet(cmd, contents)):
        fcntl.ioctl(fd, HIDIOCSFEATURE(len(rep)), bytearray(rep))

def recv_response(fd, timeout=2.0):
    """Return (status, payload_bytes). Raises TimeoutError if no 0xED framed reply."""
    stream = bytearray()
    id_off = None
    rl = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        buf = bytearray(WIRE_LEN)
        buf[0] = REPORT_ID
        n = fcntl.ioctl(fd, HIDIOCGFEATURE(WIRE_LEN), buf)
        data = bytes(buf[:n]) if n > 0 else bytes(buf)
        if id_off is None:
            if len(data) >= 2 and data[0] == REPORT_ID and data[1] == HDR_RESP:
                id_off = 1
            elif data and data[0] == HDR_RESP:
                id_off = 0
            else:
                time.sleep(0.005); continue
        stream += data[id_off:]
        if rl is None and len(stream) >= 2:
            rl = stream[1]
        if rl is not None and len(stream) >= rl + 2:
            break
        time.sleep(0.005)
    if not stream or stream[0] != HDR_RESP or rl is None:
        raise TimeoutError("no framed 0xED response")
    status = stream[3]
    payload = bytes(stream[4:4 + (rl - 3)])
    return status, payload

class DeviceError(RuntimeError):
    pass

def _cmd(fd, cmd, contents=b"", timeout=2.0, name=""):
    send_command(fd, cmd, contents)
    status, payload = recv_response(fd, timeout)
    if status != 0:
        raise DeviceError(f"{name or hex(cmd)} returned status {status:#04x}")
    return payload


# --------------------------------------------------------------------------
# device commands
# --------------------------------------------------------------------------
def get_version(fd, isp=False):
    p = _cmd(fd, CMD_GET_VER_ISP if isp else CMD_GET_VER_RUN, name="get_version")
    return p.decode("latin-1", "replace").strip("\x00").strip()

def enter_isp(fd, ldrom=False):
    p = _cmd(fd, CMD_ENTER_LDROM if ldrom else CMD_ENTER_ISP, timeout=3.0, name="enter_isp")
    model = p[0] if len(p) >= 1 else None
    filesize = (p[1] | (p[2] << 8)) if len(p) >= 3 else None
    return model, filesize

def check_profile(fd, profile10):
    _cmd(fd, CMD_CHECK_PROFILE, bytes(profile10), name="check_profile")

def erase_chip(fd):
    _cmd(fd, CMD_ERASE, timeout=20.0, name="erase_chip")   # chip erase can be slow

def write_flash(fd, addr, block16):
    contents = bytes([(addr >> 8) & 0xFF, addr & 0xFF]) + bytes(block16)  # big-endian addr
    _cmd(fd, CMD_WRITE_FLASH, contents, name=f"write_flash@{addr:#06x}")

def protect_chip(fd):
    _cmd(fd, CMD_PROTECT, name="protect_chip")

def reset_kb(fd):
    # resetKB makes the device re-enumerate; a missing reply here is expected.
    try:
        _cmd(fd, CMD_RESET, timeout=1.0, name="reset_kb")
    except (TimeoutError, OSError):
        pass


# --------------------------------------------------------------------------
# image parsing / validation
# --------------------------------------------------------------------------
class Image:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.size = len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.ldrom = (self.size == 4096)
        self.errors = []
        d = self.data
        if self.ldrom:
            if d[0xFF4:0xFF9] != bytes([0x7B, 0x6A, 0x6B, 0xCA, 0xFA]):
                self.errors.append("LDROM signature 7B6A6BCAFA missing at 0xFF4")
        else:
            if not (self.size % 1024 == 0):
                self.errors.append(f"APROM size {self.size} is not a multiple of 1024")
            if not (d[self.size - 0x10] == 0x7B and d[self.size - 0x0F] == 0x6A):
                self.errors.append("APROM signature 7B 6A missing at [size-0x10]")
        self.profile = d[self.size - 0x0E:self.size - 0x04]   # 10 bytes
        self.expected_model = self.size // 1024
        self.block_count = self.size // 16

    @property
    def valid(self):
        return not self.errors

    def blocks(self):
        """Yield (addr, block) for each non-all-zero 16-byte block (vendor skips zeros)."""
        for i in range(self.block_count):
            blk = self.data[i * 16:(i + 1) * 16]
            if any(blk):
                yield i * 16, blk


# --------------------------------------------------------------------------
# device discovery
# --------------------------------------------------------------------------
def _has_vendor_feature(desc):
    i, up, usages, top, depth = 0, None, [], None, 0
    while i < len(desc):
        b = desc[i]; i += 1
        if b == 0xFE:
            i += 2 + (desc[i] if i < len(desc) else 0); continue
        bsize = {0: 0, 1: 1, 2: 2, 3: 4}[b & 3]
        btype, btag = (b >> 2) & 3, (b >> 4) & 0xF
        val = 0
        for k in range(bsize):
            val |= desc[i + k] << (8 * k)
        i += bsize
        if btype == 1 and btag == 0:
            up = val
        elif btype == 2 and btag == 0:
            usages.append(val)
        elif btype == 0:
            if btag == 0xA:
                if depth == 0:
                    top = (up, usages[0] if usages else None)
                depth += 1; usages = []
            elif btag == 0xC:
                depth -= 1; usages = []
                if depth == 0: top = None
            else:
                if btag == 0xB and top == (1, 0x80):
                    return True
                usages = []
    return False

def find_node(explicit=None, vids=ISP_VIDS):
    if explicit:
        return explicit
    for path in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        node = "/dev/" + os.path.basename(path)
        try:
            with open(path + "/device/uevent") as f:
                uevent = f.read().upper()
            with open(path + "/device/report_descriptor", "rb") as f:
                desc = f.read()
        except OSError:
            continue
        if not any(f"{v:08X}" in uevent for v in vids):
            continue
        if f"{PID:08X}" not in uevent and not _has_vendor_feature(desc):
            continue
        if _has_vendor_feature(desc):
            return node
    return None

def reopen_after_isp(old_fd, wait=8.0):
    """After enterISP the device re-enumerates (inferred). Wait for a vendor node."""
    try:
        os.close(old_fd)
    except OSError:
        pass
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        node = find_node()
        if node:
            try:
                return os.open(node, os.O_RDWR), node
            except OSError:
                pass
        time.sleep(0.3)
    raise DeviceError("device did not reappear after enterISP (bootloader not found)")


# --------------------------------------------------------------------------
# plan / flash
# --------------------------------------------------------------------------
def print_plan(img, cur_version, model=None):
    nz = list(img.blocks())
    print("  PLAN")
    print(f"    image        : {img.path}")
    print(f"    size         : {img.size} bytes ({'LDROM' if img.ldrom else 'APROM'})")
    print(f"    sha256       : {img.sha256}")
    print(f"    signature    : {'OK' if img.valid else 'INVALID -> ' + '; '.join(img.errors)}")
    print(f"    profile blob : {img.profile.hex(' ')}")
    print(f"    expects model: {img.expected_model} (device must report this; {img.expected_model}*1024={img.size})")
    print(f"    blocks       : {img.block_count} total, {len(nz)} non-zero to write, "
          f"{img.block_count - len(nz)} zero-skipped")
    if cur_version is not None:
        print(f"    device now   : version {cur_version!r}")
    if model is not None:
        ok = (model == img.expected_model)
        print(f"    device model : {model} -> size match {'OK' if ok else 'MISMATCH'}")
    print("    sequence     : enterISP -> checkProfile -> eraseChip -> "
          f"writeFlash x{len(nz)} -> protectChip -> resetKB")

def confirm(img, node, cur_version, assume_yes):
    print("\n" + "=" * 70)
    print("  WARNING: about to WRITE FIRMWARE. This ERASES and reprograms the")
    print("  keyboard's flash. If it is the wrong image or the write is")
    print("  interrupted, the board is BRICKED with no recovery via this tool.")
    print("  Do NOT unplug the keyboard or use it until this finishes.")
    print("=" * 70)
    print(f"    device : {node}  (current firmware {cur_version!r})")
    print(f"    image  : {os.path.basename(img.path)}  ({img.size} bytes)")
    print(f"    sha256 : {img.sha256}")
    phrase = os.path.basename(img.path)
    if assume_yes:
        print(f"  [--force] confirmation auto-accepted.")
        return True
    if not sys.stdin.isatty():
        print("  Refusing: no interactive terminal for confirmation and --force not given.",
              file=sys.stderr)
        return False
    try:
        ans = input(f"\n  Type the image filename ({phrase!r}) to proceed, or anything else to abort:\n  > ")
    except (EOFError, KeyboardInterrupt):
        print("\n  aborted."); return False
    if ans.strip() != phrase:
        print("  confirmation did not match; aborting with NO changes made.")
        return False
    return True

def do_flash(node, img, assume_yes):
    fd = os.open(node, os.O_RDWR)
    try:
        cur = None
        try:
            cur = get_version(fd)
        except (TimeoutError, DeviceError):
            pass
        print_plan(img, cur)
        if not img.valid:
            print("ERROR: image failed signature validation; refusing to flash.", file=sys.stderr)
            return 3

        # ---- warning + confirmation BEFORE any state change ----
        if not confirm(img, node, cur, assume_yes):
            return 4

        # ---- first mutating command ----
        print("\n[1/6] enterISP ...")
        model, _ = enter_isp(fd, ldrom=img.ldrom)
        fd, node = reopen_after_isp(fd)
        print(f"      re-opened bootloader at {node}; device reports model={model}")

        # ---- post-ISP suitability gates; abort+recover before erase ----
        if model is not None and model != img.expected_model:
            print(f"ERROR: device expects model {model} ({model}*1024) but image is "
                  f"{img.size} bytes (model {img.expected_model}). Aborting before erase.",
                  file=sys.stderr)
            reset_kb(fd); return 7
        print("[2/6] checkProfile ...")
        try:
            check_profile(fd, img.profile)
        except DeviceError as e:
            print(f"ERROR: {e}. Image profile rejected by device. Aborting before erase.",
                  file=sys.stderr)
            reset_kb(fd); return 9

        # ---- point of no return ----
        print("[3/6] eraseChip ... (do not unplug)")
        erase_chip(fd)
        nz = list(img.blocks())
        print(f"[4/6] writeFlash: {len(nz)} blocks ...")
        for n, (addr, blk) in enumerate(nz, 1):
            write_flash(fd, addr, blk)
            if n % 64 == 0 or n == len(nz):
                print(f"        {n}/{len(nz)} blocks written", end="\r")
        print()
        print("[5/6] protectChip ...")
        protect_chip(fd)
        print("[6/6] resetKB ...")
        reset_kb(fd)
        print("\nDONE. Flash sequence completed. Re-read the version to confirm.")
        return 0
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Das Keyboard 4 Pro firmware flasher.")
    ap.add_argument("image", nargs="?", help="firmware .bin")
    ap.add_argument("--dev", help="hidraw node (default: auto-detect vendor interface)")
    ap.add_argument("--check", action="store_true", help="validate the image only; no device access")
    ap.add_argument("--flash", action="store_true", help="ARM the write path (otherwise: plan only)")
    ap.add_argument("--force", action="store_true", help="skip the interactive confirmation (still prints warning)")
    args = ap.parse_args()

    if not args.image:
        ap.error("an image path is required")
    img = Image(args.image)

    if args.check:
        print_plan(img, None)
        return 0 if img.valid else 3

    node = find_node(args.dev)
    if not node:
        print("ERROR: Das Keyboard vendor interface not found.", file=sys.stderr)
        return 2

    if not args.flash:
        # PLAN mode: read-only, no changes.
        try:
            fd = os.open(node, os.O_RDWR)
        except PermissionError:
            print(f"ERROR: permission denied on {node}; re-run with sudo or install "
                  f"70-daskeyboard.rules.", file=sys.stderr)
            return 13
        try:
            cur = None
            try:
                cur = get_version(fd)
            except (TimeoutError, DeviceError):
                pass
        finally:
            os.close(fd)
        print(f"[dev ] {node}")
        print_plan(img, cur)
        print("\nPLAN ONLY - no changes made. Re-run with --flash to write.")
        return 0

    try:
        return do_flash(node, img, args.force)
    except PermissionError:
        print(f"ERROR: permission denied on {node}; re-run with sudo or install "
              f"70-daskeyboard.rules.", file=sys.stderr)
        return 13

if __name__ == "__main__":
    sys.exit(main())
