#!/usr/bin/env python3
"""
dk4.py - unified Das Keyboard 4 firmware tool for Linux (Metadot 0x24F0:0x204A).

Reverse-engineered from the macOS HYKBUtility; see PROTOCOL.md.

Subcommands:
  status  (default)  read-only: identify the keyboard, read its firmware version,
                     scan the images/ dir, and print which images are COMPATIBLE.
                     Sends only the get-version query (0xB0). Never writes.
  flash <image>      guarded write path. Validates the image and WARNS if its
                     model number differs from the board (not a refusal: the
                     filename model is only a heuristic), requires typed
                     confirmation, then runs enterISP -> size + profile backstops
                     -> erase -> write -> protect -> reset. Bad-signature images
                     are still refused.

  ==================================================================
  `flash` ERASES and reprograms flash. A wrong or interrupted write BRICKS the
  board; there is no read-back/backup command in the protocol. `status` is safe.
  ==================================================================
"""
import sys, os, glob, re, time, fcntl, argparse, hashlib, textwrap, errno
import urllib.request, zipfile, io

VID, PID = 0x24F0, 0x204A
ISP_VIDS = (0x24F0, 0x0A34, 0x0F39)          # runtime + inferred bootloader identities
REPORT_ID, WIRE_LEN = 1, 8
DATA_LEN = WIRE_LEN - 1                        # 7 payload bytes / feature report
HDR_REQ, HDR_RESP = 0xEA, 0xED
SETTLE = 0.3                                   # post-command settle delay (the Windows tool uses 300 ms)

CMD_GET_VER_RUN, CMD_GET_VER_ISP = 0xB0, 0xA6
CMD_ENTER_ISP, CMD_ENTER_LDROM   = 0xA0, 0xAA
CMD_CHECK_PROFILE, CMD_ERASE     = 0xA5, 0xA4
CMD_WRITE_FLASH                  = 0xA1
CMD_PROTECT, CMD_RESET           = 0xA8, 0xAF

# Upstream firmware sources, keyed by board model (the digits in the version string).
# The tool DOWNLOADS these from Das Keyboard on demand and verifies sha256; it does NOT
# bundle or redistribute them. Add an entry when a model's official source URL is known.
FIRMWARE_SOURCES = {
    1947: {"url": "https://download.daskeyboard.com/firmware-releases/DK4PRO/USB_FD2_PC.zip",
           "member": "L1947V33.bin",
           "sha256": "2746e17bb497ca4be7730ff631ec251c2968f0f4836bb26bbaa415c889980934",
           "note": "Windows package, public download server"},
    2175: {"url": "https://daskeyboard.mojohelpdesk.com/api/v4/helpdesk_files/blobs/5957943/download",
           "member": "L2175V16.bin",
           "sha256": "cc0b5efbc9acfd3c39204574519e514c785a9cbcc68a730211635351ed34b45a",
           "note": "macOS package, support helpdesk attachment"},
}

# Q-series firmware: a DIFFERENT product family (e.g. 5Q is USB PID 0x2020) updated via
# the Das Keyboard Q software / a self-contained Windows updater .exe. These do NOT use
# the HY bootloader this tool flashes. Catalogued for reference only; `flash`/`fetch`
# never touch them. Flash a Q-series board with the official Q software, not this tool.
REF_BASE = "https://download.daskeyboard.com/q-software-releases/Firmware-releases"
REFERENCE_FIRMWARE = {
    "5Q":           {"versions": ["7.4.51", "7.4.48", "7.4.18"], "kind": ".exe (~5 MB)",
                     "note": "server-confirmed: 5Q/<ver>/firmware.exe"},
    "X50Q":         {"versions": ["64.0.0"], "kind": ".exe",
                     "note": "server-confirmed: X50Q/<ver>/firmware.exe"},
    "5QS":          {"versions": ["28.31.0", "24.31.0"], "kind": "via Q software",
                     "note": "changelog-listed; standalone download not located"},
    "5QS Mark IIe": {"versions": ["34.17.0"], "kind": "via Q software",
                     "note": "changelog-listed; standalone download not located"},
    "4Q":           {"versions": ["24.31.0", "21.27.0"], "kind": ".exe",
                     "note": "per official firmware page: DK4Q/<ver>/<profile>/firmware.exe"},
}

def _sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def _sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def fetch_image(model, cache_dir):
    """Download the model's firmware archive from the vendor, extract + verify the .bin.
    Returns (path, 'cached'|'downloaded'). Verifies sha256; raises on mismatch."""
    src = FIRMWARE_SOURCES.get(model)
    if not src:
        raise DeviceError(f"no known download source for model {model}")
    os.makedirs(cache_dir, exist_ok=True)
    dest = os.path.join(cache_dir, src["member"])
    if os.path.exists(dest) and _sha256_file(dest) == src["sha256"]:
        return dest, "cached"
    req = urllib.request.Request(src["url"], headers={"User-Agent": "dk4.py"})
    with urllib.request.urlopen(req, timeout=30) as r:
        blob = r.read()
    zf = zipfile.ZipFile(io.BytesIO(blob))
    member = next((n for n in zf.namelist()
                   if not n.startswith("__MACOSX") and os.path.basename(n) == src["member"]), None)
    if member is None:
        raise DeviceError(f"{src['member']} not found in archive downloaded from {src['url']}")
    data = zf.read(member)
    got = _sha256_bytes(data)
    if got != src["sha256"]:
        raise DeviceError(f"sha256 mismatch for {src['member']}: got {got}, expected {src['sha256']}")
    with open(dest, "wb") as f:
        f.write(data)
    return dest, "downloaded"

VER_RE = re.compile(r"^([A-Za-z]+)(\d+)V(\d+)$")          # e.g. S3075V10
FILE_RE = re.compile(r"^([A-Za-z]+)(\d+)V(\d+)\.bin$", re.I)  # e.g. L1947V33.bin

def _IOC(d, t, nr, size): return (d << 30) | (size << 16) | (t << 8) | nr
def HIDIOCSFEATURE(l): return _IOC(3, 0x48, 0x06, l)
def HIDIOCGFEATURE(l): return _IOC(3, 0x48, 0x07, l)


# -------------------------------------------------------------------------- transport
def _packet(cmd, contents=b""):
    L = len(contents)
    pkt = bytearray([HDR_REQ, (L + 2) & 0xFF, cmd]) + bytearray(contents)
    chk = 0
    for b in pkt:
        chk ^= b
    pkt.append(chk)
    return bytes(pkt)

def _fragments(pkt, wire_len=WIRE_LEN):
    data_len = wire_len - 1
    return [bytes([REPORT_ID]) + pkt[i:i + data_len].ljust(data_len, b"\0")
            for i in range(0, len(pkt), data_len)]

def send_command(fd, cmd, contents=b"", wire_len=WIRE_LEN):
    for rep in _fragments(_packet(cmd, contents), wire_len):
        for attempt in range(3):                       # tolerate a transient endpoint stall
            try:
                fcntl.ioctl(fd, HIDIOCSFEATURE(len(rep)), bytearray(rep)); break
            except OSError:
                if attempt == 2: raise
                time.sleep(0.02)

def recv_response(fd, timeout=2.0, wire_len=WIRE_LEN):
    stream, id_off, rl = bytearray(), None, None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        buf = bytearray(wire_len); buf[0] = REPORT_ID
        try:
            n = fcntl.ioctl(fd, HIDIOCGFEATURE(wire_len), buf)
        except OSError:
            time.sleep(0.02); continue                 # transient stall (e.g. EPIPE): retry until timeout
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
    return stream[3], bytes(stream[4:4 + (rl - 3)])   # (status, payload)

class DeviceError(RuntimeError):
    pass

def _cmd(fd, cmd, contents=b"", timeout=2.0, name="", wire_len=WIRE_LEN):
    send_command(fd, cmd, contents, wire_len)
    status, payload = recv_response(fd, timeout, wire_len)
    if status != 0:
        raise DeviceError(f"{name or hex(cmd)} returned status {status:#04x}")
    return payload

def get_version(fd, isp=False):
    p = _cmd(fd, CMD_GET_VER_ISP if isp else CMD_GET_VER_RUN, name="get_version")
    return p.decode("latin-1", "replace").strip("\x00").strip()

def enter_isp(fd, ldrom=False):
    p = _cmd(fd, CMD_ENTER_LDROM if ldrom else CMD_ENTER_ISP, timeout=3.0, name="enter_isp")
    model = p[0] if len(p) >= 1 else None
    filesize = (p[1] | (p[2] << 8)) if len(p) >= 3 else None
    return model, filesize

def check_profile(fd, profile10, wire_len=WIRE_LEN):
    _cmd(fd, CMD_CHECK_PROFILE, bytes(profile10), name="check_profile", wire_len=wire_len)
def erase_chip(fd, wire_len=WIRE_LEN):
    _cmd(fd, CMD_ERASE, timeout=20.0, name="erase_chip", wire_len=wire_len)
def protect_chip(fd, wire_len=WIRE_LEN):
    _cmd(fd, CMD_PROTECT, name="protect_chip", wire_len=wire_len)
def write_flash(fd, addr, block16, wire_len=WIRE_LEN):
    _cmd(fd, CMD_WRITE_FLASH, bytes([(addr >> 8) & 0xFF, addr & 0xFF]) + bytes(block16),
         name=f"write_flash@{addr:#06x}", wire_len=wire_len)
def reset_kb(fd, wire_len=WIRE_LEN):
    try:
        _cmd(fd, CMD_RESET, timeout=1.0, name="reset_kb", wire_len=wire_len)
    except (TimeoutError, OSError):
        pass


# -------------------------------------------------------------------------- discovery
def vendor_feature_wire_len(desc):
    """Wire byte length of the Feature report in the UsagePage-1/Usage-0x80 vendor
    collection (data bytes + 1 report-id byte), or None if absent. The ISP bootloader
    may expose a different length than runtime, so this is re-read after enterISP."""
    i, up, usages, top, depth = 0, None, [], None, 0
    rsize = rcount = rid = 0
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
        if btype == 1:                                 # Global
            if btag == 0: up = val
            elif btag == 0x7: rsize = val
            elif btag == 0x8: rid = val
            elif btag == 0x9: rcount = val
        elif btype == 2 and btag == 0:                 # Local Usage
            usages.append(val)
        elif btype == 0:                               # Main
            if btag == 0xA:
                if depth == 0: top = (up, usages[0] if usages else None)
                depth += 1; usages = []
            elif btag == 0xC:
                depth -= 1; usages = []
                if depth == 0: top = None
            else:
                if btag == 0xB and top == (1, 0x80):   # Feature item in the vendor collection
                    return (rsize * rcount + 7) // 8 + (1 if rid else 0)
                usages = []
    return None

def _has_vendor_feature(desc):
    return vendor_feature_wire_len(desc) is not None

def _node_feature_len(node, default=WIRE_LEN):
    p = "/sys/class/hidraw/" + os.path.basename(node) + "/device/report_descriptor"
    try:
        with open(p, "rb") as f:
            return vendor_feature_wire_len(f.read()) or default
    except OSError:
        return default

def find_node(explicit=None):
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
        if not any(f"{v:08X}" in uevent for v in ISP_VIDS):
            continue
        if _has_vendor_feature(desc):
            return node
    return None

def reopen_after_isp(old_fd, wait=8.0, settle=SETTLE):
    """Reopen the device after enterISP re-enumerates it. Returns (fd, node, wire_len).
    Re-reads the feature-report length from the (possibly different) bootloader descriptor
    and settles before the caller issues the next command, mirroring the Windows tool."""
    try:
        os.close(old_fd)
    except OSError:
        pass
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        node = find_node()
        if node:
            try:
                fd = os.open(node, os.O_RDWR)
            except OSError:
                time.sleep(0.3); continue
            wire_len = _node_feature_len(node)
            time.sleep(settle)                          # let the bootloader settle before the first command
            return fd, node, wire_len
        time.sleep(0.3)
    raise DeviceError("device did not reappear after enterISP (bootloader not found)")

_VANISHED = (errno.ENODEV, errno.ENOENT)          # board re-enumerated: current handle is stale

def isp_cmd(state, func, tries=6):
    """Run func(fd, wire_len) on the live ISP handle in state=[fd, node, wire_len].
    If the board re-enumerated (ENODEV/ENOENT), reopen and retry on the fresh handle,
    updating state in place. A device error (status != 0), a stall, or exhausting the
    retries all propagate - nothing is swallowed."""
    last = None
    for _ in range(tries):
        try:
            return func(state[0], state[2])
        except OSError as e:
            if e.errno not in _VANISHED:
                raise
            last = e
            state[0], state[1], state[2] = reopen_after_isp(state[0])
    raise last


# -------------------------------------------------------------------------- image model
def parse_version(s):
    """'S3075V10' -> ('S', 3075, 10) or None."""
    m = VER_RE.match(s or "")
    return (m.group(1), int(m.group(2)), int(m.group(3))) if m else None

class Image:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.data = open(path, "rb").read()
        self.size = len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.ldrom = (self.size == 4096)
        self.errors = []
        d = self.data
        if self.ldrom:
            if d[0xFF4:0xFF9] != bytes([0x7B, 0x6A, 0x6B, 0xCA, 0xFA]):
                self.errors.append("LDROM signature missing at 0xFF4")
        else:
            if self.size % 1024:
                self.errors.append(f"size {self.size} not a multiple of 1024")
            if not (d[self.size - 0x10] == 0x7B and d[self.size - 0x0F] == 0x6A):
                self.errors.append("APROM signature 7B 6A missing at [size-0x10]")
        self.profile = d[self.size - 0x0E:self.size - 0x04]
        self.expected_model = self.size // 1024          # device must report this at enterISP
        self.block_count = self.size // 16
        fm = FILE_RE.match(self.name)
        self.file_prefix = fm.group(1) if fm else None
        self.file_model = int(fm.group(2)) if fm else None   # board model, from filename
        self.file_version = int(fm.group(3)) if fm else None

    @property
    def valid(self):
        return not self.errors

    def blocks(self):
        for i in range(self.block_count):
            blk = self.data[i * 16:(i + 1) * 16]
            if any(blk):
                yield i * 16, blk

def images_in(directory):
    return [Image(p) for p in sorted(glob.glob(os.path.join(directory, "*.bin")))]

def model_matches(device_model, img):
    """Heuristic only: the filename's model digits equal the board's reported model.
    NOT authoritative - a correct image can carry a different number (the size and
    profile gates at flash time are the real check)."""
    return device_model is not None and img.file_model == device_model


# -------------------------------------------------------------------------- status
def read_device(node):
    """Return (version_string, parsed) or (None, None). Read-only (0xB0 only)."""
    fd = os.open(node, os.O_RDWR)
    try:
        try:
            v = get_version(fd)
        except (TimeoutError, DeviceError):
            return None, None
        return v, parse_version(v)
    finally:
        os.close(fd)

def cmd_status(args):
    imgs = images_in(args.images_dir)
    node = find_node(args.dev)
    dev_ver, dev_parsed = None, None
    if node:
        try:
            dev_ver, dev_parsed = read_device(node)
        except PermissionError:
            print(f"[warn] {node}: permission denied (install 70-daskeyboard.rules or use sudo); "
                  f"listing images without compatibility.", file=sys.stderr)
    dev_model = dev_parsed[1] if dev_parsed else None

    print("DEVICE")
    if node and dev_ver:
        who = f"model {dev_model}, version {dev_parsed[2]}" if dev_parsed else "unrecognised format"
        print(f"  {node}: firmware {dev_ver!r}  ({who})")
    elif node:
        print(f"  {node}: found, version not read")
    else:
        print("  no Das Keyboard vendor interface found")

    print(f"\nIMAGES in {args.images_dir}/  ({len(imgs)} found)")
    hdr = f"  {'file':<16}{'model':>6}{'ver':>5}{'size':>8}  {'kind':<5} {'sig':<5} model?"
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for im in imgs:
        comp = "-" if dev_model is None else ("match" if model_matches(dev_model, im) else "differ")
        print(f"  {im.name:<16}{str(im.file_model):>6}{('V'+str(im.file_version)) if im.file_version is not None else '?':>5}"
              f"{im.size:>8}  {'LDROM' if im.ldrom else 'APROM':<5} "
              f"{'ok' if im.valid else 'BAD':<5} {comp}")
    print("  (\"model?\" = filename model vs board model: a heuristic, NOT the authoritative")
    print("   check. Size and profile are verified at flash time; see `flash`.)")

    print("\nDOWNLOAD SOURCES (fetched from the vendor on demand, not bundled): model(s) "
          + ", ".join(str(m) for m in sorted(FIRMWARE_SOURCES)))
    if dev_model is not None:
        matches = [im for im in imgs if model_matches(dev_model, im) and im.valid]
        have_src = dev_model in FIRMWARE_SOURCES
        print()
        if matches:
            print(f"VERDICT: {len(matches)} local image(s) whose model matches this board "
                  f"({dev_model}): " + ", ".join(im.name for im in matches))
        elif have_src:
            print(f"VERDICT: no local image, but model {dev_model} is downloadable. "
                  f"Run `python3 dk4.py fetch`.")
        else:
            print(f"VERDICT: no local image and no download source whose filename model "
                  f"matches this board (model {dev_model}).")
            print(f"         Filename model is only a heuristic: a correct image (e.g. one")
            print(f"         Das Keyboard support sends for your board) may carry a different")
            print(f"         number but the right SIZE. `dk4.py flash <image>` warns on a")
            print(f"         model difference yet still proceeds, enforcing the authoritative")
            print(f"         size + profile checks at flash time.")
    return 0


# -------------------------------------------------------------------------- list
def cmd_list(args):
    print("FLASHABLE by this tool  (DK4 Professional, HY bootloader, raw .bin):")
    for model in sorted(FIRMWARE_SOURCES):
        s = FIRMWARE_SOURCES[model]
        print(f"  model {model:<5} {s['member']:<13} {s['note']}")
        print(f"              {s['url']}")
    print("\nREFERENCE ONLY  (Q-series: different product + update protocol; NOT flashable here):")
    for name, r in REFERENCE_FIRMWARE.items():
        print(f"  {name:<14} {', '.join(r['versions']):<26} [{r['kind']}]  {r['note']}")
    print(f"\n  Q-series base URL: {REF_BASE}/<MODEL>/<VERSION>/firmware.exe")
    print("  Update a Q-series board with the Das Keyboard Q software / Windows updater, not this tool.")
    return 0


# -------------------------------------------------------------------------- fetch
def cmd_fetch(args):
    model = args.model
    if model is None:
        node = find_node(args.dev)
        if not node:
            print("ERROR: no device found and --model not given.", file=sys.stderr); return 2
        try:
            _, parsed = read_device(node)
        except PermissionError:
            print(f"ERROR: permission denied on {node}; install 70-daskeyboard.rules or use sudo.",
                  file=sys.stderr); return 13
        if not parsed:
            print("ERROR: could not read/parse the firmware version to determine the model.",
                  file=sys.stderr); return 1
        model = parsed[1]
        print(f"[dev ] board model {model} (firmware {parsed[0]}{parsed[1]}V{parsed[2]})")
    if model not in FIRMWARE_SOURCES:
        print(f"No known download source for model {model}. Known sources: model(s) "
              + ", ".join(str(m) for m in sorted(FIRMWARE_SOURCES))
              + f". Request model-{model} firmware from Das Keyboard support.", file=sys.stderr)
        return 3
    src = FIRMWARE_SOURCES[model]
    print(f"[fetch] model {model}: {src['member']} from {src['url']}  ({src['note']})")
    try:
        path, how = fetch_image(model, args.cache_dir)
    except (DeviceError, OSError, zipfile.BadZipFile) as e:
        print(f"ERROR: {e}", file=sys.stderr); return 1
    print(f"[ok ] {how}: {path}\n       sha256 verified {src['sha256']}")
    print(f"\nTo flash it (guarded): python3 dk4.py flash {path}")
    return 0


# -------------------------------------------------------------------------- flash
def flash_precheck(dev_parsed, img):
    """Read-only gate, no device writes. Returns (hard_ok, hard_reason, warnings).
    Only a structurally invalid image is a HARD refusal. A model-number mismatch is
    a WARNING, not a refusal: the filename model number is not a reliable match test
    (a correct image can carry a different number). The authoritative checks are the
    size and profile gates enforced after enterISP, in cmd_flash."""
    if not img.valid:
        return False, f"image failed signature validation: {'; '.join(img.errors)}", []
    warnings = []
    if img.file_model is None:
        warnings.append(f"Could not read a model number from the filename {img.name!r}, "
                        f"so it cannot be checked against your board.")
    elif dev_parsed is None:
        warnings.append("Could not read the board's firmware version, so the image cannot "
                        "be checked against your board before flashing.")
    elif img.file_model != dev_parsed[1]:
        warnings.append(
            f"Image model {img.file_model} does not match your board's reported model "
            f"{dev_parsed[1]} (firmware {dev_parsed[0]}{dev_parsed[1]}V{dev_parsed[2]}). "
            f"The filename model number is only a heuristic - a correct image can carry a "
            f"different number - so this is not a refusal, but flashing a genuinely wrong "
            f"image can BRICK the keyboard. Proceed only if you trust where this file came "
            f"from (for example, Das Keyboard support sent it for your specific board). The "
            f"size and profile checks after enterISP will try to catch a wrong image, but "
            f"they are not a guarantee.")
    return True, "ok", warnings

def confirm(img, node, cur_version, assume_yes):
    print("\n" + "=" * 70)
    print("  WARNING: about to WRITE FIRMWARE. This ERASES and reprograms the")
    print("  keyboard's flash. Wrong image or interruption => BRICK, no recovery.")
    print("  Do NOT unplug or use the keyboard until this finishes.")
    print("=" * 70)
    print(f"    device : {node}  (current firmware {cur_version!r})")
    print(f"    image  : {img.name}  ({img.size} bytes, sha256 {img.sha256[:16]}...)")
    if assume_yes:
        print("  [--force] confirmation auto-accepted."); return True
    if not sys.stdin.isatty():
        print("  Refusing: no interactive terminal and --force not given.", file=sys.stderr)
        return False
    try:
        ans = input(f"\n  Type the image filename ({img.name!r}) to proceed:\n  > ")
    except (EOFError, KeyboardInterrupt):
        print("\n  aborted."); return False
    if ans.strip() != img.name:
        print("  confirmation did not match; aborting with NO changes made."); return False
    return True

def cmd_flash(args):
    img = Image(args.image)
    node = find_node(args.dev)
    if not node:
        print("ERROR: Das Keyboard vendor interface not found.", file=sys.stderr)
        return 2
    try:
        dev_ver, dev_parsed = read_device(node)
    except PermissionError:
        print(f"ERROR: permission denied on {node}; install 70-daskeyboard.rules or use sudo.",
              file=sys.stderr)
        return 13

    ok, reason, warnings = flash_precheck(dev_parsed, img)
    if not ok:
        print(f"REFUSED: {reason}", file=sys.stderr)
        return 5
    for w in warnings:
        print("\n" + "!" * 70)
        print("  WARNING - THIS MAY BE THE WRONG FILE:")
        for line in textwrap.wrap(w, 66):
            print("  " + line)
        print("!" * 70)

    if not confirm(img, node, dev_ver, args.force):
        return 4

    st = [os.open(node, os.O_RDWR), node, WIRE_LEN]     # [fd, node, wire_len]; reopen/isp_cmd update it
    stage = "open"
    try:
        print("\n[1/6] enterISP ...")
        model, _ = enter_isp(st[0], ldrom=img.ldrom)
        stage = "enterISP"
        st[0], st[1], st[2] = reopen_after_isp(st[0])
        print(f"      bootloader at {st[1]}; model={model}; feature report {st[2]}B")
        if model is not None and model != img.expected_model:
            print(f"ERROR: device expects model {model} ({model}*1024) but image is {img.size} "
                  f"bytes (model {img.expected_model}). Aborting before erase.", file=sys.stderr)
            reset_kb(st[0], st[2]); return 7
        time.sleep(SETTLE)
        print("[2/6] checkProfile ...")
        try:
            isp_cmd(st, lambda f, wl: check_profile(f, img.profile, wire_len=wl))
        except DeviceError as e:
            print(f"ERROR: {e}; profile rejected. Aborting before erase.", file=sys.stderr)
            reset_kb(st[0], st[2]); return 9
        stage = "checkProfile"
        if args.stop_after_checkprofile:
            print("\nPROBE OK: enterISP + checkProfile both succeeded; stopping before erase "
                  "(nothing was written). Power-cycle if the keyboard is unresponsive.")
            reset_kb(st[0], st[2]); return 0
        time.sleep(SETTLE)
        print("[3/6] eraseChip ... (do not unplug)")
        isp_cmd(st, lambda f, wl: erase_chip(f, wire_len=wl)); stage = "eraseChip"
        nz = list(img.blocks())
        print(f"[4/6] writeFlash: {len(nz)} blocks ...")
        stage = "writeFlash"
        for n, (addr, blk) in enumerate(nz, 1):
            isp_cmd(st, lambda f, wl, a=addr, b=blk: write_flash(f, a, b, wire_len=wl))
            if n % 64 == 0 or n == len(nz):
                print(f"        {n}/{len(nz)}", end="\r")
        print()
        time.sleep(SETTLE)
        print("[5/6] protectChip ...")
        isp_cmd(st, lambda f, wl: protect_chip(f, wire_len=wl)); stage = "protectChip"
        time.sleep(SETTLE)
        print("[6/6] resetKB ...")
        reset_kb(st[0], st[2])
        print("\nDONE. Re-run `dk4.py status` to confirm the new version.")
        return 0
    except (OSError, TimeoutError, DeviceError) as e:
        before_erase = stage in ("open", "enterISP", "checkProfile")
        print(f"\nERROR: flash aborted during {stage}: {type(e).__name__}: {e}", file=sys.stderr)
        if before_erase:
            print("No eraseChip/writeFlash ran: the firmware is INTACT.", file=sys.stderr)
        else:
            print("WARNING: this happened at or after eraseChip; the flash may be PARTIALLY "
                  "WRITTEN and the board may not boot until a correct image is flashed.",
                  file=sys.stderr)
        try:
            reset_kb(st[0], st[2])
        except Exception:
            pass
        print("If the keyboard is unresponsive, unplug and replug it (USB power-cycle), "
              "then run `python3 dk4.py status`.", file=sys.stderr)
        return 8
    finally:
        try:
            os.close(st[0])
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Das Keyboard 4 firmware tool.")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--images-dir", default=os.path.join(here, "images"))
    ap.add_argument("--cache-dir", default=os.path.expanduser("~/.cache/dk4-firmware"),
                    help="where fetched firmware is stored")
    ap.add_argument("--dev", help="hidraw node (default: auto-detect)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="read-only: device + image compatibility (default)")
    sub.add_parser("list", help="list known firmware: flashable here vs Q-series reference")
    pd = sub.add_parser("fetch", help="download+verify this board's firmware from the vendor")
    pd.add_argument("--model", type=int, help="board model (default: detect from device)")
    pf = sub.add_parser("flash", help="write firmware (guarded)")
    pf.add_argument("image")
    pf.add_argument("--force", action="store_true", help="skip interactive confirmation")
    pf.add_argument("--stop-after-checkprofile", action="store_true",
                    help="PROBE: enter ISP and run up to checkProfile, then stop before "
                         "erasing/writing (never modifies flash; still enters the bootloader)")
    args = ap.parse_args()

    if args.cmd == "flash":
        return cmd_flash(args)
    if args.cmd == "fetch":
        return cmd_fetch(args)
    if args.cmd == "list":
        return cmd_list(args)
    return cmd_status(args)   # default

if __name__ == "__main__":
    sys.exit(main())
