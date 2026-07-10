#!/usr/bin/env python3
"""
dk4_read.py - READ-ONLY firmware-version reader for the Das Keyboard 4 Professional
(Metadot VID 0x24F0, PID 0x204A), reverse-engineered from the macOS HYKBUtility.

SAFETY: This tool sends exactly ONE command byte, 0xB0 (get firmware version),
which is a pure query. It contains no code path that can enter ISP, erase, write,
or protect flash. The dangerous opcodes (0xA0/0xA1/0xA4/0xA8/0xAA/0xAF) appear
nowhere in this file. Verified by: grep -E '0xa[0-9a-f]|0xA[0-9A-F]' dk4_read.py

Protocol (see reversed HYKB class):
  transport  = HID FEATURE report, report id 1, 8 bytes on the wire
               (1 report-id byte + 7 payload bytes), fragmented in 7-byte chunks.
  request    = [0xEA, L+2, cmd, <L contents>, XOR-of-preceding]   (L=0 here)
  response   = [0xED, RL, cmd_echo, status, <payload RL-3 bytes>, XOR]
               status byte 0 == OK; version is the payload as text.
  On Linux hidraw the report-id byte stays at buf[0]; 0xED lands at buf[1].
"""
import sys, os, glob, struct, time, fcntl, argparse

VID, PID = 0x24F0, 0x204A
REPORT_ID = 1
WIRE_LEN = 8                 # 1 id byte + 7 data bytes (from the report descriptor)
DATA_LEN = WIRE_LEN - 1      # 7 payload bytes per report
CMD_GET_VERSION = 0xB0       # runtime get-version. THE ONLY COMMAND THIS TOOL SENDS.
HDR_REQ, HDR_RESP = 0xEA, 0xED

def _IOC(d, t, nr, size): return (d << 30) | (size << 16) | (t << 8) | nr
def HIDIOCSFEATURE(l): return _IOC(3, 0x48, 0x06, l)   # 'H' == 0x48
def HIDIOCGFEATURE(l): return _IOC(3, 0x48, 0x07, l)

def build_packet(cmd, contents=b""):
    if cmd != CMD_GET_VERSION:
        raise ValueError("this read-only tool only emits 0xB0")
    L = len(contents)
    pkt = bytearray([HDR_REQ, (L + 2) & 0xFF, cmd]) + bytearray(contents)
    chk = 0
    for b in pkt:
        chk ^= b
    pkt.append(chk)
    return bytes(pkt)

def fragment(pkt):
    """Split into 7-byte chunks, each prefixed with report id -> 8-byte reports."""
    out = []
    for i in range(0, len(pkt), DATA_LEN):
        chunk = pkt[i:i + DATA_LEN].ljust(DATA_LEN, b"\0")
        out.append(bytes([REPORT_ID]) + chunk)
    return out

def find_node(explicit=None):
    if explicit:
        return explicit
    for path in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        node = "/dev/" + os.path.basename(path)
        try:
            with open(path + "/device/uevent") as f:
                uevent = f.read()
        except OSError:
            continue
        if f"{VID:08X}:{PID:08X}" not in uevent.upper().replace("0X", ""):
            # HID_ID looks like 0003:000024F0:0000204A
            if f"{VID:08X}" not in uevent.upper() or f"{PID:08X}" not in uevent.upper():
                continue
        # confirm this node carries a Feature report in a UP=1/U=0x80 collection
        try:
            with open(path + "/device/report_descriptor", "rb") as f:
                desc = f.read()
        except OSError:
            continue
        if has_vendor_feature(desc):
            return node
    return None

def has_vendor_feature(desc):
    """True if descriptor has a Feature main item inside a UsagePage1/Usage0x80 collection."""
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
        if btype == 1 and btag == 0x0:
            up = val
        elif btype == 2 and btag == 0x0:
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

def read_version(node, verbose=True):
    fd = os.open(node, os.O_RDWR)
    try:
        # ---- send the get-version request (read-only query) ----
        pkt = build_packet(CMD_GET_VERSION)
        if verbose:
            print(f"[send] request packet : {pkt.hex(' ')}")
        for rep in fragment(pkt):
            if verbose:
                print(f"[send] SET_FEATURE    : {rep.hex(' ')}")
            fcntl.ioctl(fd, HIDIOCSFEATURE(len(rep)), bytearray(rep))

        # ---- poll + reassemble the response ----
        stream = bytearray()
        id_off = None
        rl = None
        for attempt in range(200):
            buf = bytearray(WIRE_LEN)
            buf[0] = REPORT_ID
            n = fcntl.ioctl(fd, HIDIOCGFEATURE(WIRE_LEN), buf)
            data = bytes(buf[:n]) if n > 0 else bytes(buf)
            # locate the report-id byte convention once, from the first frame
            if id_off is None:
                if len(data) >= 2 and data[0] == REPORT_ID and data[1] == HDR_RESP:
                    id_off = 1                       # Linux keeps id at [0]
                elif data and data[0] == HDR_RESP:
                    id_off = 0                       # id already stripped
                else:
                    time.sleep(0.005); continue      # not ready yet
            payload = data[id_off:]
            stream += payload
            if rl is None and len(stream) >= 2:
                rl = stream[1]                       # response length field
            if rl is not None and len(stream) >= rl + 2:
                break
            time.sleep(0.005)

        if verbose:
            print(f"[recv] raw stream     : {stream.hex(' ')}")
        if not stream or stream[0] != HDR_RESP:
            return None, "no valid response (first byte != 0xED)", stream
        rl = stream[1]
        cmd_echo = stream[2]
        status = stream[3]
        actual = rl - 3
        body = bytes(stream[4:4 + actual])
        # advisory XOR check
        xor = 0
        for b in stream[0:rl + 1]:
            xor ^= b
        xor_ok = (len(stream) > rl + 1 and stream[rl + 1] == xor)
        if verbose:
            print(f"[recv] RL={rl} cmd_echo={cmd_echo:#04x} status={status:#04x} "
                  f"actualSize={actual} xor_ok={xor_ok}")
        if status != 0:
            return None, f"device returned error status {status:#04x}", stream
        text = body.decode("latin-1", "replace").strip("\x00").strip()
        return {"version": text, "raw_payload": body.hex(" "),
                "cmd_echo": cmd_echo, "status": status}, None, stream
    finally:
        os.close(fd)

def main():
    ap = argparse.ArgumentParser(description="Read Das Keyboard 4 Pro firmware version (read-only).")
    ap.add_argument("--dev", help="hidraw node (default: auto-detect the vendor interface)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build+print the request packet only; touch no device")
    args = ap.parse_args()

    if args.dry_run:
        pkt = build_packet(CMD_GET_VERSION)
        print("DRY RUN - no device access.")
        print(f"  request packet : {pkt.hex(' ')}   ([0xEA, L+2, cmd=0xB0, xor])")
        for rep in fragment(pkt):
            print(f"  SET_FEATURE    : {rep.hex(' ')}   (report id 1 + 7 bytes)")
        print(f"  will poll GET_FEATURE (id 1, {WIRE_LEN}B) until first byte 0xED")
        return 0

    node = find_node(args.dev)
    if not node:
        print("ERROR: Das Keyboard vendor interface (24F0:204A, UsagePage1/Usage0x80) not found.",
              file=sys.stderr)
        return 2
    print(f"[dev ] {node}")
    try:
        result, err, _ = read_version(node)
    except PermissionError:
        print(f"ERROR: permission denied on {node}. Re-run with sudo:\n"
              f"  sudo python3 {os.path.abspath(__file__)}", file=sys.stderr)
        return 13
    if err:
        print(f"RESULT: {err}", file=sys.stderr)
        return 1
    print(f"\nFIRMWARE VERSION: {result['version']!r}")
    print(f"  (payload bytes: {result['raw_payload']}, cmd_echo={result['cmd_echo']:#04x})")
    return 0

if __name__ == "__main__":
    sys.exit(main())
