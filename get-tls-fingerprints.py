#!/usr/bin/env python3

import sys
import getopt
import glob

import struct
import hashlib
import socket

import dpkt

def usage(f=sys.stderr):
    program = sys.argv[0]
    f.write(f"""\
Usage: {program} [FILENAME...]

  This script reads from pcap or line-separated hex stream files and write the fingerprint IDs of each TLS Clienthello in CSV. With no FILE, or when FILE is -, read standard input. By default, print results to stdout and log to stderr.
  When parsing pcap files, the script outputs four more fields than when it parses line-separated hex stream files, including src_ip, dst_ip, src_port, dst_port.

  -h, --help            show this help
  -o, --out             write to file
  -t, --type            specify input file type, including 'pcap' and 'hex' (default: 'pcap')
  -d, --header          print a CSV header as the first line of output (default: 'false')

Examples:
  Print the SNI, TLS fingerprint ID and other information of each ClientHello in the two pcap files:
    {program} --header trojan-go-v0.10.6.pcapng hello.pcapng

  Capture and parse ClientHellos in live traffic, while saving a copy of the traffic in hello.pcap:
    sudo tcpdump '(tcp[tcp[12]/4]=22) and (tcp[tcp[12]/4+1]=3) and (tcp[tcp[12]/4+5]=1) and (tcp[tcp[12]/4+9]=3)' -w - | tee hello.pcap | {program}

  Parse a Clienthello in hex stream format:
    {program} --type hex <<<160301010d0100010903036f0ad955d72db3f51facea5089efebf2112100ac4fa06c9ed7dbac19bf9432f3209b1bfe5f0967f429ca3c81dd574064d6b476df162fe5dcdab94ecc48aa801b410026cca9cca8c02bc02fc02cc030c009c013c00ac014009c009d002f0035c012000a1303130113020100009a00000010000e00000b6578616d706c652e636f6d000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff010001000010000b000908687474702f312e3100120000002b00050403040303003300260024001d002063180e230480dcd6357bba121a08cb23223622236de663acd0bd098827ee7e0d
""")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def input_files(args):
    if not args:
        yield sys.stdin.buffer
    else:
        for arg in args:
            if arg == "-":
                yield sys.stdin.buffer
            else:
                for path in glob.glob(arg):
                    with open(path, 'rb') as f:
                        yield f


def ungrease_one(a):
    if (a & 0x0f0f) == 0x0a0a and (a & 0xf000) >> 8 == (a & 0x00f0):
        return 0x0a0a
    return a


def ungrease(x):
    return map(ungrease_one, x)


def aint(arr):
    if isinstance(arr, int):
        return arr
    return int.from_bytes(arr, byteorder='big', signed=False)


# convert lists of u16 to list of u8s
def list_u16_to_u8(l):
    r = []
    for u16 in l:
        r.append(u16 >> 8)
        r.append(u16 & 0xff)
    return r

#convenience function for generating fingerprint
def update_arr(h, arr):
    h.update(struct.pack('>L', len(arr)))
    for a in arr:
        h.update(struct.pack('>B', a))


class Fingerprint:
    def __init__(self, tls_version, ch_version, cipher_suites, comp_methods, extensions,
                 elliptic_curves, ec_point_fmt, sig_algs, alpn,
                 key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs, record_size_limit,
                 sni=""):

        # all these values are either u8 or a list of u8
        self.tls_version = tls_version
        self.ch_version = ch_version
        self.cipher_suites = cipher_suites
        self.comp_methods = comp_methods
        self.extensions = extensions
        self.elliptic_curves = elliptic_curves
        self.ec_point_fmt = ec_point_fmt
        self.sig_algs = sig_algs
        self.alpn = alpn
        self.key_share = key_share
        self.psk_key_exchange_modes = psk_key_exchange_modes
        self.supported_versions = supported_versions
        self.cert_compression_algs = cert_compression_algs
        self.record_size_limit = record_size_limit
        self.id = None
        self.sni = sni


    @staticmethod
    def from_tls_data(tls):
        if len(tls) == 0:
            return None

        if tls[0] != 0x16:
            # Not a handshake
            # eprint("not a handshake")
            return None

        tls_version = aint(tls[1:3])
        tls_len = aint(tls[3:5])
        hs_type = tls[5]
        if hs_type != 0x01:
            # not a client hello
            # eprint("not a client hello")
            return None

        # Parse client hello
        chello_len = aint(tls[6:9])
        chello_version = aint(tls[9:11])
        rand = tls[11:11 + 32]
        off = 11 + 32

        # session ID
        sess_id_len = aint(tls[off])
        off += 1 + sess_id_len

        # Cipher suites
        cs_len = aint(tls[off:off + 2])
        off += 2
        x = tls[off:off + cs_len]

        alist = []

        for i in range(int(len(x)/2)):
            u16 = x[i*2:i*2+2]
            alist.append(aint(u16))

        cipher_suites = list_u16_to_u8(ungrease(alist))

        off += cs_len

        # Compression
        comp_len = aint(tls[off])
        off += 1
        comp_methods = [aint(x) for x in tls[off:off + comp_len]]
        off += comp_len

        # Extensions
        ext_len = aint(tls[off:off + 2])
        off += 2

        sni_host = ''
        curves = []
        pt_fmts = []
        sig_algs = []
        alpn = []
        key_share = []
        psk_key_exchange_modes = []
        supported_versions = []
        cert_comp_algs = []
        record_size_limit = []
        exts = []
        end = off + ext_len
        while off < end:
            ext_type = aint(tls[off:off + 2])
            off += 2
            ext_len = aint(tls[off:off + 2])
            off += 2
            exts.append(ext_type)

            if ext_type == 0x0000:
                # SNI
                sni_len = aint(tls[off:off + 2])
                sni_type = aint(tls[off + 2])
                sni_len2 = aint(tls[off + 3:off + 5])
                sni_host = tls[off + 5:off + 5 + sni_len2]

            elif ext_type == 0x000a:
                # Elliptic curves
                # len...

                x = tls[off:off + ext_len]
                curves = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in range(int(len(x) / 2))]))
            elif ext_type == 0x000b:
                # ec_point_fmt
                pt_fmt_len = aint(tls[off])
                pt_fmts = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x000d:
                # sig algs
                # Actually a length field, and actually these are 2-byte pairs but
                # this currently matches format...
                sig_algs = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0010:
                # alpn
                # also has a length field...
                alpn = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0033:
                # key share
                this_ext = tls[off:off+ext_len]
                overall_len = aint(this_ext[0:2])
                groups = []
                idx = 2
                while idx+2 < len(this_ext):
                    # parse the named group
                    group = ungrease_one(aint(this_ext[idx:idx+2]))
                    # skip the next bytes
                    key_len = aint(this_ext[idx+2:idx+4])
                    groups.append(group)
                    groups.append(key_len)
                    idx += 2 + 2 + key_len

                key_share = list_u16_to_u8(groups)
            elif ext_type == 0x002d:
                # psk_key_exchange_modes
                # skip length
                psk_key_exchange_modes = [aint(x) for x in tls[off+1:off+ext_len]]
            elif ext_type == 0x002b:
                # supported_versions
                x = tls[off+1:off+ext_len]   # skip length
                supported_versions = list_u16_to_u8(ungrease([aint(x[2*i:2*i+2]) for i in range(int(len(x)/2))]))
            elif ext_type == 0x001b:
                # compressed_cert
                cert_comp_algs = [aint(x) for x in tls[off:off+ext_len]]
            elif ext_type == 0x001c:
                record_size_limit = [aint(x) for x in tls[off:off+ext_len]]

            off += ext_len

        exts = list_u16_to_u8(ungrease(exts))
        return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
                                         exts, curves, pt_fmts, sig_algs, alpn,
                                         key_share, psk_key_exchange_modes, supported_versions,
                                         cert_comp_algs, record_size_limit, sni=sni_host)

    def current_id(self, h):
        out, = struct.unpack('>Q', h.digest()[0:8])
        eprint("{:x}".format(out))

    def get_fingerprint_v2(self):
        h = hashlib.sha1()

        # h.update(struct.pack('>HH', self.tls_version, self.ch_version))
        h.update(struct.pack('>H', self.tls_version))
        h.update(struct.pack('>H', self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)
        update_arr(h, self.key_share)
        update_arr(h, self.psk_key_exchange_modes)
        update_arr(h, self.supported_versions)
        update_arr(h, self.cert_compression_algs)
        update_arr(h, self.record_size_limit)

        out, = struct.unpack('>Q', h.digest()[0:8])
        return out

    def get_fingerprint(self):
        if self.id is None:
            self.id = self.get_fingerprint_v2()
        return self.id

def parse_pcap(pcap_fname):
    p = dpkt.pcap.Reader(pcap_fname)

    for index, (ts, pkt) in enumerate(p):
        try:
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    if eth.type == dpkt.ethernet.ETH_TYPE_PPPoE:
                        if eth.data.data.p != 0x21:
                            continue
                        eth = eth.data.data
                    else:
                        continue
            except dpkt.dpkt.NeedData:
                eth = dpkt.sll.SLL(pkt)
                if eth.ethtype != dpkt.ethernet.ETH_TYPE_IP:
                    continue

            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            tcp = ip.data

            fingerprint = Fingerprint.from_tls_data(tcp.data)

            sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)

            if fingerprint is not None:
                yield (index, sip, dip, tcp.sport, tcp.dport, fingerprint.sni, fingerprint.get_fingerprint(), tcp.data)

        except Exception as e:
            eprint('Error in pkt %d: %s' % (index, e))


def parse_hex(hex_str):
    data = bytes.fromhex(hex_str)
    fingerprint = Fingerprint.from_tls_data(data)

    return fingerprint.sni, fingerprint.get_fingerprint()


if __name__ == '__main__':
    opts, args = getopt.gnu_getopt(sys.argv[1:], "ho:t:d", ["help", "out=", "type=", "header"])
    output_file = sys.stdout
    file_type = "pcap"
    header = False
    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(0)
        if o == "-o" or o == "--out":
            output_file = open(a, 'a+')
        if o == "-d" or o == "--header":
            header = True
        if o == "-t" or o == "--type":
            if a not in ("pcap", "hex"):
                eprint(f"Unexpected file type: {a}")
                usage()
                sys.exit(-1)
            file_type = a

    if file_type == "pcap":
        if header:
            print(f"filename;index;src_ip;dst_ip;src_port;dst_port;sni;id;url;data")
        for f in input_files(args):
            for (index, sip, dip, sport, dport, sni, fps, data) in parse_pcap(f):
                print(f"{f.name};{index};{sip};{dip};{sport};{dport};{sni.decode('utf-8')};{fps:016x};https://tlsfingerprint.io/id/{fps:016x};{data.hex()}", file=output_file)
    elif file_type == "hex":
        if header:
            print(f"filename;index;sni;id;url;data")
        for f in input_files(args):
            for index, line in enumerate(f):
                line = line.decode("utf-8").rstrip()
                sni, fps = parse_hex(line)
                print(f"{f.name};{index};{sni.decode('utf-8')};{fps:016x};https://tlsfingerprint.io/id/{fps:016x};{line}", file=output_file)
    output_file.close()
