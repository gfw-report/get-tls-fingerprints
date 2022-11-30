# get-tls-fingerprints.py

This script is a python3 port of parse_pcap.py and parse_hex.py from the [refraction-networking/tls-fingerprint](https://github.com/refraction-networking/tls-fingerprint).

The `--help` option contains a more detailed description on its usage:

```sh
./get-fingerprint-id.py -h
```

```txt
Usage: ./get-fingerprint-id.py [FILENAME...]

  This script reads from pcap or line-separated hex stream files and write the fingerprint IDs of each TLS Clienthello in CSV. With no FILE, or when FILE is -, read standard input. By default, print results to stdout and log to stderr.
  When parsing pcap files, the script outputs four more fields than when it parses line-separated hex stream files, including src_ip, dst_ip, src_port, dst_port.

  -h, --help            show this help
  -o, --out             write to file
  -t, --type            specify input file type, including 'pcap' and 'hex' (default: 'pcap')
  -d, --header          print a CSV header as the first line of output (default: 'false')

Examples:
  Print the SNI, TLS fingerprint ID and other information of each ClientHello in the two pcap files:
    ./get-fingerprint-id.py --header trojan-go-v0.10.6.pcapng hello.pcapng

  Capture and parse ClientHellos in live traffic, while saving a copy of the traffic in hello.pcap:
    sudo tcpdump '(tcp[tcp[12]/4]=22) and (tcp[tcp[12]/4+1]=3) and (tcp[tcp[12]/4+5]=1) and (tcp[tcp[12]/4+9]=3)' -w - | tee hello.pcap | ./get-fingerprint-id.py

  Parse a Clienthello in hex stream format:
    ./get-fingerprint-id.py --type hex <<<160301010d0100010903036f0ad955d72db3f51facea5089efebf2112100ac4fa06c9ed7dbac19bf9432f3209b1bfe5f0967f429ca3c81dd574064d6b476df162fe5dcdab94ecc48aa801b410026cca9cca8c02bc02fc02cc030c009c013c00ac014009c009d002f0035c012000a1303130113020100009a00000010000e00000b6578616d706c652e636f6d000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff010001000010000b000908687474702f312e3100120000002b00050403040303003300260024001d002063180e230480dcd6357bba121a08cb23223622236de663acd0bd098827ee7e0d
```

## Install dependencies

```sh
sudo pip3 install dpkt
```

## Example output

```sh
./get-fingerprint-id.py --header hello.pcap
```

```txt
filename;index;src_ip;dst_ip;src_port;dst_port;sni;id;url;data
hello.pcap;3;127.0.0.1;127.0.0.1;52256;443;example.com;750e3f0f585283bd;https://tlsfingerprint.io/id/750e3f0f585283bd;160301010d0100010903036f0ad955d72db3f51facea5089efebf2112100ac4fa06c9ed7dbac19bf9432f3209b1bfe5f0967f429ca3c81dd574064d6b476df162fe5dcdab94ecc48aa801b410026cca9cca8c02bc02fc02cc030c009c013c00ac014009c009d002f0035c012000a1303130113020100009a00000010000e00000b6578616d706c652e636f6d000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff010001000010000b000908687474702f312e3100120000002b00050403040303003300260024001d002063180e230480dcd6357bba121a08cb23223622236de663acd0bd098827ee7e0d
```
