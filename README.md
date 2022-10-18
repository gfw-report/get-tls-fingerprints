# get-tls-fingerprints.py

```sh
./get-tls-fingerprints.py -h
```
```txt
Usage: ./get-tls-fingerprints.py [FILENAME...]
This script uploads pcap files to https://tlsfingerprint.io/pcap to get TLS fingerprint IDs. By default, print results to stdout and log to stderr.

  -h, --help                   show this help
  -o filename, --out filename  write to file
  -d, --header                 add headers to CSV output (Default: False)
  -p PROXY,    --proxy PROXY   proxy to use, eg. socks5h://127.0.0.1:1080

Example:
  Get the TLS fingerprint IDs of all Clienthellos in trojan-go-v0.10.6.pcapng hello.pcapng:
    ./get-tls-fingerprints.py --header trojan-go-v0.10.6.pcapng hello.pcapng
```

## Install dependencies

```sh
sudo pip3 install requests pysocks
```

## Workflows

First, capture TLS Clienthello messages:

```sh
sudo tcpdump '(tcp[tcp[12]/4]=22) and (tcp[tcp[12]/4+1]=3) and (tcp[tcp[12]/4+5]=1) and (tcp[tcp[12]/4+9]=3)' -Uw "hello.pcap"
```

Then, get the TLS fingerprints in `hello.pcap`:

```sh
./get-fingerprint-id.py --header hello.pcapng
```
```txt
filename,packet_index,sni,fingerprint,url
hello.pcapng,1,,ad63dbc630ad9475,https://tlsfingerprint.io/id/ad63dbc630ad9475
```
