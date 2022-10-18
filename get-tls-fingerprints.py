#!/usr/bin/env python3

import sys
import getopt
import glob
import re

import requests


def usage(f=sys.stderr):
    program = sys.argv[0]
    f.write(f"""\
Usage: {program} [FILENAME...]
This script uploads pcap files to https://tlsfingerprint.io/pcap to get TLS fingerprint IDs. By default, print results to stdout and log to stderr.

  -h, --help                   show this help
  -o filename, --out filename  write to file
  -d, --header                 add headers to CSV output (Default: False)
  -p PROXY,    --proxy PROXY   proxy to use, eg. socks5h://127.0.0.1:1080

Example:
  Get the TLS fingerprint IDs of all Clienthellos in trojan-go-v0.10.6.pcapng hello.pcapng:
    {program} --header trojan-go-v0.10.6.pcapng hello.pcapng
""")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def input_files(args):
    if not args:
        yield sys.stdin
    else:
        for arg in args:
            if arg == "-":
                yield sys.stdin
            else:
                for path in glob.glob(arg):
                    with open(path, 'rb') as f:
                        yield f


def parse(text):
    result_pattern = re.compile('#([0-9]+) (.*) <a href="/id/(.+)">(.+)</a><br/>')
    results = result_pattern.findall(text)
    return results


def upload(f, proxy_url):
    url = "https://tlsfingerprint.io/pcap"
    session = requests.Session()
    if proxy_url:
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url,
        }

    response = session.post(url, files={"file": f})
    return response


if __name__ == '__main__':
    opts, args = getopt.gnu_getopt(sys.argv[1:], "ho:dp:", ["help", "out=", "header", "proxy="])
    output_file = sys.stdout
    header = False
    proxy_url = ""
    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(0)
        if o == "-o" or o == "--out":
            output_file = open(a, 'a+')
        if o == "-d" or o == "--header":
            header = True
        if o == "-p" or o == "--proxy":
            proxy_url = a

    if header:
        print(f"filename,packet_index,sni,fingerprint,url", file=output_file)

    for f in input_files(args):
        response = upload(f, proxy_url)
        results = parse(response.text)
        for result in results:
            index, sni, fingerprint, _ = result
            print(f"{f.name},{index},{sni},{fingerprint},https://tlsfingerprint.io/id/{fingerprint}", file=output_file)
    output_file.close()
