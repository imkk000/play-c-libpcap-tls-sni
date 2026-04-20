# Libpcap TLS SNI

## Why?

I want to find the SNI manually from a TLS Client Hello handshake request using libpcap in C.
Each step transforms the Wireshark payload view into code.

## What it does

Sniffs all TCP port 443 traffic on any network interface and extracts the **SNI (Server Name Indication)** hostname from TLS Client Hello packets. For each connection it also resolves which **process (PID + name)** initiated the connection by:

1. Reading `/proc/net/tcp` to map local port → socket inode (refreshed every 100µs in a background thread)
2. Walking `/proc/<pid>/fd/` to find which process owns that socket inode

Output format:
```
[<timestamp>] <src_ip>:<src_port> -> <dst_ip>:<dst_port> sni=[<hostname>] inode=<n> pid=<pid> (<process_name>)
```

## How it works

| Step | Code | Detail |
|------|------|--------|
| Capture | `pcap_open_live("any", ...)` with BPF filter `tcp port 443` | Captures raw packets on all interfaces |
| Parse headers | `parse_tcp_header()` | Skips 16-byte `any` interface header, then parses IP + TCP headers to find TLS payload offset |
| Detect Client Hello | `tls[0] == 0x16 && tls[5] == 0x01` | TLS record type 0x16 = Handshake, handshake type 0x01 = ClientHello |
| Extract SNI | `find_sni()` | Walks TLS extensions looking for extension type `0x0000` (server_name), extracts the hostname |
| Resolve process | `find_pid_by_inode()` | Reads `/proc/net/tcp` for port→inode, then scans `/proc/*/fd` symlinks for the matching socket |

## Requirements

- Linux
- libpcap (`libpcap-dev` / `libpcap-devel`)
- gcc

## Build & Run

```sh
make run        # compile + run as root
make compile    # compile only  →  ./server
make start      # run only (sudo ./server)
```

> Must run as root (or with `CAP_NET_RAW`) for raw packet capture.
