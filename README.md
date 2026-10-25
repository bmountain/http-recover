# http-recover

This is a sample program to decode HTTP messages from a pcap file.

- Parses pcap files that is captured in advance.
- Assumes the capture contains a single TCP connection.
- Only supports HTTP messages over Ethernet/IPv4/TCP.
- Ignores Ethernet frames that were not captured entirely.
- Ignores HTTP parse error silently.

## Usage
Install Rust and libpcap development files.
On Debian/Ubuntu:
```sh
sudo apt install build-essential pkg-config libpcap-dev
cargo run
```

## Dependencies
- pcap: Reads packet records from the pcap file.
- etherparse: Parses Ethernet, IPv4, and TCP headers.
- protolens: Reassembles TCP streams and parses HTTP messages.
