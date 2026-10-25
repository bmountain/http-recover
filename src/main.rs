use etherparse::SlicedPacket;
use pcap::{Capture, Offline};
use protolens::Prolens;
use std::error::Error;
use std::fmt;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Endpoint {
    addr: Ipv4Addr,
    port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct TcpFlags {
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    ece: bool,
    cwr: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FIN={}, SYN={}, RST={}, PSH={}, ACK={}, URG={}, ECE={}, CWR={}",
            self.fin, self.syn, self.rst, self.psh, self.ack, self.urg, self.ece, self.cwr
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpSegment {
    from: Endpoint,
    to: Endpoint,
    payload: Vec<u8>,
    sequence_number: u32,
    acknowledgement_number: u32,
    flag: TcpFlags,
}

impl protolens::Packet for TcpSegment {
    fn trans_proto(&self) -> protolens::TransProto {
        protolens::TransProto::Tcp
    }
    fn sip(&self) -> std::net::IpAddr {
        std::net::IpAddr::V4(self.from.addr)
    }
    fn dip(&self) -> std::net::IpAddr {
        std::net::IpAddr::V4(self.to.addr)
    }
    fn tu_sport(&self) -> u16 {
        self.from.port
    }
    fn tu_dport(&self) -> u16 {
        self.to.port
    }
    fn syn(&self) -> bool {
        self.flag.syn
    }
    fn seq(&self) -> u32 {
        self.sequence_number
    }
    fn fin(&self) -> bool {
        self.flag.fin
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
    fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

impl fmt::Display for TcpSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}->{}, sequence={}, acknowledgement={}, {}\n```\n{}```",
            self.from,
            self.to,
            self.sequence_number,
            self.acknowledgement_number,
            self.flag,
            String::from_utf8_lossy(&self.payload)
        )
    }
}

impl TcpSegment {
    fn from_sliced_packet(packet: &SlicedPacket<'_>) -> Option<TcpSegment> {
        let Some(etherparse::NetSlice::Ipv4(ip)) = &packet.net else {
            return None;
        };
        let ip_header = &ip.header();

        let Some(etherparse::TransportSlice::Tcp(tcp)) = &packet.transport else {
            return None;
        };

        let flag = TcpFlags {
            fin: tcp.fin(),
            syn: tcp.syn(),
            rst: tcp.rst(),
            psh: tcp.psh(),
            ack: tcp.ack(),
            urg: tcp.urg(),
            ece: tcp.ece(),
            cwr: tcp.cwr(),
        };

        Some(TcpSegment {
            from: Endpoint {
                addr: ip_header.source_addr(),
                port: tcp.source_port(),
            },
            to: Endpoint {
                addr: ip_header.destination_addr(),
                port: tcp.destination_port(),
            },
            payload: tcp.payload().to_vec(),
            sequence_number: tcp.sequence_number(),
            acknowledgement_number: tcp.acknowledgment_number(),
            flag,
        })
    }
}

fn dump_body<E>(
    data: &[u8],
    _seq: u32,
    _: *mut std::ffi::c_void,
    _direction: protolens::Direction,
    _content_enc: &Option<Vec<E>>,
    _transfer_enc: &Option<Vec<E>>,
) {
    print!("{}", String::from_utf8_lossy(data));
}

fn dump_header(data: &[u8], _seq: u32, _: *mut std::ffi::c_void, _direction: protolens::Direction) {
    print!("{}", String::from_utf8_lossy(data));
}

fn main() -> Result<(), Box<dyn Error>> {
    let pcap_path = Path::new("./captures/demo.pcap");
    let mut cap = Capture::from_file(pcap_path)?;
    let segments = to_segments(&mut cap)?;
    let mut lens = Prolens::<TcpSegment>::default();
    lens.set_cb_http_start_line(dump_header);
    lens.set_cb_http_header(dump_header);
    lens.set_cb_http_body(dump_body);
    let mut task = lens.new_task(protolens::TransProto::Tcp);
    lens.set_task_parser(&mut task, protolens::L7Proto::Http);
    for segment in segments {
        if !segment.payload.is_empty() {
            println!(
                "{}:{}->{}:{}",
                segment.from.addr, segment.from.port, segment.to.addr, segment.to.port
            );
        }
        lens.run_task(&mut task, segment);
    }
    Ok(())
}

fn to_segments(cap: &mut Capture<Offline>) -> Result<Vec<TcpSegment>, pcap::Error> {
    let mut segments = Vec::new();
    loop {
        let packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::NoMorePackets) => {
                break;
            }
            Err(err) => return Err(err),
        };
        if packet.header.caplen != packet.header.len {
            eprintln!("A part of ethernet frame is not captured");
            continue;
        }
        let Ok(packet) = SlicedPacket::from_ethernet(packet.data) else {
            continue;
        };
        let Some(segment) = TcpSegment::from_sliced_packet(&packet) else {
            continue;
        };
        segments.push(segment);
    }
    Ok(segments)
}
