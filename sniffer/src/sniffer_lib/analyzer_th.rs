use std::io::{stdout, Write};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use pcap::{Active, Capture, Error, Packet};
use pktparse::arp::{Operation, parse_arp_pkt};
use pktparse::icmp::parse_icmp_header;
use pktparse::ip::IPProtocol;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use crate::sniffer_lib::command::*;
use crate::sniffer_lib::{Data, L4Protocol, Value};
use crate::sniffer_lib::service_functions::{string_from_icmpcode, string_from_mac};

// Analizza un pacchetto e lo salva nella struct condivisa data
fn packet_analyzer(p: Packet, data: &Arc<Mutex<Data>>){

    let mut data = data.lock().expect("errore interno");

    // Riconosco un pacchetto IpV4 dal campo EtherType della trama Ethernet
    if p.data[12]==0x08 && p.data[13]==0x00 {

        use IPProtocol::*;

        let res = parse_ipv4_header(&p.data[14..]);
        if res.is_err() { return; }
        let ipv4_header = res.unwrap().1;
        let protocol;
        let offset: usize = (4 * ipv4_header.ihl + 14) as usize;

        match ipv4_header.protocol{
            ICMP => {
                let res = parse_icmp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let icmp_header = res.unwrap().1;
                protocol = L4Protocol::Icmp(string_from_icmpcode(icmp_header.code));
            }
            TCP => {
                let res = parse_tcp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let tcp_header = res.unwrap().1;
                protocol = L4Protocol::Tcp(tcp_header.source_port, tcp_header.dest_port);
            }
            UDP => {
                let res = parse_udp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let udp_header = res.unwrap().1;
                protocol = L4Protocol::Udp(udp_header.source_port, udp_header.dest_port);
            }
            HOPOPT => { protocol = L4Protocol::Other("HOPOPT".to_string()); }
            IGMP => { protocol = L4Protocol::Other("IGMP".to_string()); }
            GGP => { protocol = L4Protocol::Other("GGP".to_string()); }
            IPINIP => { protocol = L4Protocol::Other("IPINIP (Tunnel)".to_string()); }
            ST => { protocol = L4Protocol::Other("ST".to_string()); }
            CBT => { protocol = L4Protocol::Other("CBT".to_string()); }
            EGP => { protocol = L4Protocol::Other("EGP".to_string()); }
            IGP => { protocol = L4Protocol::Other("IGP".to_string()); }
            BBNRCCMON => { protocol = L4Protocol::Other("BBNRCCMON".to_string()); }
            NVPII => { protocol = L4Protocol::Other("NVPII".to_string()); }
            PUP => { protocol = L4Protocol::Other("PUP".to_string()); }
            ARGUS => { protocol = L4Protocol::Other("ARGUS".to_string()); }
            EMCON => { protocol = L4Protocol::Other("EMCON".to_string()); }
            XNET => { protocol = L4Protocol::Other("XNET".to_string()); }
            CHAOS => { protocol = L4Protocol::Other("CHAOS".to_string()); }
            IPV6 => { protocol = L4Protocol::Other("IPV6 (Tunnel)".to_string()); }
            ICMP6 => { protocol = L4Protocol::Other("ICMP6".to_string()); }
            Other(_) => { protocol = L4Protocol::Other("Not Recognized".to_string()); }
        }

        // Salvo le info del pacchetto ipV4 catturato nella struct data
        data.ipv4.entry((ipv4_header.source_addr, ipv4_header.dest_addr, protocol)).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec as i64;
            v.packets_number +=1;
            v.bytes_transmitted += ipv4_header.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec as i64,
            last_occurrence: p.header.ts.tv_sec as i64,
            packets_number: 1,
            bytes_transmitted: ipv4_header.length as i64
        });

        data.ipv4_count += 1;

    }

    // Riconosco un pacchetto IpV6 dal campo EtherType della trama Ethernet
    if p.data[12]==0x86 && p.data[13]==0xDD {

        use IPProtocol::*;

        let res = parse_ipv6_header(&p.data[14..]);
        if res.is_err() { return; }
        let ipv6_header = res.unwrap().1;
        let protocol;
        let offset: usize = 14 + 40; // ipv6 ha una lunghezza dell'header fissa

        match ipv6_header.next_header{
            ICMP => {
                let res = parse_icmp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let icmp_header = res.unwrap().1;
                protocol = L4Protocol::Icmp(string_from_icmpcode(icmp_header.code));
            }
            ICMP6 => {
                let icmpv6_type = p.data[offset];
                let descr = match icmpv6_type{
                    1 => "Destination Unreachable",
                    2 => "Packet Too Big",
                    3 => "Time Exceeded",
                    4 => "Parameter Problem",
                    128 => "Echo Request",
                    129 => "Echo Reply",
                    130 => "Multicast Listener Query",
                    131 => "Multicast Listener Report",
                    132 => "Multicast Listener Done",
                    133 => "Router Solicitation",
                    134 => "Router Advertisement",
                    135 => "Neighbor Solicitation",
                    136 => "Neighbor Advertisement",
                    137 => "Redirect Message",
                    _ => "Altro"
                };
                protocol = L4Protocol::IcmpV6(descr.to_string());
            }
            TCP => {
                let res = parse_tcp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let tcp_header = res.unwrap().1;
                protocol = L4Protocol::Tcp(tcp_header.source_port, tcp_header.dest_port);
            }
            UDP => {
                let res = parse_udp_header(&p.data[offset..]);
                if res.is_err() { return; }
                let udp_header = res.unwrap().1;
                protocol = L4Protocol::Udp(udp_header.source_port, udp_header.dest_port);
            }
            HOPOPT => { protocol = L4Protocol::Other("HOPOPT".to_string()); }
            IGMP => { protocol = L4Protocol::Other("IGMP".to_string()); }
            GGP => { protocol = L4Protocol::Other("GGP".to_string()); }
            IPINIP => { protocol = L4Protocol::Other("IPINIP (Tunnel)".to_string()); }
            ST => { protocol = L4Protocol::Other("ST".to_string()); }
            CBT => { protocol = L4Protocol::Other("CBT".to_string()); }
            EGP => { protocol = L4Protocol::Other("EGP".to_string()); }
            IGP => { protocol = L4Protocol::Other("IGP".to_string()); }
            BBNRCCMON => { protocol = L4Protocol::Other("BBNRCCMON".to_string()); }
            NVPII => { protocol = L4Protocol::Other("NVPII".to_string()); }
            PUP => { protocol = L4Protocol::Other("PUP".to_string()); }
            ARGUS => { protocol = L4Protocol::Other("ARGUS".to_string()); }
            EMCON => { protocol = L4Protocol::Other("EMCON".to_string()); }
            XNET => { protocol = L4Protocol::Other("XNET".to_string()); }
            CHAOS => { protocol = L4Protocol::Other("CHAOS".to_string()); }
            IPV6 => { protocol = L4Protocol::Other("IPV6 (Tunnel)".to_string()); }
            Other(_) => { protocol = L4Protocol::Other("Not Recognized".to_string()); }
        }


        // Salvo le info del pacchetto ipV6 catturato nella struct data
        data.ipv6.entry((ipv6_header.source_addr, ipv6_header.dest_addr, protocol)).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec as i64;
            v.packets_number +=1;
            v.bytes_transmitted += ipv6_header.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec as i64,
            last_occurrence: p.header.ts.tv_sec as i64,
            packets_number: 1,
            bytes_transmitted: ipv6_header.length as i64
        });

        data.ipv6_count += 1;

    }
    // Riconosco un pacchetto ARP dal campo EtherType
    if p.data[12]==0x08 && p.data[13]==0x06 {

        let res = parse_arp_pkt(&p.data[14..]);
        if res.is_err() { return; }
        let arp = res.unwrap().1;

        let operation;

        match arp.operation{
            Operation::Request => { operation = "ARP Request"; }
            Operation::Reply => { operation = "ARP Replay"; }
            Operation::Other(_) => { operation = "Other"; }
        }
        // Salvo le info del pacchetto ipV6 catturato nella struct data
        data.arp.entry((string_from_mac(arp.src_mac), string_from_mac(arp.dest_mac), operation.to_string())).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec as i64;
            v.packets_number +=1;
            v.bytes_transmitted += p.header.len as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec as i64,
            last_occurrence: p.header.ts.tv_sec as i64,
            packets_number: 1,
            bytes_transmitted: p.header.len as i64
        });

        data.arp_count += 1;
    }
}

fn command_handler(rx: &Receiver<Command>) -> bool{
    use Command::*;
    let res = rx.try_recv();
    if res.is_ok() {
        match res.unwrap(){
            Pause => {
                let res = rx.recv(); // bloccante
                match res.unwrap() {
                    Pause => { unreachable!("Ho ricevuto pause ma ero già andato in pausa"); }
                    Resume => {  }
                    Stop => { println!("Thread report chiuso"); return true; }
                }
            }
            Resume => { unreachable!("Ho ricevuto resume senza essere prima andato in pausa");}
            Stop => { println!("Thread analyzer chiuso"); return true; }
        }
    }
    stdout().flush().unwrap();
    return false; // false significa non terminare il thread
}

pub fn analyzer_job(mut cap: Capture<Active>, data: &Arc<Mutex<Data>>, rx: Receiver<Command>, verbose_mode: bool){
    //eprintln!("\n\n (Thread sniffer partito) \n");

    use Error::*;
    loop{
        let res = cap.next_packet();
        match res{
            Ok(packet) => { packet_analyzer(packet, &data); }
            Err(e) => {
                match e {
                    MalformedError(e) => if verbose_mode{ eprintln!("MalformedError: The underlying library returned invalid UTF-8\n ( {:?} )", e); }
                    InvalidString => if verbose_mode{ eprintln!("InvalidString: The underlying library returned a null string"); }
                    PcapError(s) => { eprintln!("PcapError: The unerlying library returned an error \n ( {} )\n",s); break; }
                    InvalidLinktype => if verbose_mode{ eprintln!("InvalidLinktype: The linktype was invalid or unknown"); }
                    TimeoutExpired => if verbose_mode{ eprintln!("TimeoutExpired: The timeout expired while reading from a live capture"); }
                    NoMorePackets => { eprintln!("NoMorePackets: No more packets to read from the file"); break; }
                    NonNonBlock => if verbose_mode{ eprintln!("NonNonBlock: Must be in non-blocking mode to function"); }
                    InsufficientMemory => { eprintln!("InsufficientMemory: There is not sufficent memory to create a dead capture"); break;}
                    InvalidInputString => if verbose_mode{ eprintln!("InvalidInputString: An invalid input string (internal null)"); }
                    IoError(e) => if verbose_mode{ eprintln!("IoError: An IO error occurred\n ( {:?} )", e); }
                    // Sui sistemi windows InvalidRawFd non esiste
                    //Error::InvalidRawFd => { eprintln!("InvalidRawFd: An invalid raw file descriptor was provided"); break; }
                    ErrnoError(e) => if verbose_mode{ eprintln!("ErrnoError\n ( {:?} )", e); }
                    BufferOverflow => if verbose_mode{ eprintln!("BufferOverflow: Buffer size overflows capacity"); }
                    _ => { eprintln!("InvalidRawFd: An invalid raw file descriptor was provided"); break; }
                }
            }
        }

        {
            // gestisco l'arrivo di comandi stop,pause e resume
            let stop = command_handler(&rx);
            if stop { return; }
        }

    }
    println!("Ho smesso di raccogliere pacchetti");
}