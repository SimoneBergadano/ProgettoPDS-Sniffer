use std::collections::HashMap;
use std::fs::File;
use std::io::{stdout, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device, Packet};
use pktparse::arp::{Operation, parse_arp_pkt};
use pktparse::ethernet::MacAddress;
use pktparse::ip::IPProtocol;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;

struct Value{
    first_occurrence: i64,
    last_occurrence: i64,
    packets_number: usize,
    bytes_transmitted: i64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum L4Protocol{
    Tcp(u16, u16),
    Udp(u16, u16),
    Icmp,
    Igmp,
    Ipv6,
    NotRecognized
}


struct Data{
    ipv4: HashMap<(Ipv4Addr, Ipv4Addr, L4Protocol), Value>,
    ipv6: HashMap<(Ipv6Addr, Ipv6Addr, L4Protocol), Value>,
    arp: HashMap<(String, String, String), Value>,
}

#[derive(PartialEq)]
pub enum Command{
    Pause,
    Resume
}


fn hex_from_u8(u: u8) -> Option<char>{
    let res;
    match u {
        0 => res = Some('0'),
        1 => res = Some('1'),
        2 => res = Some('2'),
        3 => res = Some('3'),
        4 => res = Some('4'),
        5 => res = Some('5'),
        6 => res = Some('6'),
        7 => res = Some('7'),
        8 => res = Some('8'),
        9 => res = Some('9'),
        10 => res = Some('A'),
        11 => res = Some('B'),
        12 => res = Some('C'),
        13 => res = Some('D'),
        14 => res = Some('E'),
        15 => res = Some('F'),
        _ => res = None
    }
    res
}

fn string_from_mac(mac: MacAddress) ->String{

    let res = format!("{}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
            hex_from_u8(mac.0[0]/16).unwrap(), hex_from_u8(mac.0[0]%16).unwrap(),
            hex_from_u8(mac.0[1]/16).unwrap(), hex_from_u8(mac.0[1]%16).unwrap(),
            hex_from_u8(mac.0[2]/16).unwrap(), hex_from_u8(mac.0[2]%16).unwrap(),
            hex_from_u8(mac.0[3]/16).unwrap(), hex_from_u8(mac.0[3]%16).unwrap(),
            hex_from_u8(mac.0[4]/16).unwrap(), hex_from_u8(mac.0[4]%16).unwrap(),
            hex_from_u8(mac.0[5]/16).unwrap(), hex_from_u8(mac.0[5]%16).unwrap(),
    ).as_str().to_string();

    res
}


pub fn get_available_devices() -> Option<Vec<Device>>{

    let res;
    let tmp = Device::list();

    if tmp.is_ok() { res = Some(tmp.unwrap()); }
    else{
        eprintln!("E' stato riscontrato un errore nel recuperare la lista dei network adapter");
        res = None; }

    res
}


pub fn open_device(dev: Device, promiscuous_mode: bool) -> Option<Capture<Active>>{

    let name = dev.name.clone();

    let cap_res = Capture::from_device(dev).unwrap()
        .promisc(promiscuous_mode)
        .snaplen(5000) // maximum length of a packet captured into the buffer
        .open();

    let res: Option<Capture<Active>>;

    if cap_res.is_ok() { println!(" {} aperto con successo", name); res = Some(cap_res.unwrap()); }
    else {
        eprintln!("Non è stato possibile aprire il socket di rete selezionato ( {} )", name);
        eprintln!("\n Errore: {:?}\n", cap_res.err().unwrap());
        res = None;
    }

    res

}

fn packet_analyzer(p: Packet, data: &Arc<Mutex<Data>>){

    let mut data = data.lock().expect("errore interno");

    // Riconosco un pacchetto IpV4 dal campo EtherType della trama Ethernet
    if p.data[12]==0x08 && p.data[13]==0x00 {

        let ipv4_header = parse_ipv4_header(&p.data[14..]).unwrap().1;

        let protocol;
        let tcp_header;
        let udp_header;

        match ipv4_header.protocol{

            IPProtocol::ICMP => {protocol = L4Protocol::Icmp;}
            IPProtocol::TCP => {
                let offset: usize = (4 * ipv4_header.ihl + 14) as usize;
                tcp_header = parse_tcp_header(&p.data[offset..]).expect("Errore analisi header tcp").1;
                protocol = L4Protocol::Tcp(tcp_header.source_port, tcp_header.dest_port);
            }
            IPProtocol::UDP => {
                let offset: usize = (4 * ipv4_header.ihl + 14) as usize;
                udp_header = parse_udp_header(&p.data[offset..]).expect("Errore analisi header udp").1;
                protocol = L4Protocol::Udp(udp_header.source_port, udp_header.dest_port);
            }
            IPProtocol::IGMP => { protocol = L4Protocol::Igmp; }
            IPProtocol::IPV6 => { protocol = L4Protocol::Ipv6; }
            _ => { protocol = L4Protocol::NotRecognized; }
        }

        // Salvo le info del pacchetto ipV4 catturato nella struct data
        data.ipv4.entry((ipv4_header.source_addr, ipv4_header.dest_addr, protocol)).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec;
            v.packets_number +=1;
            v.bytes_transmitted += ipv4_header.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec,
            last_occurrence: p.header.ts.tv_sec,
            packets_number: 1,
            bytes_transmitted: ipv4_header.length as i64
        });
        stdout().flush().unwrap();

    }
    // Riconosco un pacchetto IpV4 dal campo EtherType della trama Ethernet
    if p.data[12]==0x86 && p.data[13]==0xDD {

        let ipv6_header = parse_ipv6_header(&p.data[14..]).unwrap().1;

        let protocol;

        match ipv6_header.next_header{

            IPProtocol::ICMP => { protocol = L4Protocol::Icmp; }
            IPProtocol::TCP => {
                let offset:usize = 36; // ipv6 ha una lunghezza dell'header fissa
                let tcp_header = parse_tcp_header(&p.data[offset..]).unwrap().1;
                protocol = L4Protocol::Tcp(tcp_header.source_port, tcp_header.dest_port);
            }
            IPProtocol::UDP => {
                let offset:usize = 36; // ipv6 ha una lunghezza dell'header fissa
                let udp_header = parse_udp_header(&p.data[offset..]).unwrap().1;
                protocol = L4Protocol::Udp(udp_header.source_port, udp_header.dest_port);
            }
            _ => { protocol = L4Protocol::NotRecognized; }
        }

        // Salvo le info del pacchetto ipV6 catturato nella struct data
        data.ipv6.entry((ipv6_header.source_addr, ipv6_header.dest_addr, protocol)).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec;
            v.packets_number +=1;
            v.bytes_transmitted += ipv6_header.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec,
            last_occurrence: p.header.ts.tv_sec,
            packets_number: 1,
            bytes_transmitted: ipv6_header.length as i64
        });

    }
    // Riconosco un pacchetto ARP dal campo EtherType
    if p.data[12]==0x08 && p.data[13]==0x06 {
        let arp = parse_arp_pkt(&p.data[14..]).unwrap().1;
        let operation;
        match arp.operation{
            Operation::Request => { operation = "ARP Request"; }
            Operation::Reply => { operation = "ARP Replay"; }
            Operation::Other(_) => { operation = "Other"; }
            }
        // Salvo le info del pacchetto ipV6 catturato nella struct data
        data.arp.entry((string_from_mac(arp.src_mac), string_from_mac(arp.dest_mac), operation.to_string())).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec;
            v.packets_number +=1;
            v.bytes_transmitted += p.header.len as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec,
            last_occurrence: p.header.ts.tv_sec,
            packets_number: 1,
            bytes_transmitted: p.header.len as i64
        });
    }
}

fn report_writer(report_number: usize, f: &mut File, data: Arc<Mutex<Data>>){

    let mut data = data.lock().unwrap();

    write!(&mut *f, "\n\n REPORT#{}:\n", report_number).expect("errore scrittura file");

    write!(&mut *f, "\n Ipv4:").expect("errore scrittura file");
    data.ipv4.keys().for_each(|k|{

        let first_occurrence= data.ipv4.get(k).unwrap().first_occurrence;
        let last_occurrence= data.ipv4.get(k).unwrap().last_occurrence;
        let byte= data.ipv4.get(k).unwrap().bytes_transmitted;
        let num= data.ipv4.get(k).unwrap().packets_number;

        match k.2 {
            L4Protocol::Tcp(source_port, dest_port) => {
                write!(&mut *f, "\n
               -source: {},  dest: {}
                trasported_protocol: {}, source_port: {}, dest_port: {}
                first_occurence: {},  last_occurence: {}
                byte_trasmitted: {},  packets_number: {}",
                       k.0, k.1, "TCP", source_port, dest_port, first_occurrence, last_occurrence, byte, num)
                    .expect("errore interno");
            }
            L4Protocol::Udp(source_port, dest_port) => {
                write!(&mut *f, "\n
               -source: {}  dest: {}
                trasported_protocol: {}, source_port: {}, dest_port: {}
                first_occurence: {},  last_occurence: {}
                byte_trasmitted: {},  packets_number: {}",
                       k.0, k.1, "UDP", source_port, dest_port, first_occurrence, last_occurrence, byte, num)
                    .expect("errore interno");
            }
            L4Protocol::Icmp => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "ICMP", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::Igmp => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "IGMP", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::Ipv6 => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "IPV6", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::NotRecognized => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "NOT RECOGNIZED", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
        }
    });
    data.ipv4.clear();

    write!(&mut *f, "\n\n IpV6:").expect("errore scrittura file");
    data.ipv6.keys().for_each(|k|{

        let first_occurrence= data.ipv6.get(k).unwrap().first_occurrence;
        let last_occurrence= data.ipv6.get(k).unwrap().last_occurrence;
        let byte= data.ipv6.get(k).unwrap().bytes_transmitted;
        let num= data.ipv6.get(k).unwrap().packets_number;

        match k.2 {
            L4Protocol::Tcp(source_port, dest_port) => {
                write!(&mut *f, "\n
               -source: {}  dest: {}
                trasported_protocol: {}, source_port: {}, dest_port: {}
                first_occurence: {},  last_occurence: {}
                byte_trasmitted: {},  packets_number: {}",
                       k.0, k.1, "TCP", source_port, dest_port, first_occurrence, last_occurrence, byte, num)
                    .expect("errore interno");
            }
            L4Protocol::Udp(source_port, dest_port) => {
                write!(&mut *f, "\n
               -source: {}, dest: {}
                trasported_protocol: {}, source_port: {}, dest_port: {}
                first_occurence: {},  last_occurence: {}
                byte_trasmitted: {},  packets_number: {}",
                       k.0, k.1, "UDP", source_port, dest_port, first_occurrence, last_occurrence, byte, num)
                    .expect("errore interno");
            }
            L4Protocol::Icmp => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "ICMP", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::Igmp => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "IGMP", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::Ipv6 => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "IPV6", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
            L4Protocol::NotRecognized => {
                write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
                       k.0, k.1, "NOT RECOGNIZED", first_occurrence, last_occurrence, byte, num).expect("errore interno");
            }
        }
    });
    data.ipv6.clear();

    write!(&mut *f, "\n\n ARP:").expect("errore scrittura file");
    data.arp.keys().for_each(|k|{

        let first_occurrence= data.arp.get(k).unwrap().first_occurrence;
        let last_occurrence= data.arp.get(k).unwrap().last_occurrence;
        let byte= data.arp.get(k).unwrap().bytes_transmitted;
        let num= data.arp.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\
       -source: {},  dest: {},  tipo: {}
        first_occurence: {},  last_occurence: {}
        byte_trasmitted: {},  packets_number: {},",
               k.0, k.1, k.2, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.arp.clear();

}




pub fn start_sniffing(mut cap: Capture<Active>, file_name: String, time_interval: u64, verbose_mode: bool) -> Option<Sender<Command>>{

    // Utilizzeremo 2 thread che parlano tra loro tramite canali
    // Il thread1 legge i pacchetti e li elabora
    // Il thread2 li riceve dal thread1 e genera il report

    let data = Arc::new(Mutex::new(Data{
        ipv4: HashMap::new(),
        ipv6: HashMap::new(),
        arp: HashMap::new(),
    }));

    // thread raccoglitore e analizzatore di pacchetti
    {
        let data = Arc::clone(&data);
        thread::spawn(move ||{
            //eprintln!("\n\n (Thread sniffer partito) \n");
            while let Ok(packet) = cap.next() {
                // Qui dovremo analizzare pacchetto per pacchetto per poi generare il report
                packet_analyzer(packet, &data);
            }
            println!("Ho smesso di raccogliere pacchetti");
        });
    }

    let (tx, rx) = channel::<Command>();


    // thread che andrà a creare il report
    {
        let data = Arc::clone(&data);

        thread::spawn(move ||{

            //println!("\n (Thread report partito) \n");

            let mut f = File::create(file_name).expect("Errore scrittura file");
            let mut report_number:usize = 0;
            write!(f, "Viene generato un report ogni {} secondi", time_interval).expect("errore scrittura file");

            loop{
                // Gestione pausa
                {
                    let res = rx.try_recv();
                    if res.is_ok() {
                        let msg = res.unwrap();
                        if msg == Command::Pause {
                            loop{
                                println!("Il processo di cattura è in pausa");
                                stdout().flush().unwrap();
                                let _blocked_data = data.lock().unwrap(); //Serve a bloccare anche l'altro thread
                                let res = rx.recv();
                                if res.is_ok(){
                                    let msg = res.unwrap();
                                    if msg == Command::Resume {
                                        println!("Il processo di cattura è di nuovo attivo");
                                        stdout().flush().unwrap();
                                        break;
                                    }
                                }
                            }
                        }
                    }

                }

                report_number+=1;
                thread::sleep(Duration::from_secs(time_interval));
                report_writer(report_number, &mut f, data.clone());
                if verbose_mode { println!("\n - Report#{} disponibile\n", report_number); }
                stdout().flush().unwrap();
            }

        });

        Some(tx)
    }



}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
