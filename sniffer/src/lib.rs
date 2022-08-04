use std::collections::HashMap;
use std::fs::File;
use std::io::{stdout, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
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


struct Data{
    ipv4: HashMap<(Ipv4Addr, Ipv4Addr, String), Value>,
    ipv6: HashMap<(Ipv6Addr, Ipv6Addr, String), Value>,
    tcp: HashMap<(u16, u16), Value>,
    udp: HashMap<(u16, u16), Value>,
    arp: HashMap<(String, String, String), Value>,
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
    else{ res = None; }

    res
}


pub fn open_device(dev: Device, promiscuous_mode: bool) -> Result<Capture<Active>, pcap::Error>{

    let cap_res = Capture::from_device(dev).unwrap()
        .promisc(promiscuous_mode)
        .snaplen(5000)
        .open();

    cap_res

}

fn packet_analyzer(p: Packet, data: &Arc<Mutex<Data>>){
    // Questa funzione si occuperà di analizzare i pacchetti e restituire enum del pacchetto riconosciuto
    //println!("\n - Ho ricevuto un pacchetto: {:?}", p);

    //println!("{} - {}", p.data[12], p.data[13]);

    let mut data = data.lock().expect("errore interno");

    if p.data[12]==0x08 && p.data[13]==0x00 {

        let ip = parse_ipv4_header(&p.data[14..]).unwrap().1;

        //println!(" - Ho un pacchetto ipv4: source ip: {}, dest ip: {}", ip.source_addr, ip.dest_addr);

        let mut traspported_protocol = "not recognized";

        match ip.protocol{

            IPProtocol::ICMP => {traspported_protocol = "ICMP";}
            IPProtocol::TCP => {
                traspported_protocol = "TCP";
                let offset:usize = (4 * ip.ihl + 14) as usize;
                let tcp = parse_tcp_header(&p.data[offset..]).expect("Errore analisi header tcp").1;
                data.tcp.entry((tcp.source_port, tcp.dest_port)).and_modify(|v|{
                    v.last_occurrence = p.header.ts.tv_sec;
                    v.packets_number +=1;
                    v.bytes_transmitted += (ip.length - 4*(ip.ihl as u16)) as i64;
                }).or_insert(Value{
                    first_occurrence: p.header.ts.tv_sec,
                    last_occurrence: p.header.ts.tv_sec,
                    packets_number: 1,
                    bytes_transmitted: (ip.length - 4*(ip.ihl as u16)) as i64
                });
                stdout().flush().unwrap();
                //println!("Pacchetto TCP: porta ingresso: {} porta uscita = {} ihl={}", tcp_header.source_port, tcp_header.dest_port, ip.ihl);
            }
            IPProtocol::UDP => {
                traspported_protocol = "UDP";
                let offset:usize = (4 * ip.ihl + 14) as usize;
                let udp = parse_udp_header(&p.data[offset..]).expect("Errore analisi header udp").1;
                data.udp.entry((udp.source_port, udp.dest_port)).and_modify(|v|{
                    v.last_occurrence = p.header.ts.tv_sec;
                    v.packets_number +=1;
                    v.bytes_transmitted += (ip.length - 4*(ip.ihl as u16)) as i64;
                }).or_insert(Value{
                    first_occurrence: p.header.ts.tv_sec,
                    last_occurrence: p.header.ts.tv_sec,
                    packets_number: 1,
                    bytes_transmitted: (ip.length - 4*(ip.ihl as u16)) as i64
                });
                stdout().flush().unwrap();
            }
            IPProtocol::IPV6 => { traspported_protocol = "IPV6"; }
            _ => {}
        }

        // Salvo le info del pacchetto ipV4 catturato nella struct data
        data.ipv4.entry((ip.source_addr, ip.dest_addr, traspported_protocol.to_string())).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec;
            v.packets_number +=1;
            v.bytes_transmitted += ip.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec,
            last_occurrence: p.header.ts.tv_sec,
            packets_number: 1,
            bytes_transmitted: ip.length as i64
        });
        stdout().flush().unwrap();

    }
    if p.data[12]==0x86 && p.data[13]==0xDD {
        //println!(" - Ho un pacchetto ipv6!");
        let ipv6 = parse_ipv6_header(&p.data[14..]).unwrap().1;
        stdout().flush().unwrap();
        let mut traspported_protocol = "not recognized";

        match ipv6.next_header{
            IPProtocol::ICMP => { traspported_protocol = "ICMP";}
            IPProtocol::IGMP => { traspported_protocol = "IGMP";}
            IPProtocol::TCP => {
                traspported_protocol = "TCP";
                let offset:usize = 36; // ipv6 ha ua lunghezza dell'header fissa
                let tcp = parse_tcp_header(&p.data[offset..]).unwrap().1;
                data.tcp.entry((tcp.source_port, tcp.dest_port)).and_modify(|v|{
                    v.last_occurrence = p.header.ts.tv_sec;
                    v.packets_number +=1;
                    v.bytes_transmitted += ipv6.length as i64;
                }).or_insert(Value{
                    first_occurrence: p.header.ts.tv_sec,
                    last_occurrence: p.header.ts.tv_sec,
                    packets_number: 1,
                    bytes_transmitted: ipv6.length as i64
                });
                //println!("Pacchetto TCP: porta ingresso: {} porta uscita = {} ihl={}", tcp_header.source_port, tcp_header.dest_port, ip.ihl);
            }
            IPProtocol::UDP => { traspported_protocol = "UDP";}
            IPProtocol::IPV6 => {}
            IPProtocol::ICMP6 => { traspported_protocol = "ICMPV6";}
            _ => {}
        }

        // Salvo le info del pacchetto ipV6 catturato nella struct data
        data.ipv6.entry((ipv6.source_addr, ipv6.dest_addr, traspported_protocol.to_string())).and_modify(|v|{
            v.last_occurrence = p.header.ts.tv_sec;
            v.packets_number +=1;
            v.bytes_transmitted += ipv6.length as i64;
        }).or_insert(Value{
            first_occurrence: p.header.ts.tv_sec,
            last_occurrence: p.header.ts.tv_sec,
            packets_number: 1,
            bytes_transmitted: ipv6.length as i64
        });

    }
    if p.data[12]==0x08 && p.data[13]==0x06 {
        //println!(" - Ho un pacchetto ARP!");
        let arp = parse_arp_pkt(p.data).unwrap().1;
        let operation ;
        match arp.operation{
            Operation::Request => { operation = "ARP Request"; }
            Operation::Reply => { operation = "ARP Replay"; }
            Operation::Other(_) => { operation = "Other"; }
        }
        stdout().flush().unwrap();
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
        let last_occurrence= data.ipv4.get(k).unwrap().first_occurrence;
        let byte= data.ipv4.get(k).unwrap().bytes_transmitted;
        let num= data.ipv4.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
               k.0, k.1, k.2, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.ipv4.clear();

    write!(&mut *f, "\n\n IpV6:").expect("errore scrittura file");
    data.ipv6.keys().for_each(|k|{

        let first_occurrence= data.ipv6.get(k).unwrap().first_occurrence;
        let last_occurrence= data.ipv6.get(k).unwrap().first_occurrence;
        let byte= data.ipv6.get(k).unwrap().bytes_transmitted;
        let num= data.ipv6.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\n -source: {}  dest: {}  trasported_protocol: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
               k.0, k.1, k.2, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.ipv6.clear();

    write!(&mut *f, "\n\n ARP:").expect("errore scrittura file");
    data.arp.keys().for_each(|k|{

        let first_occurrence= data.arp.get(k).unwrap().first_occurrence;
        let last_occurrence= data.arp.get(k).unwrap().first_occurrence;
        let byte= data.arp.get(k).unwrap().bytes_transmitted;
        let num= data.arp.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\n -source: {:X?}  dest: {:X?}  tipo: {}\n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
               k.0, k.1, k.2, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.arp.clear();

    write!(&mut *f, "\n\n TCP:").expect("errore scrittura file");
    data.tcp.keys().for_each(|k|{

        let first_occurrence= data.tcp.get(k).unwrap().first_occurrence;
        let last_occurrence= data.tcp.get(k).unwrap().first_occurrence;
        let byte= data.tcp.get(k).unwrap().bytes_transmitted;
        let num= data.tcp.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\n -source_port: {}  dest_port: {}  \n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
               k.0, k.1, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.tcp.clear();

    write!(&mut *f, "\n\n UDP:").expect("errore scrittura file");
    data.udp.keys().for_each(|k|{

        let first_occurrence= data.udp.get(k).unwrap().first_occurrence;
        let last_occurrence= data.udp.get(k).unwrap().first_occurrence;
        let byte= data.udp.get(k).unwrap().bytes_transmitted;
        let num= data.udp.get(k).unwrap().packets_number;

        write!(&mut *f, "\n\n -source_port: {}  dest_port: {}  \n  first_occurence: {}  last_occurence: {}\n  byte_trasmitted: {}  packets_number: {},",
               k.0, k.1, first_occurrence, last_occurrence, byte, num).expect("errore interno");
    });
    data.udp.clear();

}


pub fn start_sniffing(mut cap: Capture<Active>, file_name: String, time_interval: u64){

    // Utilizzeremo 2 thread che parlano tra loro tramite canali
    // Il thread1 legge i pacchetti e li legge
    // Il thread2 li riceve dal thread1 e genera il report

    let data = Arc::new(Mutex::new(Data{
        ipv4: HashMap::new(),
        ipv6: HashMap::new(),
        tcp: HashMap::new(),
        udp: HashMap::new(),
        arp: HashMap::new(),
    }));

    //let mut f = File::create(file_name).expect("Errore scrittura file");


    // thread raccoglitore di pacchetti ( e analizzatore )
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


    // thread che andrà a creare il report
    {
        let data = Arc::clone(&data);
        thread::spawn(move ||{

            //eprintln!("\n (Thread report partito) \n");

            let mut f = File::create(file_name).expect("Errore scrittura file");
            let mut report_number:usize = 0;
            write!(f, "Viene generato un report ogn {} secondi", time_interval).expect("errore scrittura file");

            loop{
                report_number+=1;
                thread::sleep(Duration::from_secs(time_interval));
                report_writer(report_number, &mut f, data.clone());
                print!("\n\n - Report#{} disponibile\n >> ", report_number);
                stdout().flush().unwrap();
            }


        });
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
