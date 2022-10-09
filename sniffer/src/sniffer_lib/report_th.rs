use std::fs::File;
use std::io::{stdout, Write};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;
use crate::sniffer_lib::{Data, L4Protocol};
use crate::sniffer_lib::command::Command;

// Legge la struct data e scrive il report su file
fn report_writer(report_number: usize, f: &mut File, data: Arc<Mutex<Data>>){

    let mut data = data.lock().unwrap();

    write!(&mut *f, "\n\n REPORT#{}:\n", report_number).expect("errore scrittura file");

    if !data.ipv4.is_empty(){
        write!(&mut *f, "\n\tIpv4: ({} pacchetti/o)", data.ipv4_count).expect("errore scrittura file");
        data.ipv4.keys().for_each(|k|{

            let first_occurrence= data.ipv4.get(k).unwrap().first_occurrence;
            let last_occurrence= data.ipv4.get(k).unwrap().last_occurrence;
            let byte= data.ipv4.get(k).unwrap().bytes_transmitted;
            let num= data.ipv4.get(k).unwrap().packets_number;

            match &k.2 {
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
                L4Protocol::Icmp(code) => {
                    write!(&mut *f, "\n
              -source: {}  dest: {}  trasported_protocol: {} ( {} )
               first_occurence: {}  last_occurence: {}
               byte_trasmitted: {}  packets_number: {},",
                           k.0, k.1, "ICMP", code, first_occurrence, last_occurrence, byte, num).expect("errore interno");
                }
                L4Protocol::Other(protocol_name) => {
                    write!(&mut *f, "\n
               -source: {}  dest: {}  trasported_protocol: {}
                first_occurence: {}  last_occurence: {}
                byte_trasmitted: {}  packets_number: {},",
                           k.0, k.1, protocol_name, first_occurrence, last_occurrence, byte, num).expect("errore interno");
                }
            }
        });
    }

    if !data.ipv6.is_empty(){
        write!(&mut *f, "\n\n\tIpV6: ({} pacchetti/o)", data.ipv6_count).expect("errore scrittura file");
        data.ipv6.keys().for_each(|k|{

            let first_occurrence= data.ipv6.get(k).unwrap().first_occurrence;
            let last_occurrence= data.ipv6.get(k).unwrap().last_occurrence;
            let byte= data.ipv6.get(k).unwrap().bytes_transmitted;
            let num= data.ipv6.get(k).unwrap().packets_number;

            match &k.2 {
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
                L4Protocol::Icmp(code) => {
                    write!(&mut *f, "\n
               -source: {}  dest: {}  trasported_protocol: {} ( {} )
                first_occurence: {}  last_occurence: {}
                byte_trasmitted: {}  packets_number: {},",
                           k.0, k.1, "ICMP", code, first_occurrence, last_occurrence, byte, num).expect("errore interno");
                }
                L4Protocol::Other(protocol_name) => {
                    write!(&mut *f, "\n\
               -source: {}  dest: {}  trasported_protocol: {}\
                first_occurence: {}  last_occurence: {}\
                byte_trasmitted: {}  packets_number: {},",
                           k.0, k.1, protocol_name, first_occurrence, last_occurrence, byte, num).expect("errore interno");
                }
            }
        });
    }

    if !data.arp.is_empty(){
        write!(&mut *f, "\n\n\tARP: ({} pacchetti/o)", data.arp_count).expect("errore scrittura file");
        data.arp.keys().for_each(|k|{

            let first_occurrence= data.arp.get(k).unwrap().first_occurrence;
            let last_occurrence= data.arp.get(k).unwrap().last_occurrence;
            let byte= data.arp.get(k).unwrap().bytes_transmitted;
            let num= data.arp.get(k).unwrap().packets_number;

            write!(&mut *f, "\n
               -source: {},  dest: {},  tipo: {}
                first_occurence: {},  last_occurence: {}
                byte_trasmitted: {},  packets_number: {},",
                   k.0, k.1, k.2, first_occurrence, last_occurrence, byte, num).expect("errore interno");
        });
    }

    data.ipv4.clear();
    data.ipv6.clear();
    data.arp.clear();

    data.ipv4_count = 0;
    data.ipv6_count = 0;
    data.arp_count = 0;

}

fn command_handler(rx: &Receiver<Command>, time_interval: u64,) -> bool{
    //println!("Il thread report controlla il canale");
    use Command::*;
    let res = rx.try_recv();
    if res.is_ok() {
        match res.unwrap(){
            Pause => {
                let res = rx.recv(); // bloccante
                match res.unwrap() {
                    Pause => { unreachable!("Ho ricevuto pause ma ero già andato in pausa"); }
                    Resume => { thread::sleep(Duration::from_secs(time_interval)); }
                    Stop => { println!("Thread report chiuso"); return true; }
                }
            }
            Resume => { unreachable!("Ho ricevuto resume senza essere prima andato in pausa");}
            Stop => { println!("Thread report chiuso"); return true; }
        }
    }
    stdout().flush().unwrap();
    return false; // false significa non terminare il thread
}

pub fn report_job(data: &Arc<Mutex<Data>>, file_name: String, time_interval: u64, rx: Receiver<Command>, filter: Option<String>){

    //println!("\n (Thread report partito) \n");

    let mut f = File::create(file_name).expect("Errore scrittura file");
    let mut report_number:usize = 0;

    write!(f, "Viene generato un report ogni {} secondi", time_interval).expect("errore scrittura file");

    if filter.is_some(){
        write!(f, "\nFiltro: \"{}\"", filter.unwrap()).expect("errore scrittura file");
    }

    loop{
        report_number+=1;
        thread::sleep(Duration::from_secs(time_interval));
        { // gestisco larrivo di comandi stop,pause e resume
            let stop = command_handler(&rx, time_interval);
            if stop { return; }
        }
        report_writer(report_number, &mut f, data.clone());
        println!("\n - Report#{} disponibile\n", report_number);
        stdout().flush().unwrap();
    }

}