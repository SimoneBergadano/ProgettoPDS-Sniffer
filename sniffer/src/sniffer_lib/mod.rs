mod analyzer_th;
mod report_th;
mod command;
mod service_functions;

use analyzer_th::analyzer_job;
use report_th::report_job;
use command::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;
use pcap::{Capture, Device};

struct Value{
    first_occurrence: i64,
    last_occurrence: i64,
    packets_number: usize,
    bytes_transmitted: i64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum L4Protocol{
    Tcp(u16, u16),
    Udp(u16, u16),
    Icmp(String), // Nella stringa di Icmp scrivo il tipo di Icmp
    Other(String), // Specifico quale pacchetto nella stringa
}

pub struct Data{
    ipv4: HashMap<(Ipv4Addr, Ipv4Addr, L4Protocol), Value>,
    ipv6: HashMap<(Ipv6Addr, Ipv6Addr, L4Protocol), Value>,
    arp: HashMap<(String, String, String), Value>,
    ipv4_count: usize,
    ipv6_count: usize,
    arp_count: usize,
}

//ottengo la lista dei network adapter
pub fn get_available_devices() -> Result<Vec<Device>, pcap::Error>{
    let res = Device::list();
    if res.is_err() { eprintln!("E' stato riscontrato un errore nel recuperare la lista dei network adapter"); }
    res
}


// funzione che fa partire il processo di cattura e analisi dei pacchetti
pub fn start_sniffing(dev: Device, file_name: String, time_interval: u64, verbose_mode: bool, filter: Option<String>) -> Result<SnifferHandler, pcap::Error>{

    // Utilizzeremo 2 thread:
    // Il thread1 legge i pacchetti e li elabora
    // Il thread2 li riceve dal thread1 e genera il report

    let data = Arc::new(Mutex::new(Data{
        ipv4: HashMap::new(),
        ipv6: HashMap::new(),
        arp: HashMap::new(),
        ipv4_count: 0,
        ipv6_count: 0,
        arp_count: 0
    }));

    let device_name = dev.name.clone();

    let cap_res = Capture::from_device(dev).unwrap()
        .promisc(true)
        .snaplen(5000) // maximum length of a packet captured into the buffer
        .open();

    if cap_res.is_err() {
        eprintln!("Non è stato possibile aprire il socket di rete selezionato ( {} )", device_name);
        let e = cap_res.err().unwrap();
        eprintln!("Errore: {:?}", e);
        return Err(e);
    }

    println!("Ho aperto {} con successo", device_name);

    let mut cap = cap_res.unwrap();

    if filter.is_some(){
        // http://biot.com/capstats/bpf.html
        let f = filter.clone();
        let res = cap.filter(f.unwrap().as_str(), false);

        if res.is_err(){
            println!("Il filtro fornito è risultato errato");
            return Err(res.err().unwrap());
        }
    }


    // Serve per Stoppare/mettere in pausa il processo
    let (tx_analyser, rx_analyser) = channel::<Command>();

    // thread raccoglitore e analizzatore di pacchetti
    {

        let data = Arc::clone(&data);

        let analyser_thread = thread::Builder::new()
            .name("AnalyserThread".into());

        analyser_thread.spawn(move ||analyzer_job(cap, &data, rx_analyser, verbose_mode))
            .expect("Non sono riuscito a lanciare il thread analizzatore");
    }

    // Serve per Stoppare/mettere in pausa il processo
    let (tx_report, rx_report) = channel::<Command>();

    // thread che andrà a creare il report
    {
        let data = Arc::clone(&data);

        let report_thread = thread::Builder::new()
            .name("ReportThread".into());

        report_thread.spawn(move ||report_job(&data, file_name, time_interval, rx_report, filter, device_name))
            .expect("Non sono riuscito a lanciare il thread del report");
    }

    return Ok(SnifferHandler::new(tx_analyser, tx_report));

}