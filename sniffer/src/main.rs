use std::env::args;
use std::io::{stdin, stdout, Write};
use sniffer::{Command, Filter, get_available_devices, start_sniffing};
use clap::Parser;

#[derive(Parser)]
struct Args {
    adapter: usize,
    time_interval: u64,
    output: String,
    filter: String
}

fn main() {

    let help = "\nUtilizzo del programma:\n
   ./sniffer <nome adapter> <secondi ogni quanto generare il report> <nome del file per il report>
   ./sniffer -l o ./sniffer --list per la lista degli adapter
    DEFAULT per scegliere l'interfaccia di default
    se stai usando linux lancia il programma con sudo ./sniffer

    ./sniffer 1 10 report.txt ipv4
    ./sniffer 1 10 report.txt ipv6
    ./sniffer 1 10 report.txt arp
    ./sniffer 1 10 report.txt all\n";

    let args: Vec<String> = args().skip(1).collect();

    if args.len() == 0 {
        println!("\n prova --help per info su come utilizzare il programma");
        return;
    }

    if args[0].to_ascii_lowercase().eq("--list") || args[0].to_ascii_lowercase().eq("-l"){
        let devices = get_available_devices()
            .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");
        println!(" Sono disponibili {} network adapter: ", devices.len());
        devices.iter().enumerate().for_each(|x|println!("  {}) {}",x.0+1, x.1.name));
        return;
    }

    if args[0].to_ascii_lowercase().eq("--help"){
        println!("{}", help);
        return;
    }

    if args.len() < 4 {
        println!("prova --help per info su come utilizzare il programma");
        return;
    }

    let input: Args = Args::parse();

    println!("comandi ricevuti: \n network adapter: {}\n time_interval: {}\n output file: {}\n filter: {}", input.adapter, input.time_interval, input.output, input.filter);

    // Gestire errori

    let device;
    let adapter = input.adapter;

    let devices = get_available_devices()
        .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");
    if adapter < 1 || adapter > devices.len() {
        println!("L'adapter scelto ({}) non è stato trovato\n --list per la lista degli adapter disponibili", input.adapter);
            return;
    }
    device = devices[adapter-1].clone();

    let verbose_mode = false; // se messa a true stampa tutti gli errori


    let filter = match input.filter.to_ascii_lowercase().as_str(){
        "all" => Filter::All,
        "ipv4" => Filter::IpV4Only,
        "ipv6" => Filter::IpV6Only,
        "arp" => Filter::ArpOnly,
        _ => Filter::All
    };

    let res = start_sniffing(device, input.output, input.time_interval, verbose_mode, filter);

    if res.is_err() {
        //Se stai usando linux devi avviare il programma come permessi di amministrator
        if cfg!(unix) { println!("Se stai usando linux devi avviare il programma come permessi di amministrator"); }
        return;
    }

    let sender = res.unwrap();

    match filter{
        Filter::IpV4Only => { println!("\n Nel report verranno mostrati solo i pacchetti IpV4"); }
        Filter::IpV6Only => { println!("\n Nel report verranno mostrati solo i pacchetti IpV6"); }
        Filter::ArpOnly => { println!("\n Nel report verranno mostrati solo i pacchetti ARP"); }
        Filter::All => {}
    }

    println!("\n Il processo di sniffing è iniziato scrivi:
        - STOP per fermarlo
        - PAUSE per metterlo in pausa
        - RESUME per farlo ripartire\n");
    stdout().flush().unwrap();

    let mut user_input = String::new();

    loop{
        user_input.clear();

        stdin().read_line(&mut user_input).unwrap();
        if user_input.trim().to_ascii_lowercase().eq("stop") { break; }
        else if user_input.trim().to_ascii_lowercase().eq("pause") { sender.send(Command::Pause).expect("errore interno"); }
        else if user_input.trim().to_ascii_lowercase().eq("resume") { sender.send(Command::Resume).expect("errore interno"); }
        else { println!(" Valore inserito non valido"); }
        stdout().flush().unwrap();
    }



}
