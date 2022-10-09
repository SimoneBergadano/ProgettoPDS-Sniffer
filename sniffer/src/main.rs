mod sniffer_lib;

use std::env::args;
use std::io::{stdin, stdout, Write};
use sniffer_lib::{get_available_devices, start_sniffing};

use clap::Parser;

#[derive(Parser)]
struct Args {
    adapter: usize,
    time_interval: u64,
    output: String,
    filter: String,
}

fn main() {

    let help = "\nUtilizzo del programma:\n
   ./sniffer <numero adapter> <secondi ogni quanto generare il report> <nome del file per il report> <filtri>
   ./sniffer -l o ./sniffer --list per la lista numerata degli adapter

    se stai usando linux lancia il programma con sudo ./sniffer

    I filtri vanno inseriti secondo la Berkeley Packet Filter (BPF) syntax
    https://biot.com/capstats/bpf.html per saperne di più

    Alcuni esempi:
    ./sniffer 1 10 report.txt all
    ./sniffer 1 10 report2.txt \"ip\"
    ./sniffer 1 10 report2.txt \"ip6\"
    ./sniffer 1 10 report2.txt \"arp\"
    ./sniffer 1 10 report2.txt \"ip host 192.168.1.1\"
    ./sniffer 1 10 report2.txt \"tcp src port 80\"
    \n";

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

    println!("\nComandi ricevuti: \n - network adapter: {}\n - time_interval: {}\n - output file: {}\n - filter: {} \n",
             input.adapter, input.time_interval, input.output, input.filter);

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

    let filter: Option<String>;

    match input.filter.as_str() {
        "all" => filter = None,
        _ => filter = Some(input.filter),
    }

    let res = start_sniffing(device, input.output, input.time_interval, verbose_mode, filter);

    if res.is_err() {
        println!("E' stato riscontrato un errore: \"{}\" ", res.err().unwrap().to_string());
        //Se stai usando linux devi avviare il programma come permessi di amministrator
        if cfg!(unix) { println!("Reminder: Se stai usando linux devi avviare il programma come permessi di amministrator"); }
        return;
    }

    let mut sniffer_handler = res.unwrap();

    println!("\n Il processo di sniffing è iniziato scrivi:
        - STOP per fermarlo
        - PAUSE per metterlo in pausa
        - RESUME per farlo ripartire\n");
    stdout().flush().unwrap();

    let mut user_input = String::new();

    loop{
        user_input.clear();

        stdin().read_line(&mut user_input).unwrap();
        if user_input.trim().to_ascii_lowercase().eq("stop") { sniffer_handler.stop(); break; }
        else if user_input.trim().to_ascii_lowercase().eq("pause") { sniffer_handler.pause(); }
        else if user_input.trim().to_ascii_lowercase().eq("resume") { sniffer_handler.resume(); }
        else { println!(" Valore inserito non valido"); }
        stdout().flush().unwrap();
    }

}
