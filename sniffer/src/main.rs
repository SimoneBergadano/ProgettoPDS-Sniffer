use std::env::args;
use std::io::{stdin, stdout, Write};
use sniffer::{Command, get_available_devices, open_device, start_sniffing};
use clap::Parser;
use pcap::Device;

// cd target/debug per posizionarsi nella cartella corretta
// sudo ./sniffer per avviare il programma

// sudo ./sniffer default 10 report.txt


#[derive(Parser)]
struct Args {
    adapter: String,
    time_interval: u64,
    output: String,
}

fn main() {

    let args: Vec<String> = args().skip(1).collect();

    if args[0].to_ascii_lowercase().eq("-list"){
        let devices = get_available_devices()
            .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");
        println!(" Sono disponibili {} network adapter: ", devices.len());
        devices.iter().enumerate().for_each(|x|println!("  {}) {}",x.0+1, x.1.name));
        return;
    }

    if args[0].to_ascii_lowercase().eq("-help"){
        println!("Scrivere l'help");
    }

    if args.len() < 3 { println!("prova -help per info su come utilizzare il programma"); }

    let input: Args = Args::parse();

    println!("comandi ricevuti: \n network adapter: {}\n time_interval: {}\n output file: {}", input.adapter, input.time_interval, input.output);

    // Gestire errori

    let device;
    let adapter = input.adapter.to_ascii_lowercase();
    let mut n = 0;

    if adapter.eq("default"){ device = Device::lookup().unwrap().unwrap(); } // ???
    else{
        let devices = get_available_devices()
            .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");
        devices.iter().enumerate().for_each(|(i, dev)|{
            if dev.name.eq(adapter.as_str()){ n = i+1; }
        });
        if n == 0 {
            println!("L'adapter scelto ({}) non è stato trovato\n -list per la lista degli adapter disponibili", input.adapter);
            return;
        }
        device = devices[n-1].clone();
    }

    let cap = open_device(device, true)
        .expect("\n Non è stato possibile aprire il socket di rete selezionato\
            (Se stai usando linux devi avviare il programma come permessi di amministratore)\n");


    let verbose_mode = true;

    let res = start_sniffing(cap, input.output, input.time_interval, verbose_mode);

    let sender = res.expect("Errore interno");

    println!("\n Il processo di sniffing è iniziato scrivi:
        - STOP per fermarlo
        - PAUSE per metterlo in pausa
        - RESUME per farlo ripartire\n");
    stdout().flush().unwrap();

    let mut user_input= String::new();

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
