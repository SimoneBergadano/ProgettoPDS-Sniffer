use std::io::{stdin, stdout, Write};
use std::ops::Add;
use sniffer::{Command, get_available_devices, open_device, start_sniffing};

// cd target/debug per posizionarsi nella cartella corretta
// sudo ./sniffer per avviare il programma

fn main() {

    let mut n: usize;
    let time_interval: u64;

    let mut user_input = String::new();

    let devices = get_available_devices()
        .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");


    println!("\n Sono disponibili {} network adapter: ", devices.len());

    // Stampo la lista dei network adapter
    devices.iter().enumerate().for_each(|x|println!("  {}) {}",x.0+1, x.1.name));

    // Scelta del network adapter
    loop{
        user_input.clear();
        print!("\n Scegli un adapter\n  >> ");
        stdout().flush().unwrap();
        stdin().read_line(&mut user_input).unwrap();

        // trim() toglie il \n dalla stringa letta
        let res = user_input.trim().parse::<usize>();

        if res.is_ok(){
            n = res.unwrap();
            if n>0 && n<=devices.len(){ break; }
        }
        println!(" Valore inserito non valido");
    }

    println!("\n Hai scelto {}\n", devices[n-1].name);

    // Apro il network adapter selezionato
    let cap = open_device(devices[n-1].clone(), true)
        .expect("\n Non è stato possibile aprire il socket di rete selezionato\n (Se stai usando linux devi avviare il programma come permessi di amministratore)\n\n");



    // Scelta del time-interval
    loop{
        user_input.clear();
        print!(" Scegliere ogni quanti secondi generare un report\n  >> ");
        stdout().flush().unwrap();
        stdin().read_line(&mut user_input).unwrap();

        let res = user_input.trim().parse::<u64>();

        if res.is_ok() {
            time_interval = res.unwrap();
            break;
        }
        println!(" Valore inserito non valido");
    }

    // Scelta output file

    let output_file_name: String ;
    user_input.clear();
    print!("\n Scegliere il nome del file in cui salvare l'output\n  >> ");
    stdout().flush().unwrap();
    stdin().read_line(&mut user_input).unwrap();

    output_file_name = user_input.trim().to_string().add(".txt");
    println!("\n I report verranno salvati nel file {}", output_file_name);


    let verbose_mode = true;

    let res = start_sniffing(cap, output_file_name, time_interval, verbose_mode);

    let sender = res.expect("Errore interno");

    println!("\n Il processo di sniffing è iniziato scrivi:
        - STOP per fermarlo
        - PAUSE per metterlo in pausa
        - RESUME per farlo ripartire\n");
    stdout().flush().unwrap();

    loop{
        user_input.clear();

        stdin().read_line(&mut user_input).unwrap();
        if user_input.trim().eq("STOP") { break; }
        else if user_input.trim().eq("PAUSE") { sender.send(Command::Pause).expect("errore interno"); }
        else if user_input.trim().eq("RESUME") { sender.send(Command::Resume).expect("errore interno"); }
        else { println!(" Valore inserito non valido"); }
        stdout().flush().unwrap();
    }



}
