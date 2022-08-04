use std::io::{stdin, stdout, Write};
use std::ops::Add;
//use pcap::{Device, Capture, Active};
use sniffer::{get_available_devices, open_device, start_sniffing};


fn main() {

    let mut n:usize;
    let time_interval:u64;

    let mut user_input = String::new();

    let devices = get_available_devices()
        .expect("E' stato riscontrato un errore durante l'acquisizione dei network adapter");


    println!("\n Sono disponibili {} network adapter: ", devices.len());

    let mut i = 0;
    for dev in &devices{ i+=1; println!("  {}) {}",i, dev.name); }

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
            //if time_interval>=100 {break;}
            break;
        }
        println!(" Valore inserito non valido");
    }

    // Scelta output file

    let output_file_name ;
    user_input.clear();
    print!("\n Scegliere il nome del file in cui salvare l'output\n  >> ");
    stdout().flush().unwrap();
    stdin().read_line(&mut user_input).unwrap();

    output_file_name = user_input.trim().to_string().add(".txt");
    println!("\n I report verranno salvati nel file {}", output_file_name);


    start_sniffing(cap, output_file_name, time_interval);



    //println!("\n-------------------------------------------------\n Sono in attesa di pacchetti...");

    loop{
        user_input.clear();
        print!("\n Il processo di sniffing è iniziato scrivi stop per fermarlo\n  >> ");
        stdout().flush().unwrap();
        stdin().read_line(&mut user_input).unwrap();

        if user_input.trim().eq("stop") { break; }
        println!(" Valore inserito non valido");
    }


    /*
    while let Ok(packet) = cap.next() {
        // Qui dovremo analizzare pacchetto per pacchetto per poi generare il report
        println!("\n - Ho ricevuto un pacchetto: {:?}", packet.header);
        let a  = packet.header.ts;
    }

     */



}
