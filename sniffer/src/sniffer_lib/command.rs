use std::sync::mpsc::Sender;

#[derive(PartialEq)]
pub enum Command{
    Pause,
    Resume,
    Stop,
}

#[derive(PartialEq)]
enum State{
    Active,
    Paused,
    Stopped
}

pub struct SnifferHandler{
    state: State,
    tx_analyser: Sender<Command>,
    tx_report: Sender<Command>,
}

impl SnifferHandler{
    pub fn new(tx_analyser: Sender<Command>, tx_report: Sender<Command>)->Self{
        SnifferHandler{
            state: State::Active,
            tx_analyser,
            tx_report
        }
    }
    pub fn pause(&mut self){
        match self.state{
            State::Active => {
                self.tx_analyser.send(Command::Pause).expect("Errore interno");
                self.tx_report.send(Command::Pause).expect("Errore interno");
                println!("Il processo di cattura è in pausa");
                self.state = State::Paused;
            }
            State::Paused => { eprintln!("Questo processo di sniffing è già in pausa"); }
            State::Stopped => { eprintln!("Questo processo di sniffing è stato stoppato non è possibile riattivarlo"); }
        }
    }
    pub fn resume(&mut self){
        match self.state{
            State::Active => { eprintln!("Questo processo di sniffing è già attivo"); }
            State::Paused => {
                self.tx_analyser.send(Command::Resume).expect("Errore interno");
                self.tx_report.send(Command::Resume).expect("Errore interno");
                self.state = State::Active;
                println!("Il processo di cattura è di nuovo attivo");
            }
            State::Stopped => { eprintln!("Questo processo di sniffing è stato stoppato non è possibile riattivarlo"); }
        }
    }
    pub fn stop(&mut self){
        if self.state != State::Stopped {
            self.tx_analyser.send(Command::Stop).expect("Errore interno");
            self.tx_report.send(Command::Stop).expect("Errore interno");
            self.state = State::Stopped;
            println!("Il processo di cattura è stato stoppato definitivamente");
        }
        else{ eprintln!("Questo processo di sniffing è già stato stoppato"); }
    }
}