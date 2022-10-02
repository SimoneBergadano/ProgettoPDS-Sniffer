# Sniffer Analyzer

Authors: Simone Bergadano, Davide Cosola, Alessio Brescia

Version: 1.0

The project aims at
building a multiplatform application capable
of intercepting incoming and outgoing traffic through
the network interfaces of a computer.

## Content

- [Sniffer Analyzer](#sniffer-analyzer)
  - [Content](#content)
  - [Help](#help)
  - [Main](#main)
  - [Lib](#lib)
  - [Moduli Lib](#moduli-lib)
  - [Analyzer th](#analyzer-th)
  - [Report th](#report-th)

## Help

**Utilizzo del programma:**

- Linux:
  > sudo ./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Windows:
  > cargo run < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Mac:

**Esempi:**

- > sudo ./sniffer 1 10 report.txt ipv4
- > cargo run 1 5 report.txt ipv6

//esempio su mac    ./sniffer 1 10 report.txt arp

**Args:**

    < ADAPTER >          Inserisci l'indice dell'adapter da utilizzare
    < TIME_INTERVAL >    Inserisci ogni quanti secondi generare un report
    < OUTPUT >           Inserisci il nome del file di output
    < FILTER >           Inserisci un filtro per i pacchetti da analizzare: <all><ipv4><ipv6><arp>

**Options:**

    -h, --help    Mostra l'help 
    -l  --list    Mostra la lista dei possibili adapter

## Main

Il main contiene:

- La gestione degli argomenti ricevuti da linea di comando.
- Un loop per permettere all'utente di controllare il packet analyzer
- Una chiamata alla funzione start_sniffing contenuta in Lib.rs
  
## Lib

Nel file lib abbiamo utilizzato la libreria pcap per implementare la raccolta dei pacchetti.

**Funzioni presenti:**

- > pub fn get_available_devices() -> Result< Vec< Device >, pcap::Error >

   La funzione ritorna il vettore di device da cui è possibile raccogliere pacchetti.

- > pub fn start_sniffing(dev: Device, file_name: String, time_interval: u64, verbose_mode: bool, filter: Filter) -> Result< Sender< Command >, pcap::Error>
  
   La funzione fa partire il processo di cattura ed analisi dei pacchetti. Al suo interno vengono creati 2 thread. Il primo legge i pacchetti e li elabora, il recondo invece genera i report.

## Moduli Lib

Contiene funzioni di supporto/conversione per:

- Passare dal codice ICMP ad una stringa
- Passare da u8 a hex
- Passare dall'indirizzo mac ad una stinga

## Analyzer th

Contiene le funzioni utilizzate dall'analyzer thread.

**Funzioni presenti:**

- > pub fn analyzer_job(mut cap: Capture< Active>, data: &Arc< Mutex< Data>>, verbose_mode: bool, filter: Filter)

    La funzione fa partire un loop in cui viene analizzato ogni pacchetto catturato (tramite la funzione packet_analyzer) ed, in caso di errore, stampa un'eventuale descrizione.

- > fn packet_analyzer(p: Packet, data: &Arc< Mutex< Data>>, filter: Filter)

    La funzione analizza il pacchetto e salva il risultato nella struct data (che sarà utilizzata dall'altro thread per generare il report).

## Report th

Contiene le funzioni utilizzate dal report thread.

**Funzioni presenti:**

- > pub fn report_job(data: &Arc< Mutex< Data>>, file_name: String, time_interval: u64, rx: Receiver< Command>)
  
    La funzione fa partire un loop in cui viene gestita un'eventuale pausa da parte dell'utente e chiama la funzione per la scrittura del report (report_writer).

- > fn pause_management(data: &Arc< Mutex< Data>>, rx: & Receiver< Command>)

    La funzione serve a mettere in pausa entrambi i thread di analisi e scrittura.

- > fn report_writer(report_number: usize, f: &mut File, data: Arc< Mutex< Data>>)

    La funzione legge la struct data e scrive il report su file.
