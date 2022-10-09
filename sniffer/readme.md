# Sniffer Analyzer

Authors: Simone Bergadano, Davide Cosola, Alessio Brescia

Version: 1.0

Il progetto mira a
costruire un'applicazione multipiattaforma in grado di
di intercettare il traffico in entrata e in uscita attraverso le
le interfacce di rete di un computer.

// forse meglio non farlo mezzo in inglese mezzo in italiano 😅

## Content

- [Sniffer Analyzer](#sniffer-analyzer)
  - [Content](#content)
  - [Help](#help)
  - [Main](#main)
  - [Lib](#lib)
  - [Moduli Lib](#moduli-lib)
  - [Analyzer th](#analyzer-th)
  - [Report th](#report-th)

## Funzionamento

**Windows**
1. Install Npcap.
2. Download the Npcap SDK.
3. Add the SDK's /Lib or /Lib/x64 folder to your LIB environment variable


**MacOs**

libpcap should be installed on Mac OS X by default.

Note: A timeout of zero may cause pcap::Capture::next to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling pcap::Capture::next in a loop.

**Linux**

Install the libraries and header files for the libpcap library. For example:

    On Debian based Linux: install libpcap-dev.
    On Fedora Linux: install libpcap-devel.

Note: If not running as root, you need to set capabilities like so: sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin

## Help

**Utilizzo del programma:**

- Linux:
  > sudo ./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Windows:
  > cargo run < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
  > 
  >./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Mac:
  > ./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
  > 
**Esempi:**

- > sudo ./sniffer 1 10 report.txt ip
- > cargo run 1 5 report.txt ip6
- >./sniffer 1 10 report.txt all
- >./sniffer 1 10 report2.txt "ip"
- >./sniffer 1 10 report2.txt "ip6"
- >./sniffer 1 10 report2.txt "arp"
- >./sniffer 1 10 report2.txt "ip host 192.168.1.1"
- >./sniffer 1 10 report2.txt "tcp src port 80"

//esempio su mac    ./sniffer 1 10 report.txt arp

**Args:**

    < ADAPTER >          Inserisci l'indice dell'adapter da utilizzare
    < TIME_INTERVAL >    Inserisci ogni quanti secondi generare un report
    < OUTPUT >           Inserisci il nome del file di output
    < FILTER >           Inserisci un filtro per i pacchetti da analizzare secondo la Berkeley Packet Filter (BPF) syntax

**Options:**

    -h, --help    Mostra l'help 
    -l  --list    Mostra la lista dei possibili adapter

## main.rs

Il main contiene:

- La gestione degli argomenti ricevuti da linea di comando.
- Un loop per permettere all'utente di controllare il packet analyzer
- Una chiamata alla funzione start_sniffing contenuta in Lib.rs
  
## mod.rs

Nel file lib abbiamo utilizzato la libreria pcap per implementare la raccolta dei pacchetti.

**Funzioni presenti:**

- > pub fn get_available_devices() -> Result< Vec< Device >, pcap::Error >

   La funzione ritorna il vettore di device da cui è possibile raccogliere pacchetti.

- > pub fn start_sniffing(dev: Device, file_name: String, time_interval: u64, verbose_mode: bool, filter: Filter) -> Result< Sender< Command >, pcap::Error>
  
   La funzione fa partire il processo di cattura ed analisi dei pacchetti. Al suo interno vengono creati 2 thread. Il primo legge i pacchetti e li elabora, il recondo invece genera i report.

## service_function.rs

Contiene funzioni di supporto/conversione per:

- Passare dal codice ICMP ad una stringa
- Passare da u8 a hex
- Passare dall'indirizzo mac ad una stinga

## analyzer_th.rs

Contiene le funzioni utilizzate dall'analyzer thread.

**Funzioni presenti:**

- > pub fn analyzer_job(mut cap: Capture< Active>, data: &Arc< Mutex< Data>>, verbose_mode: bool, filter: Filter)

    La funzione fa partire un loop in cui viene analizzato ogni pacchetto catturato (tramite la funzione packet_analyzer) ed, in caso di errore, stampa un'eventuale descrizione.

- > fn packet_analyzer(p: Packet, data: &Arc< Mutex< Data>>, filter: Filter)

    La funzione analizza il pacchetto e salva il risultato nella struct data (che sarà utilizzata dall'altro thread per generare il report).

## report_th.rs

Contiene le funzioni utilizzate dal report thread.

**Funzioni presenti:**

- > pub fn report_job(data: &Arc< Mutex< Data>>, file_name: String, time_interval: u64, rx: Receiver< Command>)
  
    La funzione fa partire un loop in cui viene gestita un'eventuale pausa da parte dell'utente e chiama la funzione per la scrittura del report (report_writer).

- > fn pause_management(data: &Arc< Mutex< Data>>, rx: & Receiver< Command>)

    La funzione serve a mettere in pausa entrambi i thread di analisi e scrittura.

- > fn report_writer(report_number: usize, f: &mut File, data: Arc< Mutex< Data>>)

    La funzione legge la struct data e scrive il report su file.

## command.rs

- > da scrivere