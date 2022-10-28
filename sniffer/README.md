# Sniffer Analyzer

Autori: Simone Bergadano, Davide Cosola, Alessio Brescia

Versione: 1.0

Il progetto mira a
costruire un'applicazione multipiattaforma in grado di
di intercettare il traffico in entrata e in uscita attraverso le
le interfacce di rete di un computer.

## Contenuto

- [Sniffer Analyzer](#sniffer-analyzer)
  - [Contenuto](#content)
  - [Funzionamento](#funzionamento)
  - [Help](#help)
  - [main.rs](#mainrs)
  - [mod.rs](#modrs)
  - [service_function.rs](#service_functionrs)
  - [analyzer_th.rs](#analyzer_thrs)
  - [report_th.rs](#report_thrs)
  - [command.rs](#commandrs)

## Funzionamento

**Windows**
1. Installare Npcap.
2. Scaricare l'SDK di Npcap.
3. Aggiungere la cartella /Lib o /Lib/x64 dell'SDK alla variabile d'ambiente LIB.

**MacOs**

Libpcap dovrebbe essere già installato su Mac OS X per impostazione predefinita.

Nota: Un timeout pari a zero può far sì che pcap::Capture::next si blocchi e non ritorni mai (perché aspetta che il timeout scada prima di tornare).
Questo problema può essere risolto utilizzando un timeout diverso da zero (come raccomanda il manuale di libpcap) e chiamando pcap::Capture::next in un ciclo.

**Linux**

Installare le librerie e i file di intestazione della libreria libpcap:
- Su Linux basato su Debian: installare libpcap-dev.
- Su Fedora Linux: installare libpcap-devel.

Nota: se non si esegue come root, è necessario impostare le capabilities come segue: sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin

## Help

**Utilizzo del programma:**

- Linux:
  > sudo ./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Windows:
  >./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >
- Mac:
  > ./sniffer < ADAPTER > < TIME_INTERVAL > < OUTPUT > < FILTER >

Nota: l'argomento filtro può essere omesso se non si desidera inserire alcun filtro

**Esempi:**

- > sudo ./sniffer 1 10 report.txt
- >./sniffer 1 5 report.txt
- >./sniffer 1 10 report2.txt "ip"
- >./sniffer 1 10 report2.txt "ip6"
- >./sniffer 1 10 report2.txt "arp"
- >./sniffer 1 10 report2.txt "ip host 192.168.1.1"
- >./sniffer 1 10 report2.txt "tcp src port 80"

**Argomenti:**

    < ADAPTER >          Inserisci l'indice dell'adapter da utilizzare
    < TIME_INTERVAL >    Inserisci ogni quanti secondi generare un report
    < OUTPUT >           Inserisci il nome del file di output
    < FILTER >           Inserisci un filtro per i pacchetti da analizzare secondo la Berkeley Packet Filter (BPF) syntax (link sotto)

<a href="https://biot.com/capstats/bpf.html" target="top">BPF syntax</a>

Nota: l'argomento filtro può essere omesso se non si desidera inserire alcun filtro


**Options:**

    -h, --help    Mostra l'help 
    -l  --list    Mostra la lista dei possibili adapter

## main.rs

Il main contiene:

- La gestione degli argomenti ricevuti da linea di comando.
- Un loop per permettere all'utente di controllare il packet analyzer

      I comandi utilizzabili dall'utente sono:
        - STOP per fermarlo
        - PAUSE per metterlo in pausa
        - RESUME per farlo ripartire
- Una chiamata alla funzione start_sniffing contenuta in mod.rs
  
## mod.rs

Nel file mod.rs abbiamo utilizzato la libreria pcap per implementare la raccolta dei pacchetti.

**Funzioni presenti:**

- > pub fn get_available_devices() -> Result< Vec< Device >, pcap::Error >

   La funzione ritorna il vettore di device da cui è possibile raccogliere pacchetti o un errore in caso l'operazione non vada a buon fine.

- > pub fn start_sniffing(dev: Device, file_name: String, time_interval: u64, verbose_mode: bool, filter: Option<String>) -> Result<SnifferHandler, pcap::Error>

   La funzione fa partire il processo di cattura ed analisi dei pacchetti. Al suo interno vengono creati 2 thread. Il primo legge i pacchetti e li elabora, il secondo invece genera i report.
La funzione ritorna una struct SnifferHandler attraverso la cui è possibile controllare il processo o un errore nel caso non si riesca ad avviare il processo.

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

- > pub fn report_job(data: &Arc<Mutex<Data>>, file_name: String, time_interval: u64, rx: Receiver<Command>, filter: Option<String>, dev_name: String)
  
    La funzione fa partire un loop in cui viene gestita un'eventuale pausa da parte dell'utente e chiama la funzione per la scrittura del report (report_writer).

- > fn pause_management(data: &Arc< Mutex< Data>>, rx: & Receiver< Command>)

    La funzione serve a mettere in pausa entrambi i thread di analisi e scrittura.

- > fn report_writer(report_number: usize, f: &mut File, data: Arc< Mutex< Data>>)

    La funzione legge la struct data e scrive il report su file.

## command.rs

Contiene gli enum e la struct per gestire lo stato ed i comandi per lo sniffer.

La struct SnifferHandler implementa i metodi:

- > pub fn new(tx_analyser: Sender< Command >, tx_report: Sender< Command >)->Self

    Il metodo new serve per creare la struct SnifferHandler.

- > pub fn pause(&mut self)

    Il metodo pause mette in pausa la stato dello SnifferHandler, oltre fermare l'analisi e la scrittura dei report.

- > pub fn resume(&mut self)

    Il metodo resume serve a mettere ad attivo lo stato dello SnifferHandler ed a far ripartire l'analisi e la scrittura dei report.

- > pub fn stop(&mut self)

    Il metodo serve a terminare definitivamente il processo di cattura.