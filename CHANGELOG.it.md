# Note di versione

## [1.5.3] - 2026-11-27

### Correzioni

- Il file estratto viene scritto per intero o per niente: prima con un
  nome provvisorio accanto alla destinazione, poi messo al suo posto.
  Un'estrazione interrotta a metà (disco pieno, programma chiuso) non
  lascia più un file troncato con il nome del documento, e un file con
  quel nome comparso nel frattempo non viene sovrascritto.

### Modifiche

- L'archivio dei sorgenti corrispondenti, offerto con ogni versione, ora
  viene composto e firmato dalla compilazione automatica, anche per
  Windows.

## [1.5.2] - 2026-11-18

### Modifiche

- Su Windows le finestre secondarie usano la barra del titolo di sistema.
- La nuova finestra di aggiornamento mostra le novità in italiano quando l'app è impostata in italiano.
- Preferenze e Firme usano la stessa impaginazione e le stesse spaziature delle altre finestre.
- I pacchetti includono le licenze delle librerie integrate. Nella pagina della versione, accanto ai pacchetti, sono disponibili i sorgenti corrispondenti.
- L'installer e il pacchetto portabile per Windows occupano meno spazio.

## [1.5.1] - 2026-11-17

### Modifiche

- Nuova icona coordinata con le altre app di Daniel. Il sigillo rosso con
  due nastri su fondo blu ha un disegno specifico per la barra delle
  applicazioni di Windows, alle dimensioni da 16 a 24 pixel.
- Tutte le dimensioni dell'icona sono generate dal disegno SVG con
  `tools/make_icon.py`.

## [1.5.0] - 2026-11-16

### Modifiche

- Da questa versione P7M Extractor è distribuito con licenza GPL-3.0 o
  successiva. Le versioni fino alla 1.4.0 mantengono la licenza MIT.
  Ogni pacchetto include il testo della licenza. I pacchetti Windows
  includono anche le licenze e gli indirizzi dei sorgenti delle librerie
  MSYS2 che contengono.
- Su Windows la ricerca degli aggiornamenti avviene all'avvio e al
  ritorno dalla barra delle applicazioni, al massimo ogni quattro ore.
  Il primo avvio dopo l'aggiornamento esegue un nuovo controllo.
- Da Informazioni si può copiare o salvare un rapporto con versione,
  sistema, cartelle, impostazioni e file degli errori. Il rapporto
  esclude i documenti aperti.
- I messaggi di aggiornamento indicano GitHub come origine della risposta
  e il progetto come firmatario atteso dell'installer.

### Correzioni

- Gli errori della finestra vengono conservati in `errors.log`, con
  rotazione oltre 1 MB, anche quando si avvia il programma da Esplora file
  o dal desktop.
- Il salvataggio di `settings.ini` evita di lasciare il file parziale e
  riprova se Windows blocca temporaneamente la sostituzione.
