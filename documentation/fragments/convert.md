# Umwandeln der Github-JSON Dateien zu LiteDB

## Vorgehen
Zunächst wird anhand der Ordnerstruktur eine Liste erstellt, die alle Jahre aufgrund der vorhandenen Ordner aus dem Git-Repo extrahiert.
Mittels dieser Liste kann anschließen die Sortierung der JSON-Dateien erfolgen.

Vor dem Konvertieren ist es erforderlich eine Liste der gesamten verfügbaren JSON-Dateien zu erstellen.
Da aktuell noch Dateien in der Liste vorhanden sind, die nicht zwingend zur CVE-Liste gehören, muss diese noch davon gesäubert werden.
Um dies zu vollziehen, wird mittels Regex-Match auf die Dateinamenstruktur "CVE-[-\S]+.json" geprüft.
Dieser besagt, dass die Datei mit "CVE-" beginnen muss und nach möglichen weiteren Zahlen und "-" auf ".json" zu enden hat.

Nachdem diese gereinigte Liste vorhanden ist, kann die Konvertierung beginnen.

Dazu werden alle Einträge in der Liste nach Funktionsaufruf erneut auf ihr Datum geprüft und somit zu einer Jahres-Datenbank zugeordnet.
Dabei ist wichtig zu erwähnen, dass der absolute Pfad verwendet wird und somit der Speicherort zu der JSON-Datei auf seine Zuordnung verwendet wird.

Wenn ein entsprechendes Jahr erfolgreich ermittelt wurde, ist wird der Inhalt der JSON-Datei als nächstes per JsonConvert.Deserialize von Newtonsoft in ein Objekt zur Speicherung in die Datenbank umgewandelt.
Nach der Speicherung folgt das nächste Element, bis alle fertig sind.

## Grundlage der Jahresdatenbanken
<p style="color: red">noch zu erledigen</p>

## Fragen zur Leistung

### Zeit der Konvertierung
Ein kompletter Vorgang des Umwandelns der JSON-Dateien zu den LiteDB's dauert ca 1h auf einem 3,6GHz intel Prozessor.

### Dauer der Abfrage auf den LiteDB-Dateien
-- erst möglich wenn Funktion implementiert --

### Dauer der Abfrage auf den JSON Dateien
-- erst möglich wenn Funktion implementiert --

### Conclusio
-- erst nach den beiden vorherigen Kapiteln erstellbar --
