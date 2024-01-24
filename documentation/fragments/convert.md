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
Sobald ein Update der Datenbank erfolgen soll, ist es so einfacher, sowohl neue Daten einzufügen, als auch alte Daten zu validieren oder zu ersetzten.
Sollte es beispielsweise notwendig sein, die Daten des Jahres 2012 zu erneuern, so muss lediglich diese eine Datenbank angepasst werden.

Ebenso ist der unwahrscheinlich, aber nicht ausgeschlossene somit ein Ausfall einer Datei nicht so dramatisch, da nur ein Jahr neu erstellt werden muss und nicht alle gesamt, was weitaus länger dauert.

## Fragen zur Leistung

### Zeit der Konvertierung
Ein kompletter Vorgang des Umwandelns der JSON-Dateien zu den LiteDB's dauert ca 1h auf einem 3,2GHz intel Prozessor.
Auf einem 2,1GHz intel Prozessor betrag die Dauer ca 1h 40min.

Die Angaben betreffen die Grundtaktrate.

### Statistik Dauer
Es wurden 2 Szenarien untersucht.
1. Das mehrfache Konvertieren der Daten bei laufender API
2. Das mehrfache Konvertieren der Daten und jeweils neugestarteter API.

Zu 1. ist zu sagen, daß die Zeit sukzessive abnahm. Dies wird daran liegen, daß im RAM der Anwendung noch Teile der zu konvertierenden Daten vorhanden waren und somit der Prozess sich beschleunigte.
Ein Ansprechen des Garbage Collectors lieferte keine Änderung.

Zu 2. ist zu erwähnen, daß die abgehaltenen 5 Messungen getätigt wurden, um mit einem Mittelwert arbeiten zu können, der ein besseren Eindruck liefert.

Die Ergebnisse der Messungen befinden sich in einer Log-Datei (selbes Verzeichnis wie die Fragments).

Hier sind die Ergebnisse:
```log
2024-01-23 10:45:45.426 +01:00 [INF] Konvertieren der Datenbank completed in 3527225.2 ms (1. Start)
2024-01-23 11:53:15.037 +01:00 [INF] Konvertieren der Datenbank completed in 2955200.9 ms (1. Start)
2024-01-23 12:49:05.159 +01:00 [INF] Konvertieren der Datenbank completed in 2842891.2 ms (1. Start)
2024-01-23 13:36:43.036 +01:00 [INF] Konvertieren der Datenbank completed in 2753230.7 ms (1. Start)
2024-01-23 14:24:01.824 +01:00 [INF] Konvertieren der Datenbank completed in 2418296.2 ms (1. Start)
2024-01-23 15:41:27.854 +01:00 [INF] Konvertieren der Datenbank completed in 3654741.8 ms (2. Start)
2024-01-23 18:27:49.178 +01:00 [INF] Konvertieren der Datenbank completed in 2902944.9 ms (3. Start)
2024-01-24 12:10:04.811 +01:00 [INF] Konvertieren der Datenbank completed in 3866013.7 ms (4. Start)
2024-01-24 13:39:15.699 +01:00 [INF] Konvertieren der Datenbank completed in 2803370.4 ms (5. Start)
```

### Dauer der Abfrage auf den LiteDB-Dateien
-- erst möglich wenn Funktion implementiert -- <br/>
-- siehe analysis.md --

### Dauer der Abfrage auf den JSON Dateien
-- erst möglich wenn Funktion implementiert -- <br/>
-- siehe analysis.md --

### Conclusio
-- erst nach den beiden vorherigen Kapiteln erstellbar --
