# Analyze der CVE Daten
Grundlegend muss zur Analyse ein vollständiger Clone des CVE-Repo vorliegen, und oder ein Satz konvertierter Jahres-Datenbanken.

## Datenbank (LiteDB)
Die Analyse auf den Jahresdatenbanken erfolgt über die Standardfunktionen von LiteDB.
Dabei wird jedoch zur Analyse nicht die gesamte Datenbank als ein Satz in den Arbeitsspeicher geladen, sondern über einen Enumerator über die einzelnen Einträge iteriert.
Die Abfrage, ob das zu analysierende Paket enthalten ist wird dabei über die Abfrage der: 
```csharp
item.containers.cna.affected.Any(y => y.product.Equals(designation))
```
im Container-CNA-Affected-Product Partition des Eintrages analysiert.

Zur Leistung ergaben sich dabei folgende Werte:

<label style="color: red; background: yellow">Daten messen und einfügen!!!</label>

## JSON-Dateien
