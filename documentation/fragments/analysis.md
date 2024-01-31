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

```log
2024-01-24 18:50:37.698 +01:00 [INF] LiteDB completed in 12977.4 ms
2024-01-24 18:51:27.297 +01:00 [INF] LiteDB completed in 6495.3 ms
2024-01-24 18:51:34.629 +01:00 [INF] LiteDB completed in 6246.0 ms
2024-01-24 18:51:41.629 +01:00 [INF] LiteDB completed in 6307.4 ms
2024-01-24 18:52:03.326 +01:00 [INF] LiteDB completed in 6199.2 ms
2024-01-24 18:52:11.007 +01:00 [INF] Crowd completed in 6300.2 ms
2024-01-24 18:52:20.006 +01:00 [INF] Crowd completed in 6318.8 ms
2024-01-24 18:52:35.177 +01:00 [INF] Crowd completed in 6280.9 ms
2024-01-24 18:52:41.926 +01:00 [INF] Crowd completed in 6250.5 ms
2024-01-24 18:52:48.771 +01:00 [INF] Crowd completed in 6287.2 ms
2024-01-24 18:53:00.968 +01:00 [INF] LiteDb completed in 6364.8 ms (Fehler)
2024-01-24 18:53:07.971 +01:00 [INF] LiteDB completed in 6155.5 ms
```

## JSON-Dateien

```log
2024-01-24 19:08:18.676 +01:00 [INF] Package "LiteDB" completed in 853896.3 ms
```
