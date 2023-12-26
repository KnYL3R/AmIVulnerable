# JSON-LD
offizielle Webseite: [json-ld.org](https://json-ld.org/)

## Kurzbeschreibung
JSON steht für "**J**ava**S**cript **O**bject **N**otation" und der Suffix LD für "**L**inked **D**ata"
Mit ihm soll es Webnutzern weltweit ermöglicht werden, standardisierte und maschienenlesbare Datenformate zu nutzen.
Während im context-Teil des JSON ein einzelner Link sich befindet, kann in der dort aufgerufenen Beschreibung eine vielzahl weiterführender Links und somit weiterer verlinkter Daten stehen. <sup>[Linked Data Abschnitt](https://json-ld.org/)</sup>

## Funktionsweise
JSON-LD (JavaScript Object Notation for Linked Data) erweitert JSON, um strukturierte und verknüpfte Daten im Web zu repräsentieren. Die Schlüsselprinzipien sind:

1. JSON-Struktur: Verwendung der JSON-Syntax für leicht lesbare Daten.
2. Verknüpfte Daten: Nutzung von URIs, um Beziehungen zwischen Datenpunkten herzustellen.
3. Kontext: Definition von Bedeutungen durch den Kontext, der angibt, wie Schlüssel interpretiert werden sollen.
4. Typisierung: Möglichkeit, Datenpunkte zu typisieren, um die Art der Daten zu kennzeichnen.
5. HTML-Einbettung: Integration in HTML-Dokumente für maschinenlesbare Informationen, besonders relevant für SEO.

JSON-LD erleichtert die Interoperabilität von strukturierten Daten im Web.

## Umsetzung
### Webseite-Ansicht
Um die API-Rückgaben verständlich und beschreibend zu gestalten, wurde ein weiterer *Controller* hinzugefügt.
Dieser MVC<sup>Model-View-Controller</sup>-Controller gibt über die Route "views/json-ld" eine Webseite zurück, deren Inhalt die Beschreibung des JSON darstellt, welche die Abfragerouten zurückgeben werden.

<label style="color: red">
    <ul>
        <li>
            HTML aktuell noch leer, weil Endpunkte nicht genau definiert.
        </li>
        <li>
            Name der HTML vllt ebenfalls noch anzupassen.
        </li>
        <li>
            Auch die Route ist noch nicht final, falls weitere Definitionen eingebunden werden sollten später, sind diese anzupassen damit der Grundweg "views/json-ld" als Hauptteil identisch bleibt und dort dann eine Subroute definiert wird, wie z.B. "/cve" für die CVE-Datendefinition - "/packages" für die Beschreibung, welche Pakte problematisch sind mit dem Indikator dazu etc.
        </li>
    </ul>
</label>

### JSON-Context
Im Allgemeinen bezieht sich der "@context"-Schlüssel in JSON-LD auf die Definition der Bedeutung oder Semantik der verwendeten Begriffe (Schlüssel) in einem JSON-LD-Dokument. Er spielt eine zentrale Rolle bei der Interpretation der Daten, indem er angibt, wie die verschiedenen Schlüssel und Werte zu verstehen sind.

Der @context kann in unterschiedlichen Formen angegeben werden:

1. IRI (Internationalized Resource Identifier): Eine Zeichenfolge, die auf eine externe Ressource verweist, die die Bedeutung der verwendeten Begriffe definiert. Zum Beispiel "@context": "http://schema.org/", wobei Schema.org ein gemeinsames Vokabular für strukturierte Daten ist.
2. Objekt: Ein eingebettetes JSON-Objekt, das die Bedeutung der Schlüssel im aktuellen Dokument angibt. 

Der "@context" ermöglicht also eine klare Definition der Semantik und erleichtert die interoperable Verwendung von strukturierten Daten im Web, da er sicherstellt, dass verschiedene Systeme und Anwendungen ein gemeinsames Verständnis der Daten haben.

## Aufgetretene Probleme
<ol>
    <li>
        Die Beschreibung des HTML-Dokuments, welches angezeigt werden soll, muss als String zurückgegeben werden von dem Endpunkt.
        Für eine volle Beschreibung ist dies jedoch ein sehr langer String, welches die Controller-Datei stark aufbläht.
    </li>
</ol>

## Lösung der Probleme
Zu den Punkten oben hier die Lösungen mit den selben Nummern:
<ol>
    <li>
        Der Inhalt wurde in eine eigene html-Datei ausgelagert und dann über das Dateisystem geladen - System.IO.File.
        Somit wird die Controller-Beschreibung schlanker und eine bessere Wartbarkeit gewährleistet.
    </li>
</ol>

## Sonstiges