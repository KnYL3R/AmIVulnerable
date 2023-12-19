# JSON-LD
offizielle Webseite: [json-ld.org](https://json-ld.org/)

## Kurzbeschreibung
JSON steht für "**J**ava**S**cript **O**bject **N**otation" und der Suffix LD für "**L**inked **D**ata"
Mit ihm soll es Webnutzern weltweit ermöglicht werden, standardisierte und maschienenlesbare Datenformate zu nutzen.
Während im context-Teil des JSON ein einzelner Link sich befindet, kann in der dort aufgerufenen Beschreibung eine vielzahl weiterführender Links und somit weiterer verlinkter Daten stehen. <sup>[Linked Data Abschnitt](https://json-ld.org/)</sup>

## Funktionsweise

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

## Aufgetretene Probleme

## Lösung der Probleme

## Sonstiges