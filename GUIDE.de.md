# Anleitung

> **Wichtig für Fehler-Reports:** Schalte unten auf der Seite den **Diagnose-Log** ein, *bevor* du dich mit dem Scooter verbindest. Nur dann wird der komplette Verbindungsaufbau mitgeschnitten - und genau diese Zeilen brauchen wir in einem [Ticket](https://github.com/Laufbursche42/Laufbursche42/issues), um ein Problem nachzuvollziehen.

## Was du brauchst
- Einen RCB E-Scooter (Tuya/Smart-Life-App `com.rcb.ytd`).
- Ein Handy oder einen Rechner mit **Chrome**, **Edge** oder auf iOS **Bluefy**. Safari und Firefox können kein Web Bluetooth.
- Zum Schreiben zusätzlich deinen Tuya-localKey und einen srand aus der Kopplung (siehe unten).

## Verbinden
1. Bluetooth am Gerät einschalten, den Scooter einschalten (wecken).
2. Auf **Verbinden** tippen und den Scooter in der Liste auswählen.
3. Taucht er nicht auf, setze den Haken bei **Alle Geräte zeigen** und verbinde erneut. Der echte Test ist das gefundene Tuya-GATT-Profil, nicht der angezeigte Name.
4. Nach dem Verbinden erscheinen die Karten für Live-Werte und Einstellungen.

## Schlüssel und Sitzung
Der Tuya-DP-Kanal ist verschlüsselt. Der Sitzungsschlüssel ist `secretKey5 = MD5(localKey + srand)`.
- Den **localKey** bekommst du aus deinem Tuya-Konto (zum Beispiel über die Tuya-IoT-Plattform). Er steht nicht im Bluetooth-Verkehr und wird nie von dieser Seite erzeugt.
- **srand** sind 6 Byte aus der Kopplungsantwort des Rollers.
- Beide Felder ausfüllen, dann zeigt die Seite den abgeleiteten Schlüssel an. Die Ableitung passiert rein lokal.
- Optional: Lade einen Bluetooth-Mitschnitt hoch. Die Seite durchsucht ihn lokal und zeigt srand- und dpId-Kandidaten als Vorschlag. Nichts wird hochgeladen und nichts ist bewiesen.

## Geräte-Schema
Die numerischen dpIds sind pro Produkt in der Tuya-Cloud definiert und stehen nicht im App-Paket. Trage im Schema zu jedem Code seine dpId ein, als JSON, zum Beispiel `{"headlight_switch":104,"boost":{"dpId":110,"type":"bool"}}`. Erst mit dpId und Sitzungsschlüssel lässt sich eine Zeile schreiben.

## Live-Werte lesen
Der Roller meldet Datenpunkte über den DP-Kanal. Eine Kachel zeigt einen Wert, sobald ein gemeldeter dpId zu einem Code aus deinem Schema passt. Ein Strich heißt nur, dass dieser Wert noch nicht kam. Ohne Sitzungsschlüssel bleiben verschlüsselte Frames unlesbar.

## Einstellungen schreiben
In der Karte **Einstellungen** stehen die vom App-Paket belegten Tuya-Steuer-Codes (Scheinwerfer, LED, Tempomat, Nullstart, Einheit, Auto-Entsperren, Bewegungsalarm, Suchen und Boost). Jede Zeile braucht ihre dpId aus dem Schema und einen gültigen Sitzungsschlüssel. Riskante Schreibvorgänge wie Boost oder Auto-Entsperren fragen vorher nach. Wichtig: Ein Echo im Log heißt nur, dass der Roller das Frame angenommen hat. Erst ein geänderter Live-Wert beweist die Wirkung.

## Erweiterte Einstellungen (Engine-Ebene)
Hier baust du ein DP-Frame von Hand aus dpId, Typ, Wert und Protokoll-Version. In der Vorschau wird nur gebaut und geloggt, scharf wird es verschlüsselt gesendet.

## Shortcuts
Kopiere den Link auf den Startbildschirm, dann öffnet ein Tipp die Seite und versucht zu verbinden. Auf iOS über Bluefy, und der Scooter muss vorher einmal normal verbunden gewesen sein.

## Wenn etwas nicht geht
- Kein Verbinden? Prüfe, dass der Browser Web Bluetooth kann, Bluetooth an ist und der Scooter wach ist. Mit **Alle Geräte zeigen** erneut versuchen.
- Zeile bleibt gesperrt? Dann fehlt die dpId im Schema oder der Sitzungsschlüssel (localKey und srand).
- Nichts passiert nach einem Befehl? Schau ins Log: steht dort "gesendet", wurde das Frame geschrieben, aber nur ein geänderter Live-Wert beweist die Wirkung.
- **Diagnose: alle Geräte auflisten** im Log-Bereich zeigt alle Bluetooth-Dienste eines Geräts, ohne etwas zu schreiben - hilfreich für Support.

## Mithelfen
Willst du herausfinden, ob und wie Tuning bei deinem Scooter geht? Teste dieses Tool an deinem eigenen Fahrzeug und öffne ein Ticket auf [GitHub](https://github.com/Laufbursche42/Laufbursche42/issues) - mit deinem Modell und was funktioniert hat (oder nicht). So finden wir gemeinsam heraus, was bei welchem Modell möglich ist.
