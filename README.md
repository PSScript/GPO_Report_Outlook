# Outlook GPO & Registry Audit — Pre-Migration Assessment

[English](README.md) | **Deutsch**

PowerShell-basiertes Scanner- und Referenz-Toolkit zur Identifikation von Outlook/Exchange-GPO-Einstellungen, Registry-Altlasten und Migrationsblockern vor Exchange Online (M365) Migrationen.

## Problemstellung

In gewachsenen Enterprise-Umgebungen sammeln sich über Jahre Outlook-GPO-Richtlinien, direkte Registry-Eingriffe und Überreste aus Office 2010/2013 an. Bei Exchange-Migrationen verursachen diese versteckten Einstellungen:

- **AutoDiscover-Fehler** — `PreferLocalXML`, `ExcludeHttpsAutoDiscoverDomain` überschreiben lautlos das Cloud-Routing
- **Authentifizierungsblockaden** — `EnableADAL = 0` verhindert Modern Auth, M365 wird unerreichbar
- **Protokoll-Downgrades** — `MapiHttpDisabled = 1` erzwingt RPC/HTTP-Fallback mit Performanceeinbußen
- **Hardcodierte Server** — `ProxyServer`-Werte, die auf stillgelegte Infrastruktur zeigen
- **Proxy/WPAD-Konflikte** — maschinenweite Proxy-Durchsetzung blockiert M365-Optimize-Endpunkte

Dieses Tool findet sie alle, bevor sie euch finden.

## Funktionsumfang

```
HKCU:\Software\Microsoft\Office\16.0\Outlook\*          ← Benutzer direkt
HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\* ← GPO Benutzerkonfiguration
HKCU:\Software\Microsoft\Exchange\*                      ← Exchange-Client
HKLM:\Software\Microsoft\Office\16.0\Outlook\*          ← Maschine direkt
HKLM:\Software\Policies\Microsoft\Office\16.0\Outlook\* ← GPO Computerkonfiguration
HKLM:\Software\Policies\Microsoft\Exchange\*             ← Exchange-Maschinenrichtlinie
Office 14.0 / 15.0 Äquivalente                          ← Legacy-Altlasten
WPAD / Interneteinstellungen / WinHTTP                   ← Proxy-Durchsetzung
```

Jeder Fund wird:
- **Auf seinen ADMX-Richtliniennamen gemappt** (was der GPO-Editor anzeigt vs. was in der Registry steht)
- **Nach Schweregrad bewertet** (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Mit Migrationsauswirkung annotiert** und Handlungsempfehlung versehen
- **Gekennzeichnet** als GPO-erzwungen, direkt gesetzt oder Legacy

## Schnellstart

```powershell
# Einfacher lokaler Scan
.\Get-OutlookGPOAudit.ps1

# Vollständiger Scan mit WPAD und GPO-Objektanalyse
.\Get-OutlookGPOAudit.ps1 -IncludeWPAD -GPOAnalysis

# Remote-Scan mehrerer Rechner
.\Get-OutlookGPOAudit.ps1 -ComputerName DC01,WS001,WS002

# Eigener Ausgabepfad
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\Migration\Audit -IncludeWPAD
```

## Ausgabe

```
OutlookGPOAudit_20250218_143022/
├── OutlookGPO_FullInventory.csv        # Alle gefundenen Registry-Werte
├── OutlookGPO_MigrationBlockers.csv    # Nur CRITICAL + HIGH Einträge
├── OutlookGPO_AuditReport.html         # Visueller Report mit Severity-Hervorhebung
└── OutlookGPO_PolicyObjects.csv        # GPO-Objekte (bei -GPOAnalysis)
```

Der HTML-Report enthält:
- Dashboard mit Zusammenfassung (Gesamtfunde, Critical/High/Medium, Legacy-Anzahl)
- Migrationsblocker-Tabelle mit Empfehlungen
- Vollständiges Registry-Inventar mit ADMX-Richtlinien-Querverweisen
- GPO-Objektliste mit Verknüpfungs- und Scope-Informationen
- WPAD-Dokumentation und M365-Endpunkt-Bypass-Referenz
- Pre-Migration-Checkliste

## Parameter

| Parameter | Typ | Standard | Beschreibung |
|-----------|-----|----------|-------------|
| `-ComputerName` | String[] | localhost | Zielrechner für den Scan |
| `-ExportPath` | String | `.\OutlookGPOAudit_<Zeitstempel>` | Ausgabeordner |
| `-IncludeWPAD` | Switch | aus | WPAD-/Proxy-/WinHTTP-Schlüssel scannen |
| `-GPOAnalysis` | Switch | aus | GPO-Objekte über `Get-GPO` auswerten (erfordert RSAT) |

## ADMX-Zuordnung

Der Kernwert dieses Tools ist der Rosetta-Stein zwischen Registry und ADMX. Der GPO-Editor zeigt benutzerfreundliche Namen wie *„AutoErmittlung deaktivieren"*, schreibt aber in Registry-Pfade, die beim Troubleshooting nicht offensichtlich sind.

| GPO-Editor zeigt | Registry-Wert | Warum es wichtig ist |
|---|---|---|
| Abfrage der AutoErmittlungsdomäne ausschließen | `ExcludeHttpsAutoDiscoverDomain` | Blockiert HTTPS-AutoDiscover — M365 braucht das |
| Lokale XML-AutoErmittlung bevorzugen | `PreferLocalXML` | Lokales XML überschreibt ALLES. Blockiert Migration komplett. |
| Zero-Config-Exchange deaktivieren | `ZeroConfigExchange` | Verhindert automatische Profilerstellung |
| Moderne Authentifizierung aktivieren | `EnableADAL` | **Pflicht** für M365. 0 = keine Verbindung möglich. |
| MAPI/HTTP deaktivieren | `MapiHttpDisabled` | DAS Protokoll für M365. Deaktiviert = eingeschränkt. |
| OST-Datei nicht zulassen | `NoOST` | Nur Online-Modus. Massive Performanceeinbußen mit M365. |
| RPC-Proxyservername | `ProxyServer` | Hardcodierter Server WIRD nach Migration fehlschlagen |

Vollständige Zuordnung von 30+ Richtlinien in der `$ADMXMappings`-Hashtable des Skripts.

## Schweregrad-Klassifikation

| Stufe | Bedeutung | Beispiel |
|-------|-----------|---------|
| **CRITICAL** | Unterbricht M365-Konnektivität | `EnableADAL=0`, `MapiHttpDisabled=1`, `NoOST=1` |
| **HIGH** | Verursacht erhebliche Probleme | AutoDiscover-Ausschlüsse, hardcodierte Proxy-Server |
| **MEDIUM** | Sollte geprüft werden | Cached-Mode-Einstellungen, OST-Größenlimits, Sync-Fenster |
| **LOW** | Informativ / Aufräumen | Roaming-Signaturen, Anhangsblockierung, Legacy-Schlüssel |

## Pre-Migration-Checkliste

1. ☐ Modern Auth aktivieren (`EnableADAL = 1`) per GPO
2. ☐ Hardcodierte RPC-`ProxyServer`-Werte entfernen
3. ☐ MAPI/HTTP aktiviert sicherstellen (`MapiHttpDisabled` = 0 oder nicht vorhanden)
4. ☐ Cached Mode aktivieren (`NoOST` = 0 oder nicht vorhanden)
5. ☐ `PreferLocalXML`-AutoDiscover-Überschreibungen entfernen
6. ☐ AutoDiscover-Ausschlussrichtlinien prüfen
7. ☐ `ZeroConfigExchange` aktiviert sicherstellen
8. ☐ Cached-Mode-Synchronisierungsfenster setzen (12 Monate empfohlen)
9. ☐ Legacy Office 2010/2013 GPO-Überreste entfernen
10. ☐ Proxy/WPAD erlaubt M365-Optimize-Endpunkte verifizieren

## Citrix vs. Fat-Client Vergleich

In Citrix-Published-App-Umgebungen kommen Outlook-GPOs aus **zwei unterschiedlichen Quellen**, die bei der Fehlersuche oft übersehen werden:

```
Fat Client:    Benutzer-OU-GPO  ──→  HKCU am Endgerät    ──→  Outlook
Citrix VDA:    Server-OU-GPO    ──→  HKCU via Loopback    ──→  Outlook (Published App)
                                     + UPM/FSLogix-Layering
```

Das Ergebnis: Ein Benutzer mit lokalem Outlook bekommt andere Einstellungen als derselbe Benutzer mit Outlook als Citrix Published App. Klassischer Migrations-Blindspot.

### Verwendung

```powershell
# Auto-Erkennung ob auf/in Citrix
.\Get-CitrixOutlookGPO.ps1 -AutoDetect

# Expliziter Vergleich
.\Get-CitrixOutlookGPO.ps1 -CitrixVDAServers CTX01,CTX02 -CompareWithClient WS001

# Empfohlener Workflow
# Schritt 1: Basis-Audit auf VDA
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\ctx_audit -IncludeWPAD    # auf Citrix-Server
# Schritt 2: Basis-Audit auf Fat Client
.\Get-OutlookGPOAudit.ps1 -ExportPath C:\cli_audit -IncludeWPAD    # am Endgerät
# Schritt 3: Vergleich
.\Get-CitrixOutlookGPO.ps1 -CitrixVDAServers CTX01 -CompareWithClient WS001
```

### Was erkannt wird

| Fund | Risiko | Warum |
|------|--------|-------|
| **Wertkonflikte** | Unterschiedliche Werte auf VDA vs. Client | Benutzer bekommt inkonsistentes Outlook-Verhalten |
| **Nur-Citrix-Einstellungen** | GPO nur an VDA-OU, nicht an Endgerät-OU | Published-App-Benutzer bekommen Einstellungen, die Fat-Client-Benutzer nicht haben |
| **Nur-Client-Einstellungen** | GPO nur an Endgerät-OU, nicht an VDA-OU | Fat-Client-Benutzer bekommen Einstellungen, die Citrix-Benutzer vermissen |
| **UPM-Ausschlüsse entfernen Outlook-Keys** | UPM-Registry-Ausschlussliste löscht Outlook-Einstellungen | Einstellungen verschwinden zwischen Citrix-Sitzungen |
| **OST auf nicht-persistentem Speicher** | Cached Mode aktiv, aber kein FSLogix/persistente Disk | Vollständiger OST-Neuaufbau bei jedem Citrix-Logon |
| **Modern Auth ohne Citrix FAS** | EnableADAL=1, aber kein FAS/SSO-Passthrough | Auth-Popups scheitern oder schleifen in Published Apps |
| **Proxy-Divergenz** | VDA routet über Datacenter-Proxy, Client über lokalen | M365 funktioniert lokal, scheitert aber in Citrix |

### Citrix-spezifische Registry-Pfade

Zusätzlich zu den Standard-Outlook-Pfaden scannt das Citrix-Modul:

```
HKLM:\Software\Policies\Citrix\UserProfileManager\*     ← UPM Sync-/Ausschlusslisten
HKLM:\Software\FSLogix\Profiles                          ← FSLogix-Profilcontainer
HKLM:\Software\Policies\FSLogix\ODFC                     ← FSLogix-Office-Container
HKLM:\Software\Citrix\VirtualDesktopAgent                ← VDA-Erkennung
HKLM:\Software\Citrix\CtxHook\AppInit_DLLs\Outlook       ← Citrix Outlook-Hooks
HKLM:\Software\Citrix\...\Authentication                 ← Citrix SSO/FAS-Konfiguration
```

### GPO-Loopback-Verarbeitung

Dies ist der Kern des Citrix-GPO-Problems. Wenn Loopback aktiviert ist (Standard bei Citrix):

- **Ersetzen-Modus**: Benutzerkonfiguration der VDA-Server-OU *ersetzt* die normale Benutzerrichtlinie vollständig
- **Zusammenführen-Modus**: VDA-Server-OU-Benutzerkonfiguration wird mit der Benutzer-OU-Richtlinie *zusammengeführt* (VDA gewinnt bei Konflikten)

Prüfen mit: `gpresult /scope computer /v | findstr Loopback`

## Voraussetzungen

- PowerShell 5.1+
- Lokale Adminrechte (für HKLM-Zugriffe)
- RSAT-Gruppenrichtlinienmodul (optional, für `-GPOAnalysis`)
- WinRM auf Zielrechnern aktiviert (für Remote-`ComputerName`)

## Dateien

```
├── Get-OutlookGPOAudit.ps1             # Haupt-Scanner-Skript
├── Get-CitrixOutlookGPO.ps1            # Citrix vs. Fat-Client Vergleich
├── OutlookGPO_AuditReference.docx      # Vollständige Dokumentation (druckbar)
├── README.md                            # English
└── README.de.md                         # Diese Datei
```

## Lizenz

MIT

## Autor

Jan Hübener
