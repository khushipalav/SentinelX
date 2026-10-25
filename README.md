# Sentinel-X Desktop

Integrated desktop application containing all Sentinel-X modules:

1. Malware Scanner (static analysis: signatures, heuristics, Random Forest ML)
2. Process Monitor (real-time process behavior and risk analysis)
3. Phishing Detector (PhishGuard, custom KNN URL classifier)
4. Ransomware Monitor (folder behavior monitoring, burst scoring, safe quarantine)
5. Central Security Dashboard (combines all of the above)

## Run

```powershell
cd SentinelX_Desktop
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py main.py
```

Or double-click `run_sentinelx.bat` (it also installs any newly added dependency, e.g. `watchdog`).

The malware scanner performs static analysis only. It does not execute uploaded files.

## Ransomware Monitor

Code lives in the `ransomware/` package (engine) and `RansomwarePage` in `main.py` (UI).

- **Alerts / Activity / Folders / Quarantine / Settings** tabs inside the Ransomware page.
- Watches only the folders you add. Scores bursts of modifications, renames and deletions per folder
  and raises an alert only when risk escalates (Low / Medium / High / Critical).
- Alerts feed the dashboard: Live Activity list, Security Alerts counter, Active Modules counter
  and the System Health panel.
- Data (own SQLite DB, scan CSVs, quarantine folder) is stored in `ransomware_data/`, separate
  from `sentinelx.db`. Events from that folder are ignored so the monitor never reacts to itself.

**Limits:** this is real-time *detection*, not prevention. It does not block writes or terminate
processes, cannot recover already-encrypted files, and is not a replacement for Windows Defender
or professional endpoint protection. Quarantine always asks for confirmation and restore is
hash-verified.

Safe way to try it: add an empty throw-away folder, press **Start Protection**, then create/edit/rename
a few dozen dummy text files quickly inside it. Never test with real documents.

## Tests

```powershell
py -m pip install pytest
py -m pytest tests -q
```
