# Windows event samples — SYNTHETIC

These XML files were **authored** by `build_windows_samples.py`; they were not captured
from a real computer. They follow the Windows event XML schema and the documented field
names of Sysmon, Windows Security auditing, PowerShell Operational and Microsoft Defender
Operational, in the layout `wevtutil qe <channel> /f:xml /e:Events` produces.

* `demo/` — host DESKTOP-RW01, all four sources: an EICAR test detection, a benign
  Intune inventory script, RW-01 (hidden encoded PowerShell to example.com), RW-03
  (PowerShell → cmd → whoami/ping), RW-04 (failed logons), plus routine background.
* `demo-no-sysmon/` — host DESKTOP-RW05, Sysmon not installed (RW-05).

They make the Windows pipeline testable anywhere (`--backend windows-replay`). They do
not demonstrate that the live event-log reader works on Windows.
