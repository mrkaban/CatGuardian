# CatGuardian

Cat Guardian is a comprehensive real-time protection suite for Windows PCs. The program pairs the ClamAV scanning engine with advanced integrity monitoring of critical system files and the registry, firewall management backed by threat intelligence feeds, and a resident antivirus scanner with heuristic analysis.

You can read more details on the official website (Russian language): https://alekseycheremnykh.ru/post/cat-guardian/

Main Capabilities
-----------------

- Resident antivirus scanner powered by the ClamAV engine with automatic signature updates, an instant malware hash index (built from ClamAV signature databases) for immediate detection, and in-house heuristic analysis (entropy, behavior, reputation)
- Advanced integrity control of critical Windows files and the registry (File Inspector)
- Windows Firewall management with Threat Intelligence databases
- Proactive protection against ransomware, cryptojacking, credential theft, keyloggers, screen lockers, script-based attacks (AMSI), WMI abuse, LOLBins, DLL hijacking and fileless malware
- AppContainer sandbox for isolated execution of high-risk applications
- Reputation scoring (Pre-Scan) with digital signature verification
- Decoy files (honeypots) that detect unauthorized access to user data
- Quarantine and automatic database updates
- Self-defense mechanisms: file locking, registry protection, anti-kill filter
- First-run wizard, UI themes, Russian and English localization

Demonstration of antivirus operation
-----------------
You can watch the Cat Guardian in action in the video via the following link: https://www.youtube.com/watch?v=m-J2h0lQT4U

Why a commercial antivirus is better than a free one
-------------------

A short list of advantages of a paid (commercial) antivirus:

1. Kernel-level driver (minifilter) — intercepts file-system and process events at the
   kernel level: minimal CPU and RAM usage, instant reaction before a threat can run.

2. Real-time behavioral analysis — catches new (zero-day) threats by behavior, not only
   by known signatures.

3. Cloud reputation and telemetry — millions of devices worldwide report new threats;
   the database updates within minutes, not days.

4. 24/7 technical support — help with infections, false positives and configuration;
   SLA and guarantees.

5. Regular updates and new modules — protection against current threats (ransomware,
   stealers, miners, phishing), not a "frozen" feature set.

6. All-in-one protection — antivirus, firewall, web protection, anti-theft, sandbox,
   parental controls.

7. Protection against targeted and advanced attacks — EDR elements, isolation, quarantine,
   rollback of changes.

8. Legal responsibility and licensing — quality guarantees, compliance (including corporate),
   contract and support.

9. Saves IT time and resources — centralized management, reports, automation.

10. Funding for development — the paid model ensures continuous product development,
    while free solutions are often abandoned by their authors.


License Information
-------------------

- License: GNU General Public License v2 (GPL v2)
- Source code: https://github.com/mrkaban/CatGuardian/
- Antivirus engine: ClamAV® — distributed under the GNU General Public License v2
- ClamAV source code: https://github.com/Cisco-Talos/clamav


The program name "Cat Guardian" and the original logo are the author's own (the trademark is not registered). Using the original name in third-party code modifications (forks) is prohibited. Cat Guardian images — program icons, the original logo and the cat image — are the exclusive property of the author and are protected by copyright.
