# OSINT & Threat Intelligence Enrichment

> **Investigation Scope:** External infrastructure, DNS records, and embedded payload links extracted from `Lab_Email_Analysis_02` were queried across open-source intelligence (OSINT) platforms to assess sender legitimacy and identify malicious infrastructure. All IOCs are defanged (`[.]`) to prevent accidental navigation.

---

## 1. Sender Domain & SPF Record Analysis (`comunidadeduar.com[.]ar`)

<p>
<img width="800" alt="SPF Record Lookup" src="https://github.com/user-attachments/assets/61aa99dc-94a1-4148-82c0-bd62aa9cfe3d" />
<img width="800" alt="SPF Record for _spf.google.com" src="https://github.com/user-attachments/assets/6fde6e84-ffda-4cb5-97a2-8f5926ad3629" />
<img width="645" height="499" alt="image" src="https://github.com/user-attachments/assets/13462dda-a657-4b8c-9b5a-a3b34126da77" />
</p>

* **DNS Record Policy (`-all`):** An authoritative DNS query (`one.one.one.one`) confirms the domain enforces a hard-fail SPF policy (`-all`), permitting outbound mail exclusively through two delegated third-party cloud providers:
  * `include:_spf.google[.]com` — Google Workspace IPv4/IPv6 ranges (e.g., `74.125.0.0/16`)
  * `include:spf.protection.outlook[.]com` — Microsoft 365 / Exchange Online
* **Security Implication:** Because the email was dispatched directly from an authorized Microsoft 365 relay (`40.107.215[.]98`), it passed SPF validation (`spf=pass`). Rather than external domain spoofing, this confirms the attacker leveraged a compromised account or abused tenant within `comunidadeduar.com[.]ar`.

---

## 2. Sender IP Reputation & Geolocation (`40.107.215[.]98`)

<p>
<img width="800" alt="Sender IP Info 1" src="https://github.com/user-attachments/assets/9e4a7809-1713-4031-9a09-9526bc469631" />
<img width="800" alt="Sender IP Info 2" src="https://github.com/user-attachments/assets/1275a8ce-bc0f-4c4f-98d2-6c9e061dbc01" />
<img width="800" alt="Sender IP Info 1" src="https://github.com/user-attachments/assets/e0bc44b7-d76c-4df4-b963-d1f70b8f368d" />
</p>

* **ASN & Infrastructure:** `40.107.215[.]98` belongs to **Microsoft Corporation** (`AS8075` — Exchange Online Protection / Outlook outbound mail infrastructure).
* **Reputation & Abuse Signals:** Baseline threat intelligence lookups on **VirusTotal** and **AbuseIPDB** show a clean reputation score due to its role as shared cloud email infrastructure, though community reports document frequent abuse of these shared Microsoft 365 relays in phishing and BEC campaigns.
* **Analyst Takeaway:** Perimeter IP blocking is not recommended because `40.107.215[.]98` handles high volumes of legitimate enterprise mail. Containment should target the specific sender account (`nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar`), subject line patterns, and downstream phishing infrastructure.

---

## 3. Embedded Attachment Link & Domain Analysis (`script.google[.]com`)

<p>
<img width="800" alt="Domain in Embedded Attachment Link" src="https://github.com/user-attachments/assets/f416bcc6-c457-4649-9569-7172796e5599" />
</p>

* **Extracted IOC / Domain:** `script.google[.]com`
* **Infrastructure Context:** Legitimate **Google Apps Script** / Google Cloud infrastructure (`script.google[.]com`), frequently abused by threat actors to host credential-harvesting pages, redirects, or form-capture workflows behind a trusted Google domain.
* **Threat Intelligence Verdict:** Multi-engine scanning shows a split verdict—flagged as **Phishing** by **Criminal IP**, while marked **Clean** by traditional vendors—a common evasion signature when attackers weaponize legitimate cloud-hosted scripts.
* **Attack Chain Role:** Embedded inside the fake Amazon account-recovery image lure to capture victim credentials and enable account takeover (ATO).

---

## Summary of Indicators of Compromise (IOCs)

| Indicator Type | Defanged Value | Context / Role |
| :--- | :--- | :--- |
| **Sender Address** | `nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar` | Compromised or abused sender account |
| **Sender Domain** | `comunidadeduar.com[.]ar` | Delegates SPF to Google Workspace & Microsoft 365 (`-all`) |
| **Sender IP** | `40.107.215[.]98` | Microsoft 365 outbound relay (`AS8075`, `spf=pass`) |
| **Phishing / Abuse Domain** | `script.google[.]com` | Flagged for phishing; hosts Amazon credential-harvesting flow |
