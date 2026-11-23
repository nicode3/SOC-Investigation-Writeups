# Phishing Investigation: Amazon Credential Harvesting (`Lab_Email_Analysis_02`)

> **Verdict:** **Malicious — Credential Phishing (Brand Impersonation)**  
> **Primary IOCs:** `nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar` | `40.107.215[.]98` | `script.google[.]com`

---

## Executive Summary

This investigation analyzes an unsolicited phishing email masquerading as an **Amazon account security alert** with the subject line `"We locked your account for security reason"`. By embedding fake account-recovery instructions inside an image rather than plaintext, the threat actor attempted to bypass traditional keyword-based email filters and lure the recipient into submitting credentials via a **Google Apps Script** (`script.google[.]com`) redirect/credential harvester.

Although the message passed SPF authentication (`spf=pass`) because it originated from authorized Microsoft 365 outbound infrastructure (`40.107.215[.]98`), external OSINT enrichment confirmed the sender domain (`comunidadeduar.com[.]ar`) has been reported for active phishing in the wild—indicating a compromised or abused tenant rather than legitimate communication.

---

## Recap of Findings

* **Email Authentication & Infrastructure:** `SPF` passed because the sending IP (`40.107.215[.]98`) belongs to **Microsoft Corporation** (`AS8075`), which is authorized under `comunidadeduar.com[.]ar`'s DNS policy. However, `DKIM` and `DMARC` are unconfigured (`none`), and AbuseIPDB flags the relay IP for outbound email spam activity.
* **Header & Spoofing Anomalies:** No `Reply-To` header was present, and the display name does not align with the underlying sender address (`nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar`).
* **Social Engineering & Evasion:** The email relies on artificial urgency and scarcity tactics (*account lockout*) alongside an image-based lure to evade static body text inspection.
* **Payload & Destination Analysis:** Dynamic/OSINT analysis via **URLScan** and threat intelligence feeds identified an embedded link pointing to `script.google[.]com` (`/exec`), functioning as a redirector and credential-harvesting endpoint.

---

## Containment, Hunting & Next Steps

Because the email is confirmed malicious, execute the following incident response actions across email and network telemetry:

### 1. Threat Hunting (SIEM & Email Gateway)
Query email transaction/header logs (or the email gateway directly) across **September 2023** to determine exposure across the organization:
* **By Subject Line:** Search for messages matching `"We locked your account for security reason"`.
* **By Specific Sender:** Search for all inbound/outbound traffic involving `nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar`.
* **By Sender Domain:** Search for any messages to or from `@comunidadeduar.com[.]ar`, as the domain is actively associated with phishing campaigns.

### 2. Network & Proxy Log Review
* Query outbound proxy, firewall, or DNS logs during **September 2023** for connections to `script.google[.]com` containing `/exec` in the URI path.
* Identify any internal hosts or user accounts that resolved or accessed the link.

### 3. Remediation & Account Hardening
* **Purge Messages:** Quarantine and hard-delete all matching phishing emails from user mailboxes.
* **Credential & Session Reset:** For any user confirmed to have clicked the link or interacted with the page, enforce an immediate **password reset** and **revoke active Entra ID / SSO sessions** to prevent unauthorized account takeover.
