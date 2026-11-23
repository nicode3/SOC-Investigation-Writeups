# Key Findings & Technical Evidence

> **Operational Safety:** File integrity was verified by pulling and comparing cryptographic hashes prior to examination. All analysis was performed inside an isolated sandbox environment.

---

## 1. Hash Check

<p>
<img width="974" height="214" alt="image" src="https://github.com/user-attachments/assets/0192799d-bfeb-4b22-a735-785805605df8" />
<img width="544" height="313" alt="image" src="https://github.com/user-attachments/assets/b110fbff-6580-429a-a4ad-3f321c9cfca6" />
</p>

---

## 2. Email Authentication Analysis (SPF / DKIM / DMARC)

<p>
<img width="510" height="80" alt="image" src="https://github.com/user-attachments/assets/86ca4027-40b0-4f6f-a2a2-8c1976431fa0" />
<img width="516" height="45" alt="image" src="https://github.com/user-attachments/assets/989c2ace-dcd9-4381-997d-fafd2e8f8591" />
</p>

* **SPF Verdict (`Pass`):** The sending server (`40.107.215[.]98`) is authorized by `spf.protection.outlook[.]com` to send emails on behalf of `comunidadeduar.com[.]ar`. Because the sender domain delegates its SPF record to Microsoft 365 (`protection.outlook[.]com`), the check evaluates as `Pass`.
* **Missing Protections:** Neither **DKIM** (`dkim=none`) nor **DMARC** (`dmarc=none`) records are configured for the domain, leaving recipients without cryptographic verification or strict rejection policies.

---

## 3. Routing & Header Metadata (`From` / `Return-Path` / `To`)

<p>
<img width="445" height="48" alt="image" src="https://github.com/user-attachments/assets/86bb9dd4-da46-455c-858b-e1eb4d268fb6" />
<img width="574" height="39" alt="image" src="https://github.com/user-attachments/assets/6ffa3c3b-1823-42ed-bfc1-f91458fc6e50" />
</p>

* **Sender & Recipient:** Sent from `nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar` to `Phishingisfun@hotmail[.]com` on **Fri, 8 Sep 2023 05:11:14 +0000**.
* **Subject Line:** `"We locked your account for security reason"` — uses urgency and grammatical errors typical of mass credential-harvesting lures.
* **Routing Behavior:** The `Return-Path` and `From` addresses match (`nuthostsrl.SaintU74045Walker@comunidadeduar.com[.]ar`). While mismatched routing headers are a common spoofing indicator, matching fields do not confirm legitimacy—especially when a legitimate domain or tenant has been compromised to send malicious mail.

---

## 4. MIME Structure & Message-ID Artifacts

<p>
<img width="715" height="156" alt="image" src="https://github.com/user-attachments/assets/6b58b6f4-71f7-44b1-864d-f49703724077" />
<img width="526" height="60" alt="image" src="https://github.com/user-attachments/assets/389eefa9-d906-4dbd-8669-ec6f6791b6f4" />
</p>

* **Content Type & Encoding:** `multipart/mixed` with `8bit` transfer encoding, allowing the email to bundle embedded image payloads alongside standard message parts.
* **Message-ID Infrastructure:** `<lCoLrriMV1genj0ZtZQMKEVTBnhfL56Wal3quBo1vU@mail-pf1-f856.outlook.office365[.]com>` confirms the message was generated and routed through Microsoft 365 / Exchange Online infrastructure rather than an unauthenticated third-party relay.

---

## 5. Threat Classification & Attack Vector

* **Attack Type:** Credential Phishing Attack (Brand Impersonation — Amazon)
* **Delivery & Evasion Technique:** Instead of placing plaintext phishing text directly in the email body—which traditional keyword filters easily flag—the attacker embedded an **image** displaying fake account recovery instructions for **Amazon**.
* **Objective:** The embedded image directs the victim to click a malicious link and submit their Amazon login credentials, enabling the threat actor to harvest the credentials and execute an account takeover (ATO).
