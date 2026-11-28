## 🎯 Lab Objective
Identify **Impossible Travel** and **unfamiliar sign-in activity** in Splunk by crafting transformation queries to isolate anomalous logins. 

> **Why this matters:** Impossible travel and unfamiliar sign-ins are core identity-based detection use cases in a SOC, designed to rapidly flag account takeovers when a user authenticates from an unexpected geographic location or an impossible timeframe.

---

## 📝 Investigation Q&A

| Investigation Question | Finding |
| :--- | :--- |
| **1. What account was compromised?** | `JChan@7pd6vr.onmicrosoft[.]com` |
| **2. According to OSINT, where did this user log in from?** | **Singapore** (`188.214.125[.]138`) |
| **3. What date & time did this login occur (UTC)?** | `2024-02-11 20:46:39 UTC` |
| **4. Did any other account log in from this IP?** | **No.** Activity from `188.214.125[.]138` was isolated exclusively to `JChan`. |

### 5. What activities were performed from this IP?
* **Initial Access:** Authenticated into `JChan`'s mailbox from Singapore (`188.214.125[.]138`).
* **Persistence & Evasion:** Created a malicious inbox rule forwarding emails from `schan` to an external attacker address (`stoicellis@imcourageous[.]com`), marking them as **Read**, and moving them to **Deleted Items**.
* **Collection (Reconnaissance):** Accessed two sensitive messages:
  * `RE: First Invoice of the month`
  * `URGENT: Client Bank Account`
* **Internal Spearphishing:** Sent an email titled **`URGENT: Client Bank Account`** containing a malicious PDF attachment (`NEW-BANK-ACCOUNT.pdf`).

---

## 📌 Recap of Findings
* **Unauthorized Access:** Confirmed a successful login for `JChan` originating from a Singapore IP (`188.214.125[.]138`) just 13 minutes after a legitimate login in Vancouver, BC.
* **Covert Exfiltration:** An inbox forwarding rule (`stoicellis@imcourageous[.]com`) and SMTP forwarding were configured to silently exfiltrate correspondence from `schan`.
* **Mailbox Tampering:** The threat actor accessed financial/invoice threads, deleted the draft **`"Re: First Invoice of the month!"`** from `JChan`'s `\Drafts` folder, and launched an internal Business Email Compromise (BEC) lure (`NEW-BANK-ACCOUNT.pdf`) targeting `schan`.
