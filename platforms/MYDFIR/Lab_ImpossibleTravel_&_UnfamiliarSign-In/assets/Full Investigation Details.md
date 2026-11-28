# 🛡️ Incident Investigation: Business Email Compromise (BEC) & Impossible Travel

## 📋 Executive Summary
During an investigation covering **February 11 – February 12**, suspicious authentication activity was detected on a corporate Microsoft 365 account (`jchan`). Threat hunting across unified audit logs revealed an **Impossible Travel** event originating from Singapore (`188.214.125[.]138`), followed by mailbox reconnaissance, unauthorized forwarding rules, email deletion, and an internal Business Email Compromise (BEC) phishing attempt targeting `schan`.

---

## 🔍 Phase 1: Initial Triage & Log Verification

### 1. Evidence Integrity (Hash Check)
Before beginning log analysis, file integrity was verified via cryptographic hash checks to ensure the dataset had not been tampered with.

<img width="955" height="229" alt="Hash Check 1" src="https://github.com/user-attachments/assets/bd232e16-4c4b-406f-b334-e41e2bc3e0cf" />
<img width="678" height="263" alt="Hash Check 2" src="https://github.com/user-attachments/assets/c9f87471-39d5-4b2f-8e95-af023e50ce5c" />

### 2. Scoping & Baseline Query
We scoped our search window to **Feb 11 – Feb 12** and analyzed the raw log structure to identify relevant fields for transformation.

<img width="1780" height="127" alt="Search Timeframe" src="https://github.com/user-attachments/assets/0c824498-39f7-4391-88f6-a88acb9ef9cf" />
<img width="627" height="631" alt="Log Field Analysis" src="https://github.com/user-attachments/assets/e0810527-26be-41e1-b7f1-1c8fe3091989" />

To avoid dropping events with null fields, we started with the `table` command rather than `stats`, ensuring full visibility across all log attributes.

<img width="1782" height="581" alt="Initial Table Query" src="https://github.com/user-attachments/assets/86424c0c-946d-4ee1-a9a4-9038ea1ef376" />

---

## 🌍 Phase 2: Detecting Impossible Travel

### 1. Filtering Authentication Events
To investigate potential Impossible Travel, we filtered specifically for `UserLoggedIn` operations. This narrowed our dataset down to **23 events**. *(Note: Missing `ClientIP` values indicate workloads where IP logging is not populated).*

<img width="1778" height="552" alt="UserLoggedIn Filter" src="https://github.com/user-attachments/assets/70ed1428-a7a9-4ff7-a458-11f44137aa09" />

Once the key fields (`ActorIpAddress` and `ClientIP`) were identified, we pivoted to the `stats` command to aggregate the authentication sources.

<img width="557" height="644" alt="Stats Query Setup" src="https://github.com/user-attachments/assets/3ea0c574-f129-4d12-b18a-8abf0dd9d40a" />
<img width="1773" height="115" alt="Stats Results" src="https://github.com/user-attachments/assets/feb608f1-3ce4-4cb6-8cc6-c622735b7942" />

### 2. Filtering Out System Accounts
The query returned 4 events showing `UserId: Not Available`. Cross-referencing Microsoft documentation confirmed these correspond to automated system accounts (`UserType = 4`). We excluded `UserType=4` to isolate human user activity.

<img width="1784" height="431" alt="System Account Logs" src="https://github.com/user-attachments/assets/4076b6ab-bdcc-42c2-80e7-bfdcc6111bed" />
<img width="804" height="322" alt="Filtering UserType 4" src="https://github.com/user-attachments/assets/6edc6b4b-36ca-493d-ba2a-368bd32bb941" />

### 3. OSINT IP Enrichment & Timeline Correlation
Three distinct IP addresses remained. Performing OSINT geolocation revealed:
* **Two IPs** resolved to **Vancouver, BC** (expected corporate location). User `schan` only authenticated once from this legitimate location and was ruled out as benign.
* **One IP (`188.214.125[.]138`)** resolved to **Singapore**.

<img width="1894" height="444" alt="IP Comparison" src="https://github.com/user-attachments/assets/efdde1df-35a1-4942-89ac-078415de7767" />
<img width="616" height="882" alt="OSINT Result 1" src="https://github.com/user-attachments/assets/dea55aca-e389-41db-96b1-734b918a3bba" />
<img width="767" height="879" alt="OSINT Result 3" src="https://github.com/user-attachments/assets/cb8c4dd1-8453-4b8e-8ced-498378a3a928" />

Adding timestamps to the query confirmed **Impossible Travel**: account `jchan` authenticated from **Vancouver, BC**, and just **13 minutes later** authenticated from **Singapore**. *(Note: In a production environment, a 30-to-90-day baseline search would also be conducted to verify historical login patterns).*

<img width="1776" height="531" alt="Impossible Travel Timeline" src="https://github.com/user-attachments/assets/baa589eb-2b0f-40e9-a407-aca2e0fd140d" />
<img width="1365" height="569" alt="Impossible Travel Proof" src="https://github.com/user-attachments/assets/de5b04ec-d97c-4854-aad7-c73c7fd70882" />

---

## 🕵️‍♂️ Phase 3: Post-Compromise Threat Hunting

Pivoting on the malicious IP `188.214.125[.]138`, we investigated all actions performed by the threat actor following initial access.

<img width="1761" height="809" alt="Threat Actor Actions" src="https://github.com/user-attachments/assets/b72c2460-3d7e-4454-a007-f07cd0cd1323" />

### 1. Persistence & Defense Evasion (`New-InboxRule` & `Set-Mailbox`)
The threat actor established persistence and hid their tracks by creating a malicious inbox rule named **`1`** and modifying mailbox forwarding settings:
* **Rule Name:** `1`
* **Condition:** Emails from `schan@7pd6vr.onmicrosoft[.]com`
* **Actions:** Forward to external attacker address `stoicellis@imcourageous[.]com`, mark as **Read**, and move to **Deleted Items**.

<img width="973" height="867" alt="New-InboxRule Details" src="https://github.com/user-attachments/assets/99cebb05-a667-41ad-95d6-c8cb94d692b3" />

Searching for additional activity tied to `imcourageous[.]com` uncovered a `Set-Mailbox` operation configuring `ForwardingSmtpAddress` to `stoicellis@imcourageous[.]com`—a classic indicator of automated data exfiltration.

<img width="1303" height="774" alt="Set-Mailbox Forwarding" src="https://github.com/user-attachments/assets/5ac29a5e-f407-4c30-ac6c-4fedbbfb5bf0" />

### 2. Mailbox Reconnaissance (`MailItemsAccessed`)
Filtering out `UserLoggedIn`, `Set-Mailbox`, and `New-InboxRule` revealed `MailItemsAccessed` events. 

<img width="1756" height="550" alt="MailItemsAccessed Query" src="https://github.com/user-attachments/assets/175389b2-8ce7-4419-99a0-a4b17ba314fa" />

Key forensic artifacts extracted from these logs:
* **Access Type:** `Bind` (indicates individual messages were viewed/accessed directly, as opposed to `Sync` bulk downloads).
* **Folder Path:** `\Drafts`
* **Artifacts Recorded:** `ClientInfoString` (User-Agent) and specific `InternetMessageId` values.

<img width="883" height="780" alt="Bind Access and InternetMessageId" src="https://github.com/user-attachments/assets/4286f28d-a315-483e-bc47-0f384d273ee8" />

### 3. Correlating Accessed & Deleted Emails
By stripping the domain portion (everything after `@`) from the `InternetMessageId` values and querying the email logs, we identified the exact messages accessed by the attacker:
1. `"First Invoice of the Month"`
2. `"Urgent: Client Bank Account"`

<img width="787" height="391" alt="InternetMessageId Query 1" src="https://github.com/user-attachments/assets/d28e8ec4-5605-4353-a08a-c4ab380d46ef" />
<img width="852" height="96" alt="InternetMessageId Query 2" src="https://github.com/user-attachments/assets/0b698efa-5362-40df-b691-90f270808107" />
<img width="976" height="453" alt="Message Correlation" src="https://github.com/user-attachments/assets/96acbd44-8d10-41eb-b184-9d0a2beb0708" />
<img width="1754" height="392" alt="Correlated Email Subjects" src="https://github.com/user-attachments/assets/9c6de909-1517-41fd-91c5-8ee8dbc08740" />
<img width="840" height="732" alt="Email Log Details 1" src="https://github.com/user-attachments/assets/f3ff5e91-d715-42b1-9147-2fdf10fb2f60" />
<img width="795" height="262" alt="Email Log Details 2" src="https://github.com/user-attachments/assets/a7fd335f-08fb-489d-99c2-ed0af97bb501" />
<img width="1043" height="760" alt="Email Log Details 3" src="https://github.com/user-attachments/assets/c6252aea-ba12-4d44-8e92-c8c8837f2868" />

Checking `MoveToDeletedItems` operations confirmed the attacker deleted a draft email inside `jchan`'s mailbox titled **`"Re: First Invoice of the Month!"`**.

<img width="675" height="736" alt="MoveToDeletedItems Log" src="https://github.com/user-attachments/assets/9638e67e-aaab-4722-9914-c7bfc3eca15f" />

### 4. Internal BEC Phishing (`Send` Operation)
Finally, filtering for `Send` operations revealed the threat actor used `jchan`'s compromised account to send an email containing an attachment with the subject **`"Urgent: Client Bank Account"`** to colleague **`schan`**.

<img width="337" height="50" alt="Send Operation Filter" src="https://github.com/user-attachments/assets/8624e26a-1601-4ea8-954a-572bfab1de8c" />
<img width="1149" height="768" alt="Recipient Confirmation" src="https://github.com/user-attachments/assets/6dcbd80e-cb2c-43b3-b03a-7c743b5c5549" />

---

## 🚨 Indicators of Compromise (IOCs) & MITRE ATT&CK Mapping

| Indicator / Artifact | Type | Context |
| :--- | :--- | :--- |
| `188.214.125[.]138` | IP Address | Malicious login origin (Singapore) |
| `stoicellis@imcourageous[.]com` | Email / Domain | External exfiltration target via Inbox Rule & SMTP Forwarding |
| Inbox Rule `"1"` | Persistence | Auto-forwards emails from `schan`, marks read, deletes |
| `"Urgent: Client Bank Account"` | Email Subject | Internal BEC spear-phishing lure sent from `jchan` to `schan` |

* **Initial Access:** Valid Accounts (`T1078`)
* **Persistence / Defense Evasion:** Email Forwarding Rule (`T1564.008` / `T1114.003`)
* **Collection:** Email Collection (`T1114`)
* **Lateral Movement / Impact:** Internal Spearphishing (`T1534`)

---

## 🛡️ Remediation & Recommendations
1. **Account Containment:** Revoke all active session tokens for `jchan` and enforce an immediate password reset.
2. **Remove Persistence:** Delete malicious Inbox Rule `"1"` and remove `stoicellis@imcourageous[.]com` from `ForwardingSmtpAddress`.
3. **Phishing Cleanup:** Purge the `"Urgent: Client Bank Account"` email and attachment from `schan`'s mailbox and block `imcourageous[.]com` at the email gateway.
4. **Hardening:** Enforce Conditional Access policies blocking logins from unauthorized countries and require phishing-resistant MFA.
