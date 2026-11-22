# Lab: First Email Analysis

> **Platform:** MYDFIR  
> **Verdict:** Malicious / Advance-Fee Scam (`16M USD` lure)  
> **Recommended Action:** Purge message, audit recipient/reply activity, and block sender infrastructure

## Objective

Examine an email's headers, indicators, and content without opening it in a standard mail client, and use Open Source Intelligence (OSINT) to gather supporting context and determine next steps.

## Key Findings

* **Known Malicious Infrastructure:** `yobow[.]cn` is associated with similar campaigns, and the sender IP has prior spam reports.
* **Authentication Failure:** SPF returned a `softfail`, indicating the sending IP is not authorized for the claimed domain.
* **Header & Identity Mismatches:** The `Reply-To` address does not match the `From` address, and the display name does not align with the `From` address.
* **Social Engineering Lure:** The message attempts to bait recipients into replying to initiate a fraudulent `$16,000,000 USD` payout conversation.

## Indicators & Hunt Pivot Points

| Indicator Type | Value (Defanged) | Role in Investigation | Search Guidance |
| :--- | :--- | :--- | :--- |
| **Domain** | `yobow[.]cn` | Associated with prior similar mailings | Pivot on sending domain / infrastructure |
| **Sender Address** | `p.chambers@sasktel[.]net` | Listed in `From` header | Search emails to and from this address |
| **Reply-To Address** | `agentcynthiajamescontact01@gmail[.]com` | Listed in `Reply-To` header | Search emails to and from this address |
| **Body Address** | `dr.philipmaxwell303@gmail[.]com` | Referenced inside message body | Search emails to and from this address |
| **Sender Domain** | `sasktel[.]net` | Domain in `From` address | Broad domain hunt (use caution; avoid for `gmail.com` / `microsoft.com`) |

## Investigation & Response Next Steps

1. **Scope Organizational Impact:** Check SIEM email transaction and header logs (if ingested) or query the email gateway for messages with the subject `"Attention Dear Beneficiary"` in **December**.
2. **Run Targeted Searches:** Query mail/SIEM logs for activity involving:
   * `p.chambers@sasktel[.]net` (`From`)
   * `agentcynthiajamescontact01@gmail[.]com` (`Reply-To`)
   * `dr.philipmaxwell303@gmail[.]com` (body)
   * `sasktel[.]net` (all traffic to/from domain—watch for high volume)
3. **Contain & Remediate:** Delete the scam email across affected mailboxes, and instruct any user who replied to cease all communication immediately.
