# OSINT & Infrastructure Investigation

> **Investigation:** MYDFIR — Lab Email Analysis 01  
> **Primary Pivot Targets:** `mail.yobow[.]cn`, `183.56.179[.]169`, `sasktel[.]net`  
> **Key Takeaway:** Originating mail infrastructure and IP reputation point to China and prior 419/scam reporting, contrasting with the spoofed Canadian ISP sender domain (`sasktel[.]net`).

---

## 1. Originating Mail Server (`mail.yobow[.]cn`)

Initial header inspection points to `mail.yobow[.]cn` as the mail server associated with the message.

### WHOIS & Domain Registration
<img width="720" alt="WHOIS lookup for yobow.cn" src="https://github.com/user-attachments/assets/3fd39555-c60a-4ddf-852c-e534fc45a83f" />

* **Registration Date:** July 18, 2014
* **Attribution:** Registered in Beijing, China, aligning with the `.cn` country-code top-level domain.

### VirusTotal Reputation
<img width="720" alt="VirusTotal results for yobow.cn" src="https://github.com/user-attachments/assets/4ee82c7a-1e56-49f3-ba42-92c2d86981af" />

* **Threat Context:** Flagged under `"419 Scam - Fraudulent email accounts by sender domain"`, indicating prior community/vendor reporting of similar advance-fee lures tied to this infrastructure.

---

## 2. Claimed Sender Domain (`sasktel[.]net`)

Next, the claimed sender domain in the `From` header (`sasktel[.]net`) was evaluated to separate legitimate domain reputation from potential spoofing.

<p>
  <img width="48%" alt="Domain reputation check 1 for sasktel.net" src="https://github.com/user-attachments/assets/f06a5fbc-65a9-4c84-99d7-3c0e7cbe5ea2" />
  <img width="48%" alt="Domain reputation check 2 for sasktel.net" src="https://github.com/user-attachments/assets/78383ff8-b58a-42d7-b7b0-c401d822b798" />
</p>

<img width="650" alt="WHOIS creation date for sasktel.net" src="https://github.com/user-attachments/assets/d67534db-2ecd-4b79-95d0-46281d05a67d" />

* **Reputation & Age:** Clean on VirusTotal with no malicious detections in this lookup; WHOIS shows a long-standing creation date of **April 5, 2000**.
* **Entity Context:** Open-source lookup confirms `sasktel[.]net` belongs to a legitimate telecommunications/ISP provider in Saskatchewan, Canada—making it a likely spoofing target rather than attacker-owned infrastructure.

---

## 3. Sending IP Address (`183.56.179[.]169`)

OSINT checks on the originating IP address `183.56.179[.]169` were gathered to verify geolocation, ownership, and abuse history.

<p>
  <img width="48%" alt="IP intelligence lookup 1 for 183.56.179.169" src="https://github.com/user-attachments/assets/2d445050-43c1-41d5-af99-becc3e542053" />
  <img width="48%" alt="IP intelligence lookup 2 for 183.56.179.169" src="https://github.com/user-attachments/assets/2e276753-6b0a-402a-af11-0f988ce29c2a" />
</p>

<p>
  <img width="48%" alt="IP abuse and reputation check 3 for 183.56.179.169" src="https://github.com/user-attachments/assets/6d515a25-64d8-445c-bada-794e236a7186" />
  <img width="48%" alt="IP intelligence check 4 for 183.56.179.169" src="https://github.com/user-attachments/assets/b7d6fc59-ab2d-46e3-b6f1-5845e8663874" />
</p>

* **Geolocation & History:** Geolocated in China with **10 prior abuse/spam reports**, reinforcing malicious/unwanted sending behavior.

---

## 4. SPF Record Verification (`NSLookup.io`)

To understand why the message produced an SPF `SoftFail`, DNS/SPF records were inspected using NSLookup.io.

<img width="720" alt="NSLookup.io SPF record check" src="https://github.com/user-attachments/assets/3ac30ed9-8f88-4d4a-96b3-4a0a5040f400" />

* **Authentication Alignment:** `183.56.179[.]169` does not satisfy the domain's authorized sender conditions for a `Pass`, aligning with the observed `SoftFail` result.

---

## OSINT Summary Matrix

| Indicator (Defanged) | Type | Key Finding |
| :--- | :--- | :--- |
| `mail.yobow[.]cn` | Mail Server / Domain | Registered July 18, 2014 (Beijing, CN); tied to `"419 Scam"` reporting |
| `sasktel[.]net` | Sender Domain | Established April 5, 2000; legitimate Saskatchewan ISP—likely spoofed |
| `183.56.179[.]169` | IP Address | Located in China; 10 prior reports indicating suspicious/malicious activity |
