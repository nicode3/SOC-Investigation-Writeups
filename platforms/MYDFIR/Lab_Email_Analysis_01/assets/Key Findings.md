# Key Findings & Technical Evidence

> **Operational Safety:** File integrity was verified by pulling and comparing cryptographic hashes prior to examination. All analysis was performed inside an isolated sandbox environment.

---

## 1. Hash Check

<p>
  <img width="1003" height="226" alt="Pasted image 20261121200840" src="https://github.com/user-attachments/assets/b6764533-ad3a-46b0-b63c-0908968f382c" />
  <img width="705" height="206" alt="Pasted image 20261121200756" src="https://github.com/user-attachments/assets/18bb9f75-4b91-4b64-8325-42e0dd1be6fe" />
</p>

---

## 2. Email Authentication Analysis (SPF / DKIM / DMARC)

<p>
  <img width="654" height="96" alt="Pasted image 20261121201216" src="https://github.com/user-attachments/assets/f8a023e6-b971-4503-8133-5115649db705" />
  <img width="652" height="120" alt="Pasted image 20261121222312" src="https://github.com/user-attachments/assets/b29f08be-77af-4f1f-bcf0-39bf78e1f11a" />
</p>

* **SPF Verdict (`SoftFail`):** The sending server (`183.56.179[.]169`) is not authorized by `sasktel[.]net` to send emails on its behalf. Because it was configured as a soft fail rather than a hard fail, the message was flagged as suspicious but still delivered to the recipient's inbox.
* **Missing Protections:** Neither **DKIM** nor **DMARC** records are configured for the domain, leaving recipients without cryptographic verification or strict rejection policies.

---

## 3. Return-Path & Reply-To Inspection

<p>
  <img width="323" height="79" alt="Pasted image 20261121233746" src="https://github.com/user-attachments/assets/0f0f0929-5a2d-462f-8bba-ccce20eca835" />
  <img width="427" height="81" alt="Pasted image 20261121233712" src="https://github.com/user-attachments/assets/a95795c4-f422-40d3-a21c-48c7b2c3eb71" />
</p>

* **Routing Behavior:** The `Return-Path` and `Reply-To` addresses do not match each other. While mismatched routing headers can occur in legitimate mailing lists or third-party services, in this context it serves to redirect victim replies to an attacker-controlled Gmail account.

---

## 4. MIME Structure & Message-ID Artifacts

<p>
  <img width="700" height="350" alt="image" src="https://github.com/user-attachments/assets/9242d7d9-352c-4e58-bfbc-9e63437bc4f6" />
  <img width="228" height="72" alt="Pasted image 20261121233828" src="https://github.com/user-attachments/assets/66a7b74a-6637-4142-abda-00fbab3abd18" />

</p>

* **Content Type:** `text/html` — allows rich formatting and layout styling used to make the advance-fee lure appear official.

<img width="479" height="64" alt="Pasted image 20261121233956" src="https://github.com/user-attachments/assets/d898dc3b-5bf7-4058-92bc-365042559e4c" />

* **Message-ID Infrastructure:** Reveals the originating mail server domain (`mail.yobow[.]cn`), exposing the underlying infrastructure behind the spoofed `sasktel[.]net` sender address.

---

## 5. Social Engineering Lure & Contact Personas

<img width="448" height="191" alt="Pasted image 20261121234120" src="https://github.com/user-attachments/assets/8d16f2d7-8c43-4e1b-817e-6be94516ddef" />

The message body instructs the target to reach out to two fabricated personas to claim the funds:

| Role in Lure | Claimed Persona | Contact Address (Defanged) |
| :--- | :--- | :--- |
| **1st Contact** | Diplomatic Agent Miss. Cynthia R. James | `agentcynthiajamescontact01@gmail[.]com` |
| **2nd Contact** | Diplomatic Agent Mr. John Williams | `dr.philipmaxwell303@gmail[.]com` |
