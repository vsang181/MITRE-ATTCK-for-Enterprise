# Phishing for Information

Phishing for Information is a reconnaissance technique classified under **MITRE ATT&CK T1598** in which adversaries send electronically delivered social engineering messages to trick targets into voluntarily disclosing sensitive information, most commonly credentials, organisational intelligence, or other actionable data.  It is fundamentally distinct from **T1566 – Phishing** in its objective: where T1566 aims to execute malicious code on the victim's system, T1598 aims to elicit information directly from the victim through deception, making it a pre-compromise intelligence gathering technique rather than an initial access technique. 

Phishing for information operations exploit core human psychological vulnerabilities including trust, urgency, authority, and fear.  Adversaries construct lures that create a believable pretext for the target to provide information, impersonating trusted entities such as employers, vendors, financial institutions, IT support teams, or government authorities.  AI-powered tools including **Large Language Models (LLMs)** are increasingly used by adversaries to generate grammatically flawless, contextually precise phishing content at scale, eliminating the linguistic errors that have historically served as detection indicators and enabling personalised lure generation across large target populations simultaneously. 

***

## Social Engineering Mechanics

Effective phishing for information campaigns are underpinned by structured social engineering principles applied across the full message lifecycle: 

- **Pretexting:** Adversaries construct a convincing false scenario that provides a plausible reason for the target to disclose the requested information. Common pretexts include IT security alerts requiring credential verification, HR policy updates requiring personal data confirmation, financial processes requiring account details, and executive requests requiring urgent information provision.
- **Authority and urgency:** Messages frequently impersonate high-authority figures (e.g., CEO, CFO, IT department, HMRC/IRS) and create artificial time pressure to prevent the target from pausing to verify the request or consult colleagues. 
- **Personalisation:** Spearphishing operations incorporate personally relevant detail derived from prior reconnaissance — including the target's name, role, recent activities, colleague names, and organisational context — to increase the plausibility of the lure and reduce the target's scepticism.
- **Email spoofing:** Adversaries spoof the sender address to impersonate trusted internal or external entities, deceiving both the human recipient and automated email security tools that rely on sender identity for filtering decisions. Spoofing is implemented at the display name, reply-to address, or SMTP envelope level, with varying degrees of technical sophistication. 
- **Email hiding rules:** In campaigns operating from compromised email accounts, adversaries may manipulate mailbox rules to hide sent messages, delete incoming replies, or redirect specific correspondence, enabling sustained phishing activity from a legitimate account while concealing evidence of the operation from the legitimate account owner.

***

## Procedure Examples

### APT28 (Fancy Bear)
**APT28** has conducted sustained spearphishing campaigns to compromise credentials across a broad range of government, military, political, and private sector targets.  The group constructs contextually targeted credential phishing emails impersonating trusted services, with lures tailored to the specific roles and interests of targeted individuals based on prior OSINT reconnaissance, reflecting the group's structured integration of pre-compromise intelligence gathering with phishing operations. 

### Kimsuky
**Kimsuky** has deployed tailored spearphishing email campaigns specifically designed to gather victim information including contact lists, which are then used to identify additional high-value targets within the same organisational network.  This iterative approach — using phishing to harvest contact data and then targeting the newly identified contacts with subsequent campaigns — enables the group to progressively expand its access to an organisation's personnel network from a single initial phishing success.

### Moonstone Sleet
**Moonstone Sleet** has directly interacted with targets via email to elicit organisational information, conducting conversational information-gathering operations in which the adversary exchanges multiple messages with targets under a cover persona to build sufficient trust and rapport to elicit sensitive organisational details over the course of an extended email dialogue. 

### Scattered Spider
**Scattered Spider** operationally combines credential phishing with real-time voice-based social engineering to capture **One-Time Password (OTP) codes** from targets, defeating MFA protections through adversary-in-the-middle (AiTM) techniques.  The group uses SMS and voice-based social engineering to contact target employees in real time, impersonating IT support staff and manipulating targets into providing OTP codes while the adversary simultaneously submits stolen credentials to the legitimate service, effectively defeating time-based MFA protections. This technique was operationally used in the group's high-profile attacks against **MGM Resorts** and **Caesars Entertainment** in 2023. 

### ZIRCONIUM (APT31)
**ZIRCONIUM** conducted targeted credential phishing campaigns against **US presidential campaign staffers**, sending carefully crafted spearphishing emails designed to capture account credentials of high-value political personnel, demonstrating the application of phishing for information against electoral and political intelligence collection objectives.
***

## Mitigations

### Email Authentication (MITRE M1054 – Software Configuration)
Implementing the full suite of email authentication standards provides the strongest available technical defence against sender spoofing: 

- **SPF (Sender Policy Framework):** A DNS TXT record published by the domain owner specifying which mail servers are authorised to send email on behalf of the domain. Receiving mail servers validate the sending server's IP against the SPF record and can reject or quarantine mail from unauthorised senders.
- **DKIM (DomainKeys Identified Mail):** A cryptographic email signing mechanism that attaches a digital signature to outbound emails, verifiable by the recipient's mail server against the public key published in the sender's DNS. DKIM ensures message integrity, detecting modifications to the email body or headers in transit.
- **DMARC (Domain-based Message Authentication, Reporting and Conformance):** A policy framework built on top of SPF and DKIM that enables domain owners to instruct receiving mail servers on how to handle messages that fail SPF or DKIM validation (e.g., `p=quarantine` or `p=reject`). DMARC additionally provides aggregate and forensic reporting, enabling domain owners to monitor for spoofing attempts against their domains. 

Organisations should implement DMARC with a `p=reject` policy for all owned domains after validating that all legitimate mail flows are correctly SPF and DKIM authenticated, using monitoring tools such as 

### User Training (MITRE M1017)
Security awareness training is a critical complementary control, as technical email authentication measures do not address phishing delivered through non-email channels (voice, SMS, social media) or highly convincing lures that successfully pass authentication checks.  Training programmes should be delivered through platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training), incorporating: 
- Role-specific phishing simulation campaigns calibrated to the most relevant attack scenarios for each personnel category.
- Training on identification of urgency and authority manipulation tactics.
- Specific guidance on voice phishing (vishing) and SMS phishing (smishing) recognition, given the increasing operational use of voice-based social engineering for MFA bypass. 
- Reporting procedures for suspected phishing attempts, enabling rapid threat intelligence collection from employee-reported lures.

***

## Detection Strategy

### Email Security and Authentication Monitoring
Effective detection of phishing for information requires layered email security controls operating across sender validation, content analysis, and URL inspection: 

- **DMARC, DKIM, and SPF enforcement and reporting:** Monitor DMARC aggregate reports for spoofing attempts against the organisation's domains, and configure email security gateways to apply quarantine or rejection policies for messages failing SPF and DKIM validation. 
- **Email security gateway analysis:** Deploy email security platforms such as [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) and [Proofpoint Email Protection](https://www.proofpoint.com/uk/products/email-security-and-protection) with AI-powered content analysis, attachment sandboxing, and URL detonation to detect phishing lures that successfully pass authentication checks. 
- **Unusual sender volume monitoring:** Monitor for patterns of numerous accounts within the organisation receiving messages from a single unusual or unknown sender address, characteristic of bulk credential phishing campaigns targeting multiple personnel. 
- **URL inspection and category filtering:** Apply URL inspection within email delivery pipelines including expansion of shortened URLs, and implement DNS-layer filtering through services such as [Cisco Umbrella](https://umbrella.cisco.com/) to block access to uncategorised or known-malicious domains associated with credential harvesting infrastructure. 

### Multi-Channel and Behavioural Detection

- **Social media and messaging platform monitoring:** Monitor for suspicious activity from external accounts on corporate-connected social media and collaboration platforms, including unsolicited information requests, unusual file sharing, and messages from accounts exhibiting characteristics of adversary cover personas such as recently created accounts with limited history. 
- **Voice phishing detection:** Monitor corporate device call logs for calls to and from known malicious phone numbers and for call patterns consistent with social engineering operations, particularly calls targeting IT helpdesk personnel immediately prior to or following anomalous account access events. 
- **MFA bypass anomaly detection:** Monitor authentication logs for patterns consistent with real-time AiTM credential and OTP capture, including rapid credential submission after OTP issuance and authentication events from unexpected geographic locations or IP addresses, using **Entra ID Identity Protection** risk-based conditional access to apply step-up authentication for anomalous login patterns. 
- **Network traffic anomaly analysis:** Monitor for anomalous network data flows associated with credential harvesting page interactions, including connections to newly registered domains, domains with low reputation scores, and non-categorised sites from email client processes. 

***

## Sub-Techniques

| Sub-Technique | Delivery Vector | Primary Objective | Key Distinguishing Characteristics |
|---|---|---|---|
| **[Spearphishing via Service](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Phishing%20for%20Information/Spearphishing%20Service.md)** | Third-party social media, messaging platforms, and collaboration tools (LinkedIn, WhatsApp, Slack, Teams, Signal) | Credential theft and information elicitation through trusted communication channels | Leverages perceived authenticity of non-email platforms; bypasses email security gateways; enables gradual trust-building through extended messaging conversations  |
| **[Spearphishing Attachment](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Phishing%20for%20Information/Spearphishing%20Attachment.md)** | Email with malicious or deceptive file attachments | Credential harvesting through convincing document-based lures | Attachments include fake login forms in Office documents, PDFs requesting credential entry, or HTML attachments rendering phishing pages locally to evade URL filtering |
| **[Spearphishing Link](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Phishing%20for%20Information/Spearphishing%20Link.md)** | Email containing links to adversary-controlled credential harvesting pages | Credential capture through convincing fake login portals | Adversary-controlled sites impersonate legitimate services (Microsoft 365, VPN portals, corporate intranets); URL obfuscation through URL shorteners, homoglyph domains, and typosquatting; real-time MiTM proxying via [Evilginx2](https://github.com/kgretzky/evilginx2) captures session tokens to bypass MFA |
| **[Spearphishing Voice](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Phishing%20for%20Information/Spearphishing%20Voice.md)** | Voice calls (Vishing) and SMS messages (Smishing) to corporate or personal devices | Real-time social engineering for credential disclosure or OTP capture | Direct human interaction removes written evidence; enables real-time adversary adaptation to target responses; particularly effective for OTP and MFA bypass as demonstrated by Scattered Spider  |
