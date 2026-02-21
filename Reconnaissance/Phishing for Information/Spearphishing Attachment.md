# Spearphishing Attachment

Spearphishing Attachment is a sub-technique of Phishing for Information (**MITRE ATT&CK T1598.002**) in which adversaries send targeted emails containing file attachments designed to elicit sensitive information — most commonly credentials — from the recipient, rather than to execute malicious code.  This distinguishes it from its initial access counterpart **T1566.001**, which uses attachments to deliver and execute malware: in T1598.002, the attachment itself is a vehicle for information collection, operating through victim interaction with the document's content rather than through code execution. 

The technique exploits recipient trust by constructing plausible business pretexts that provide a compelling reason to engage with the attached file. Common pretexts include requests for information from business associates, forms requiring completion before an event or transaction, and surveys or questionnaires presented as coming from a known organisation.  Adversaries leverage prior reconnaissance intelligence — including organisational structure, personnel roles, business relationships, and operational context gathered through sub-techniques covered earlier in this series — to craft attachment lures with the specificity and contextual relevance required to overcome recipient scepticism. 

***

## Attachment-Based Credential Harvesting Mechanisms

Adversaries implement credential harvesting through spearphishing attachments using several distinct technical approaches, each designed to circumvent specific categories of defensive control: 

- **Recipient-populated documents:** Adversaries attach Microsoft Office documents (Word, Excel) or PDF forms containing embedded input fields that request credential entry, ostensibly for a legitimate business purpose such as a shared resource access form, a vendor portal registration, or a survey requiring authentication. Recipients who complete and return the document transfer their credentials directly to the adversary. 
- **HTML Smuggling for fake login portals:** Adversaries embed malicious HTML files within attachments (or as the attachment itself) that, when opened in a browser, locally render a convincing fake login portal for a targeted service (Microsoft 365, VPN gateway, corporate intranet).  Because the credential harvesting page is rendered locally from an attachment rather than loaded from a remote URL, it bypasses URL reputation filtering, DNS-layer blocking, and web proxy inspection entirely — the connection to the credential harvesting server only occurs when the victim submits their credentials. 
- **Attachment-to-link redirection:** Attachments contain links to credential harvesting pages rather than harvesting credentials directly within the document itself. The attachment serves as the delivery vehicle for the link, providing a contextual pretext that increases click-through rates while the actual credential capture occurs at an adversary-controlled web page.  **Star Blizzard** operationally used this approach, first establishing rapport through extended email exchanges before eventually delivering messages containing attachments with embedded links to credential-stealing sites. 
- **Adversary-in-the-Middle (AiTM) credential proxying:** Links delivered via attachments may point to reverse-proxy phishing frameworks such as [Evilginx2](https://github.com/kgretzky/evilginx2) and [Modlishka](https://github.com/drk1wi/Modlishka) that transparently proxy the legitimate authentication service. These frameworks capture submitted credentials and session cookies in real time, enabling adversaries to bypass time-based MFA protections by harvesting authenticated session tokens rather than just static passwords. 

***

## Common Attachment File Types

The choice of attachment file type reflects a balance between plausibility for the targeted recipient and evasion of email security gateway inspection: 

- **Microsoft Office documents (.docx, .xlsx, .pptx):** Widely used given their ubiquity in business communications and strong contextual plausibility. For T1598.002, Office documents may contain embedded forms requesting credential entry, or VBA macros that launch browser windows directed at credential harvesting pages.
- **PDF documents:** Trusted by recipients as a standard business document format; PDFs can contain embedded links to credential harvesting pages and interactive form fields requesting credential submission. 
- **HTML attachments:** Increasingly favoured for HTML smuggling-based credential harvesting, as HTML files rendered locally bypass URL filtering while providing full visual fidelity for fake login portal rendering. 
- **Archive files (.zip, .rar):** Password-protected archives evade attachment sandboxing by preventing automated detonation, with the password provided in the email body. Archive contents may include HTML credential harvesting pages, Office documents, or other attachment types. 

***

## Procedure Examples

### Dragonfly (Energetic Bear)
**Dragonfly** used spearphishing emails with **Microsoft Office attachments** specifically to enable the harvesting of user credentials from targeted energy sector organisations.  The group's attachment-based campaigns were designed to elicit credential submission from recipients through document-embedded lures, with collected credentials subsequently used to facilitate persistent access to industrial control system environments. 

### SideCopy
**SideCopy** crafted generic spam campaign lures targeting large recipient populations, using attached documents to collect email addresses and credentials at scale for subsequent use in more targeted operations.  The group's approach demonstrates that spearphishing attachment techniques are applicable not only to precision individual targeting but also to mass credential harvesting campaigns where volume rather than precision is the primary collection objective. 

### Sidewinder
**Sidewinder** sent spearphishing emails containing malicious attachments that, upon interaction, redirected recipients to adversary-controlled credential harvesting websites.  The attachment served as a trusted-context delivery mechanism for the credential harvesting URL, with the document's content providing a plausible business pretext that increased the likelihood of the recipient following the embedded link to the harvesting page. 

### Star Blizzard (SEABORGIUM / Callisto Group)
**Star Blizzard** operationally integrated attachment-based spearphishing into a structured multi-stage engagement campaign. The group first established extended rapport with targets through legitimate-appearing email exchanges — sometimes over days or weeks — before eventually transitioning to messages containing attachments that included links to credential-stealing sites.  This rapport-building approach leverages the accumulated trust of an established correspondence to significantly lower the recipient's defensive threshold at the moment the malicious attachment is delivered. 

***

## Mitigations

### Email Authentication (MITRE M1054 – Software Configuration)
Implementing the full email authentication stack is the foundational technical control against attachment-based spearphishing delivered through spoofed sender identities: 

- **SPF:** Validates that inbound messages were sent from servers authorised by the sending domain's published SPF record, blocking spoofed messages from unauthorised infrastructure.
- **DKIM:** Cryptographically verifies message integrity, detecting modifications to email headers and body content including spoofed sender display names.
- **DMARC (p=reject):** Instructs receiving mail servers to reject messages that fail SPF and DKIM validation, providing the strongest available protection against domain spoofing. Configure with DMARC aggregate report monitoring through platforms such as [Dmarcian](https://dmarcian.com/) and [PowerDMARC](https://powerdmarc.com/) to identify legitimate mail flow gaps before enforcing `p=reject`.

### Attachment Sandboxing and Content Inspection
Deploy email security gateways with attachment sandboxing capabilities to automatically detonate suspicious attachments in an isolated environment before delivery, identifying malicious behaviour including HTML smuggling patterns and macro-triggered browser redirects.  Platforms including [Microsoft Defender for Office 365 Safe Attachments](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365), [Proofpoint Targeted Attack Protection](https://www.proofpoint.com/uk/products/advanced-threat-protection/targeted-attack-protection), and [Cofense PDC](https://cofense.com/product-services/phishing-detection-and-response/) provide real-time sandboxing and zero-day attachment detection. 

### User Training (MITRE M1017)
Security awareness training should specifically address attachment-based credential harvesting scenarios, including: 

- Recognition of requests to enter credentials into document-embedded forms or attached HTML files.
- Scepticism toward documents received from unknown senders requesting credential submission.
- Understanding that legitimate IT systems will not request credentials through email-delivered documents.
- Simulation campaigns using platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training) with attachment-themed phishing scenarios.

***

## Detection Strategy

### Email-Layer Detection

- **Sender validation monitoring:** Email security gateways should log and alert on all messages failing SPF and DKIM validation, with DMARC reporting providing aggregate data on spoofing attempts against the organisation's domains. 
- **Attachment type and content monitoring:** Implement email security gateway policies to block or sandbox high-risk attachment types commonly used in information elicitation campaigns, including HTML files, password-protected archives, and Office documents containing embedded forms or external link references. 
- **Bulk sender pattern detection:** Monitor for patterns consistent with credential harvesting campaigns, including multiple internal mailboxes receiving attachments from the same unknown external sender within a short time window, using **SIEM** correlation rules in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel). 

### Endpoint and Network Detection

- **Process network connection monitoring:** Monitor for browser and Office application processes initiating network connections to newly registered domains, low-reputation sites, or non-categorised external URLs following attachment opening events, using **Sysmon** Event ID 3 (Network Connection) and **EDR** telemetry from [CrowdStrike Falcon](https://www.crowdstrike.com/) and [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint).  Office application processes spawning browser processes or initiating direct outbound HTTP connections should be flagged as suspicious, as this behaviour pattern is characteristic of macro-triggered or embedded-link credential harvesting page redirects.
- **HTML smuggling detection:** Monitor for HTML attachments that, upon browser rendering, create and execute dynamically assembled payloads. **Microsoft Defender for Office 365** and network inspection tools can identify HTML smuggling patterns through analysis of attachment content structure and local JavaScript execution behaviour. 
- **Credential submission to non-corporate domains:** Deploy DNS-layer filtering through [Cisco Umbrella](https://umbrella.cisco.com/) and web proxy inspection through [Zscaler](https://www.zscaler.com/) to block access to adversary-controlled credential harvesting domains reached through attachment-embedded links, including real-time URL reputation assessment for links resolved during attachment interaction. 
- **Authentication anomaly correlation:** Correlate authentication events in **Entra ID** and VPN logs with attachment delivery and opening events, flagging credential submission activity to external sites that precedes anomalous login attempts from unexpected locations or devices as a high-confidence credential compromise indicator. 
