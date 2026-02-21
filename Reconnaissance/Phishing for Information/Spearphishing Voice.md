# Spearphishing Voice

Spearphishing Voice is a sub-technique of Phishing for Information (**MITRE ATT&CK T1598.004**) in which adversaries use voice communications — phone calls, VoIP sessions, automated robocalls, or callback phishing scenarios — to trick targets into voluntarily disclosing sensitive information, most commonly credentials, OTP codes, and organisational access details.  As with all T1598 sub-techniques, the objective is information elicitation rather than malware delivery, distinguishing it from the initial access counterpart **T1566.004** even though both employ voice-based social engineering. The technique is commonly referred to as **vishing** (voice phishing) and is operationally significant because human voice communication carries substantially higher perceived trust than email, with acoustic characteristics of a human voice — tone, confidence, urgency — significantly influencing how trustworthy a caller is perceived to be. 

Vishing is particularly effective because it operates in real time, enabling adversaries to dynamically adapt their approach, overcome hesitation, and respond to target questions in ways that static email phishing cannot.  Combined with prior reconnaissance intelligence from techniques including **T1591 – Gather Victim Org Information** and **T1589 – Gather Victim Identity Information**, adversaries can construct pretexts of sufficient specificity and contextual relevance to defeat even security-aware personnel. 

***

## Delivery Mechanisms

Adversaries implement voice-based spearphishing through several operationally distinct mechanisms: 

- **Direct manual vishing:** Adversaries personally call the target, impersonating a trusted entity — IT support, HR, a senior executive, a vendor, or a government agency — and socially engineer the target into disclosing credentials, OTP codes, or other actionable information in real time.
- **Callback phishing:** Adversaries send a phishing email or SMS directing the recipient to call a specific phone number, which is answered by the adversary or a hired call centre operating under a constructed pretext. By inducing the target to initiate the call, callback phishing exploits the target's inherent trust in a number they believe they have independently chosen to dial. 
- **VoIP-based scaled operations:** **Voice over IP (VoIP)** technology enables adversaries to generate thousands of phone numbers simultaneously, scale attack operations well beyond what manual calling supports, cycle numbers rapidly to circumvent blocked caller identification, and mask true geographic origin. 
- **Automated robocalls:** Pre-recorded automated voice messages impersonating banks, government agencies, and IT departments are used at scale to solicit target responses, with recorded answers harvested for account compromise. 
- **AI deepfake voice synthesis:** Adversaries increasingly use voice cloning and deepfake audio technology to generate convincing synthetic voices impersonating specific individuals — executives, IT administrators, colleagues — from short publicly available audio samples.  This capability eliminates the need for skilled human social engineers and enables highly convincing impersonation of individuals the target personally knows. **ReliaQuest** assesses that as **Scattered Spider** refines its operations, adoption of AI voice deepfake technology to impersonate employees and leadership roles represents a likely near-term operational evolution. 
- **Caller ID spoofing:** Adversaries manipulate caller ID to display the number of a trusted entity — the target's bank, their employer's IT helpdesk, a government agency, or a known colleague — making the call appear to originate from a legitimate source. 
- **MFA prompt manipulation:** Voice phishing is frequently combined with simultaneous credential submission attempts to trick targets into verbally confirming or reading back OTP codes or approving **MFA push notification prompts** generated in real time by the adversary as the call proceeds, defeating time-based MFA protections. 

***

## Procedure Examples

### Scattered Spider (C0027)
**Scattered Spider** is among the most prolific and operationally sophisticated practitioners of voice-based social engineering. During **C0027**, the group used phone calls impersonating legitimate IT personnel to instruct victims to navigate to credential-harvesting websites, combining caller ID spoofing with AiTM credential capture to defeat MFA in real time.  The group's approach to **IT helpdesk impersonation** is particularly well-documented: adversaries contact organisational helpdesks impersonating employees, providing PII and employee IDs obtained through prior OSINT reconnaissance to pass identity verification checks, then request MFA factor resets and password changes for targeted accounts.  **CrowdStrike** observed Scattered Spider using help desk voice-based phishing in **almost all observed 2025 incidents** to compromise **Microsoft Entra ID** and SSO environments.  The group's operationally demonstrated effectiveness — including the compromise of **MGM Resorts International** and **Caesars Entertainment** in 2023 — reflects the devastating access achievable through voice-based social engineering against helpdesk personnel. 

### LAPSUS$
**LAPSUS$** called victim organisations' IT help desks to convince support personnel to reset credentials for privileged accounts, exploiting the procedural willingness of helpdesk staff to assist callers who successfully passed identity verification challenges.  The group used PII harvested through prior reconnaissance to authenticate as the account holder during helpdesk calls, converting externally gathered identity intelligence into privileged account access through pure social engineering without any technical exploitation. 

### Salesforce Data Exfiltration (C0059)
During the **Salesforce Data Exfiltration** campaign, threat actors initiated voice calls with victims to socially engineer them into **authorising malicious OAuth applications** or divulging sensitive credentials, exploiting the real-time trust dynamics of voice communication to manipulate targets into taking specific technical actions within their own authenticated sessions. 

***

## Mitigations

### User Training (MITRE M1017)
Security awareness training is the primary available mitigation, as vishing operates entirely through human interaction channels that bypass technical email and network security controls.  Effective training programmes must specifically address: 

- Recognition of high-pressure urgency and authority manipulation tactics characteristic of vishing scenarios.
- Structured verification procedures: never disclosing credentials, OTP codes, or sensitive information to callers who initiate contact, regardless of apparent caller ID or claimed identity, before independently verifying the caller's identity through a separately obtained contact channel.
- Specific helpdesk and IT support policies requiring all personnel to escalate unexpected inbound requests for credential resets or MFA changes to a supervisor before processing, particularly when the request involves privileged accounts.
- Training targeting helpdesk and IT support staff with role-specific vishing simulation exercises, given their disproportionate exposure as primary targets for LAPSUS$-style and Scattered Spider-style helpdesk impersonation operations.

### Callback Verification Protocols
Organisations should implement and enforce **mandatory callback verification** policies for all helpdesk interactions involving credential resets, MFA changes, and access provisioning: before processing any such request, helpdesk staff should independently retrieve and call the requester's phone number from the verified corporate directory rather than trusting the number provided by the caller or the displayed caller ID.  This procedural control directly defeats caller ID spoofing-based helpdesk impersonation. 

### Phishing-Resistant MFA
Deploying **phishing-resistant MFA** methods — specifically **FIDO2/WebAuthn hardware security keys** (e.g., [YubiKey](https://www.yubico.com/), [Google Titan Key](https://store.google.com/gb/category/security-keys)) — provides a technical control that prevents OTP and push notification code disclosure through vishing, as FIDO2 authentication is cryptographically bound to the legitimate site's origin and cannot be replayed by an adversary even if the code is verbally disclosed by the target. 
***

## Detection Strategy

### Call Log Monitoring
Monitor corporate device call logs for calls to and from known malicious or suspicious phone numbers, using threat intelligence feeds that track phone numbers associated with vishing infrastructure.  Patterns of multiple employees receiving calls from the same external number within a short window — particularly if followed by anomalous authentication events — should be flagged as a potential vishing campaign indicator. 

### Helpdesk Anomaly Detection
Monitor IT helpdesk ticketing systems and call logs for anomalous patterns consistent with social engineering attempts: 

- High frequency of password reset and MFA factor change requests within a short period.
- Requests for privileged account credential resets from callers who cannot complete standard identity verification steps without escalating pressure or urgency.
- Requests initiated outside of normal business hours, exploiting reduced staffing and supervisory oversight.
- Multiple requests for the same account from callers claiming different identities or contact details.

### Authentication Event Correlation
Correlate helpdesk activity logs with **Entra ID** and VPN authentication events, flagging credential changes followed within minutes by authentication from unexpected geographic locations, previously unseen devices, or IP addresses associated with known VPN and proxy infrastructure.  Implement **Entra ID Identity Protection** risk-based conditional access to require step-up authentication for sessions evaluated as anomalous following recent credential modification events. Deploy **Microsoft Defender for Identity** alerts for unusual account modification patterns, including MFA method changes followed immediately by new device authentication, which is a high-confidence indicator of successful vishing-enabled account takeover. 
### AI Deepfake Voice Awareness
As AI deepfake voice technology becomes increasingly accessible, security awareness programmes and helpdesk verification protocols must evolve to treat voice alone as insufficient verification, regardless of how convincingly the caller sounds.  Implement procedural controls requiring multi-factor identity verification for all privileged access requests, combining voice interaction with independent verification through a separately authenticated channel — such as a verified email to the employee's corporate address or an SMS to their registered corporate device — before processing any sensitive request. 
