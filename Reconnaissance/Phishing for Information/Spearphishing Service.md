# Spearphishing Service

Spearphishing via Service is a sub-technique of Phishing for Information (**MITRE ATT&CK T1598.001**) in which adversaries conduct information elicitation and credential harvesting operations through third-party social media platforms, personal webmail services, instant messaging applications, and other non-enterprise controlled communication channels rather than through corporate email infrastructure.  This delivery vector provides adversaries with two compounding operational advantages over direct email-based phishing: third-party consumer services operate under significantly less strict security policies than enterprise environments — lacking the DMARC enforcement, URL detonation, and attachment sandboxing deployed on corporate email gateways — and messages arriving through social platforms carry an inherent familiarity and perceived personal relevance that reduces recipient scepticism. 

The objective is identical to the parent technique (**T1598**): eliciting sensitive information — most commonly credentials, OTP codes, and organisational intelligence — from targets through deception, rather than executing malicious code. The technique is distinct from **T1566.003 – Spearphishing via Service** (which targets initial access through malware delivery) in that T1598.001 is concerned exclusively with information gathering during the reconnaissance phase. 

***

## Operational Mechanics

Spearphishing via service operations typically follow a structured engagement lifecycle designed to progressively build sufficient trust to elicit the targeted information: 

1. **Platform and persona selection:** Adversaries select the third-party platform most likely to reach the target convincingly. LinkedIn is favoured for professional and job opportunity pretexts; WhatsApp and Telegram for impersonating colleagues or IT support; Twitter/X and Facebook for broader social engineering operations. Adversary-controlled personas are constructed with sufficient history and plausibility to withstand basic scrutiny by the target. 
2. **Initial contact and rapport building:** Adversaries initiate contact under a pretext relevant to the target's role and interests, such as a fake job opportunity, a shared professional interest, a vendor relationship, or an impersonation of a known colleague or IT staff member. Extended multi-message conversations are used to build trust before any elicitation or malicious content is introduced. 
3. **Information elicitation or credential capture:** Once sufficient rapport is established, the adversary introduces the targeted elicitation request — directly asking for credentials or sensitive information under a plausible pretext, directing the target to a credential harvesting page, or requesting details about organisational policies, systems, and infrastructure through questions that appear contextually appropriate within the established conversation. 
4. **Persistence and troubleshooting:** If the initial elicitation attempt fails, adversaries continue the conversation, troubleshoot the target's hesitation, and re-approach the elicitation from a different angle. This persistence capability — available because the communication is taking place on a platform the adversary controls — is a key tactical advantage over email-based delivery.
5. 
***

## Platform Categories

Adversaries exploit a broad range of third-party services as spearphishing delivery vectors: 

- **Professional social networks:** [LinkedIn](https://www.linkedin.com/) is the most widely exploited platform for job opportunity pretexts, enabling adversaries to identify and directly message high-value targets with personalised career-relevant lures. Lazarus Group's **Operation Dream Job** campaign relied extensively on LinkedIn to deliver fake job vacancy messages to targeted engineers and technical personnel. 
- **Consumer messaging applications:** [Telegram](https://telegram.org/), [WhatsApp](https://www.whatsapp.com/), and [Signal](https://signal.org/) are used for impersonation-based credential harvesting, particularly for IT support and helpdesk impersonation scenarios. **Scattered Spider** operationally used Telegram to send messages impersonating IT personnel during **C0027**, directing targets to credential harvesting infrastructure while appearing to operate within a legitimate internal support context. 
- **Personal webmail services:** [Gmail](https://gmail.com/), [Outlook.com](https://outlook.com/), and similar personal webmail platforms are used to reach targets on addresses that bypass corporate email security controls, often after establishing initial contact through a social platform and transitioning the conversation to webmail to deliver credential-capturing content. 
- **General social media platforms:** [Facebook](https://www.facebook.com/), [Twitter/X](https://twitter.com/), and [Instagram](https://www.instagram.com/) have been used by threat actors including **Dark Caracal** and **Magic Hound** for direct message-based social engineering, with the informal conversational context of social platforms reducing the target's defensive posture relative to email communications. 
- **Enterprise collaboration platforms:** [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/), [Slack](https://slack.com/), and similar collaboration tools represent an emerging and particularly effective delivery vector, as messages arriving through what appears to be a trusted internal or partner-connected workspace channel carry significantly elevated perceived legitimacy. **Storm-1811** has used Microsoft Teams to send messages and initiate voice calls impersonating IT support personnel, directly exploiting the trust assumptions associated with a seemingly internal communication channel. 
- **File sharing notification abuse:** **EXOTIC LILY** exploited the email notification features of legitimate file sharing services to deliver spearphishing messages, leveraging the trusted sender identity of platforms such as [WeTransfer](https://wetransfer.com/) and [SharePoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration) to bypass email security filtering applied to unknown senders. 

***

## Procedure Examples

### C0027 — Scattered Spider
**C0027** was a financially motivated campaign conducted by **Scattered Spider** (also tracked as **Roasted 0ktapus**, **Octo Tempest**, and **Storm-0875**) targeting telecommunications companies and business process outsourcing (BPO) organisations.  During the campaign, the group sent **Telegram messages impersonating IT personnel** to targeted employees, creating a pretext that simulated an internal IT support interaction and directing targets to adversary-controlled credential harvesting pages.  The combination of a familiar platform (Telegram), a plausible internal IT support pretext, and real-time adversary-in-the-middle session handling enabled the group to capture both credentials and OTP codes, defeating MFA protections in real time.  Scattered Spider subsequently used stolen SSO session cookies and OAuth tokens harvested through these operations to gain authenticated access to victim environments without requiring further authentication. 

### Operation Dream Job — Lazarus Group
During **Operation Dream Job**, Lazarus Group sent targeted spearphishing messages to selected individuals via **LinkedIn**, presenting fraudulent but highly convincing job vacancy announcements tailored to each recipient's specific technical expertise and career background.  The use of LinkedIn provided the campaign with built-in professional plausibility, as targets reasonably expected to receive recruitment-related contact through the platform. Malicious documents and links delivered through subsequent stages of the LinkedIn conversations exploited the trust established during the initial recruitment-framed contact. 
### Additional Group Examples
Numerous other threat actor groups have operationally adopted spearphishing via service as a component of their reconnaissance and initial access operations: 

- **APT29** used the legitimate mailing service **Constant Contact** to send phishing emails, leveraging the service's trusted sender reputation to bypass email filtering.
- **Magic Hound** used **LinkedIn** and **WhatsApp** for social engineering and credential harvesting against targeted individuals.
- **Moonstone Sleet** used social media services to spearphish victims and deliver trojaned software.
- **Dark Caracal** spearphished victims via **Facebook** and **WhatsApp**.
- **FIN6** sent fake job advertisements via **LinkedIn** to targeted individuals.

***

## Mitigations

### User Training (MITRE M1017)
Security awareness training is the primary available mitigation for spearphishing via service, as the delivery vectors involved operate entirely outside the organisation's technical control perimeter.  Effective training programmes should specifically address: 
- Recognition of social engineering lures delivered through non-email channels including LinkedIn messages, Telegram, and WhatsApp.
- Scepticism toward unsolicited contact from unknown individuals on social platforms, particularly communications that request credentials, system access details, or organisational information.
- Understanding that IT support, HR, and executive communications arriving through personal social media or messaging applications rather than official corporate channels should be independently verified through known-good contact methods before any information is provided.
- Specific training on fake job opportunity lures targeting technical and security-cleared personnel, given the prevalence of this vector in campaigns by Lazarus Group, FIN6, and Contagious Interview.

### Restrict Web-Based Content (MITRE M1021)
Organisations should evaluate whether access to specific social media and personal messaging platforms is operationally necessary for business functions, and consider applying content category filtering through web proxy platforms such as [Zscaler Internet Access](https://www.zscaler.com/products/zscaler-internet-access) and [Cisco Umbrella](https://umbrella.cisco.com/) to restrict access to platforms that cannot be adequately monitored and present significant spearphishing risk. 

### User Account Management (MITRE M1018)
Enforce strict management of third-party service accounts used for business purposes, ensuring accounts are configured with minimum necessary permissions and that access is regularly reviewed and revoked when no longer required. 

### Audit and Logging (MITRE M1047)
Implement auditing and logging for interactions with third-party messaging services and collaboration platforms integrated into corporate environments (e.g., Teams, Slack), monitoring user activity and reviewing logs for suspicious link sharing, file transfers, and external account interactions. 
***

## Detection Strategy

### Social Media and Third-Party Platform Monitoring

Third-party platform-delivered spearphishing largely occurs outside the visibility of corporate monitoring infrastructure, making direct detection highly challenging.  Available detection approaches include: 

- **Enterprise collaboration platform monitoring:** For spearphishing delivered through corporate-connected platforms such as **Microsoft Teams** and **Slack**, monitor audit logs for messages from external federated accounts, unexpected file sharing, and suspicious link delivery from unknown external parties using [Microsoft Purview Audit](https://learn.microsoft.com/en-us/purview/audit-solutions-overview) and [Microsoft Defender for Cloud Apps](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-cloud-apps). 
- **Social media threat monitoring:** Deploy social media monitoring services such as [ZeroFOX](https://www.zerofox.com/) and [Recorded Future Brand Intelligence](https://www.recordedfuture.com/) to identify adversary-controlled personas impersonating the organisation or its personnel on social platforms, enabling proactive takedown of fake accounts before they successfully elicit information from employees. 

### Network and Endpoint Detection

Where spearphishing via service leads to a target accessing a credential harvesting page or downloading a file through a social or messaging platform, the following detection controls can identify downstream artefacts: 

- **DNS and URL filtering:** DNS-layer filtering through [Cisco Umbrella](https://umbrella.cisco.com/) and web proxy inspection through [Zscaler](https://www.zscaler.com/) can block access to adversary-controlled credential harvesting domains reached through links delivered via third-party messaging platforms, including links expanded from URL shorteners.
- **Network anomaly detection:** Monitor for anomalous network flows originating from social media application processes or browser sessions, including connections to newly registered domains and low-reputation sites, using **SIEM** correlation in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel). 
- **Authentication anomaly detection:** Monitor identity platform authentication logs (Entra ID, Okta) for credential submissions and session token usage following patterns consistent with AiTM credential capture — particularly authentication events from unexpected geographic locations or IP addresses occurring immediately after the issuance of MFA codes, using **Entra ID Identity Protection** risk-based conditional access to flag and step-up anomalous authentication attempts. 
- **Detection pivot to Initial Access:** Given the limited direct visibility available during the reconnaissance delivery phase, correlate any downstream Initial Access indicators — including anomalous VPN authentications, unexpected SSO logins, and new device registrations — with prior social platform-based phishing activity identified through employee reporting or monitoring. 
