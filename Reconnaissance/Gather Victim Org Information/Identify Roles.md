# Identify Roles

Identify Roles is a sub-technique of Gather Victim Org Information (**MITRE ATT&CK T1591.004**) in which adversaries collect intelligence about the identities, titles, responsibilities, and access levels of personnel within a target organisation to support precision targeting.  Role intelligence is operationally valuable because it enables adversaries to identify not just who works at an organisation, but specifically which individuals hold the access rights, decision-making authority, or security awareness levels most relevant to the adversary's operational objectives — whether that is privileged system access, financial approval authority, or susceptibility to social engineering. 

Gathered role intelligence can directly inform further reconnaissance (e.g., **T1598 – Phishing for Information**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1585 – Establish Accounts**, **T1586 – Compromise Accounts**), and most critically, enable highly targeted initial access through **T1566 – Phishing**, where role-specific contextual detail transforms generic phishing lures into convincing, personalised spearphishing scenarios. 

***

## High-Value Role Categories

Adversaries prioritise specific personnel categories based on their operational objectives. The targeting landscape has evolved significantly, with adversaries increasingly distributing targeting across all organisational levels rather than concentrating exclusively on executives: 

| Role Category | Why Targeted | Common Attack Vectors |
|---|---|---|
| **C-Suite Executives (CEO, CFO, COO)** | Authority over financial approvals, strategic data, and organisational decision-making; impersonation enables business email compromise (BEC) fraud | Spearphishing, whaling, deepfake voice/video social engineering, fake social media profile impersonation |
| **IT Administrators and Network Staff** | Privileged access credentials, system configuration rights, and visibility into the entire network environment | Credential theft phishing, helpdesk impersonation, adversary-in-the-middle attacks targeting admin login sessions |
| **Security and SOC Personnel** | Knowledge of defensive tool configurations, detection capabilities, and monitoring coverage gaps enables evasion planning | Targeting for intelligence gathering rather than direct compromise; impersonation of security vendors |
| **Finance and Accounts Payable** | Authority to initiate financial transfers; targeted for BEC fraud and invoice manipulation | CFO impersonation phishing, fraudulent wire transfer requests, supplier invoice fraud |
| **Human Resources Personnel** | Access to employee personally identifiable information (PII), payroll systems, and new-hire credential issuance processes | Targeting for PII exfiltration; impersonation to request credential resets or payroll redirection |
| **Engineers and Technical Operations Staff** | Access to industrial control systems (ICS), operational technology (OT), and critical technical infrastructure | Engineering-themed spearphishing lures, fake resume documents, technical job posting impersonation |
| **Contractors and Temporary Staff** | Variable security training levels, limited organisational loyalty, often excluded from security awareness programmes, and may retain access beyond operational need | Social engineering via professional networking platforms, credential phishing |

***

## Collection Vectors

Adversaries use a broad range of passive and active methods to enumerate individual roles and identities within target organisations:

- **LinkedIn and Professional Networks:** LinkedIn is the primary and most operationally direct source of role intelligence, with employees routinely publishing their job title, department, specific responsibilities, technology certifications, project experience, and direct reporting relationships on publicly accessible profiles.  Role-specific searches on LinkedIn (e.g., filtering by company and job title) enable adversaries to build comprehensive inventories of personnel by function, access level, and seniority without any interaction with the target organisation's infrastructure. 
- **Corporate Websites and Leadership Pages:** Corporate websites routinely publish executive leadership biographies, board of director listings, and key personnel profiles with names, titles, and in many cases direct contact details, providing adversaries with a directly accessible starting point for high-value personnel identification. 
- **Job Postings:** Employment advertisements disclose role responsibilities, required access levels, technology platforms used, and specific system permissions associated with advertised positions. Security operations, IT administration, and privileged access management job postings are particularly rich sources of role and access level intelligence. 
- **Conference Speakers and Industry Publications:** Personnel who present at security conferences, author industry publications, or participate in public webinars inadvertently confirm their specific roles and responsibilities, technology expertise, and the platforms their organisations deploy.
- **Social Media Activity Analysis:** Employee posts on platforms including Twitter/X and LinkedIn can reveal role-specific project involvement, system access, team structure, and operational responsibilities through professional updates, project announcements, and peer interactions.
- **Phishing for Information (T1598):** Adversaries may directly elicit role and personnel information through targeted social engineering, impersonating HR departments, IT support, or external recruiters to extract organisational chart details and key personnel contact information.

***

## Procedure Examples

### FIN7 (Carbanak)
**FIN7** specifically targeted its role intelligence collection toward **IT staff and employees with elevated administrative rights**, building inventories of privileged personnel whose credentials, if compromised, would provide broad access to financial systems and point-of-sale infrastructure.  FIN7 used this targeting intelligence to focus spearphishing campaigns on the specific individuals whose compromise would yield the most operationally valuable access, maximising the return on intrusion operations against retail and hospitality targets. 
### HEXANE (Lyceum)
**HEXANE** conducted structured role enumeration targeting **executives, HR staff, and IT personnel** within victim organisations across the energy and telecommunications sectors.  By identifying the specific individuals occupying these high-value roles, HEXANE was able to construct highly personalised spearphishing lures tailored to each recipient's specific responsibilities, increasing the plausibility and delivery success rate of initial access campaigns against critical infrastructure targets. 

### LAPSUS$
**LAPSUS$** gathered exceptionally detailed intelligence about the internal team structures of targeted organisations, mapping departmental hierarchies, identifying personnel with privileged access to source code repositories and credential management systems, and targeting IT helpdesk staff whose procedures for identity verification could be exploited through social engineering to obtain credential resets for high-value accounts.  The group's role intelligence enabled it to identify and directly contact specific individuals within target organisations through messaging platforms, impersonating colleagues and internal IT staff to manipulate them into providing access credentials. 

### Operation Dream Job (Lazarus Group)
During **Operation Dream Job**, Lazarus Group conducted precise individual-level role targeting, identifying **specific personnel within organisations** and delivering tailored fraudulent job vacancy announcements customised to each target's specific role, career level, and technology expertise.  This technique transformed generic recruitment-themed phishing into highly personalised career-relevant lures, dramatically increasing engagement rates with malicious attachments and links by ensuring the content was directly relevant to each recipient's current professional circumstances. 
### Volt Typhoon
**Volt Typhoon** specifically identified key **network and IT staff members** within target organisations as part of its extensive pre-compromise reconnaissance, building profiles of the specific personnel responsible for managing the network infrastructure it intended to exploit.  This intelligence directly informed the group's operational approach, enabling it to anticipate the detection and response capabilities of identified security personnel and to tailor its LotL-based operational tradecraft to evade the specific tools and monitoring capabilities in use at each targeted organisation. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Role identification reconnaissance operates predominantly through passive OSINT collection against publicly accessible data sources, placing collection activity entirely outside the reach of conventional enterprise network controls.  Mitigation efforts should focus on limiting the role intelligence available to adversaries and hardening high-value personnel against the targeted attack vectors that this intelligence enables: 

- **Restrict granular role disclosure in public profiles:** Implement guidance for employees on the level of access-related detail appropriate for public professional profiles, discouraging the publication of specific system access rights, privileged role names, and technology certification details that confirm administrative access levels. 
- **Role-stratified security awareness training:** Deliver role-specific security awareness training calibrated to the attack vectors relevant to each personnel category, using platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training). Provide specialised training for identified high-value role categories including finance, IT administration, and executive assistants, rather than delivering uniform baseline training across all staff levels. 
- **Implement privileged access protections for identified high-value roles:** Apply enhanced access controls for personnel in roles identified as high-value targeting categories, including **Privileged Access Workstations (PAWs)** for IT administrators, phishing-resistant **FIDO2/WebAuthn MFA** for all privileged accounts, and **Just-in-Time (JIT)** privileged access policies using platforms such as [Microsoft Entra Privileged Identity Management (PIM)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id-governance) to limit persistent privileged access exposure. 
- **Executive and VIP protection programmes:** Implement dedicated cyber protection measures for identified executive and high-value personnel including social media impersonation monitoring through services such as [ZeroFOX](https://www.zerofox.com/) and [Recorded Future Identity Intelligence](https://www.recordedfuture.com/), regular credential exposure monitoring, and executive-specific phishing simulation exercises to maintain elevated security awareness among the personnel most frequently targeted on the basis of role identification. 

***

## Detection Strategy

### Passive Collection Visibility Limitations

Role identification conducted through passive OSINT collection against LinkedIn, corporate websites, job postings, and professional publications generates no observable artefacts within the target organisation's IT infrastructure.  Direct detection of this reconnaissance activity is therefore largely infeasible through conventional monitoring controls. 
### Downstream Targeted Attack Detection

Detection resources yield the highest operational value when focused on the **Initial Access** and **Credential Access** stages at which collected role intelligence is applied:

- **Role-aware email security monitoring:** Configure email security gateways including [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) and [Proofpoint Email Protection](https://www.proofpoint.com/uk/products/email-security-and-protection) with detection rules that apply elevated scrutiny to inbound emails targeting identified high-value role categories including finance approvers, IT administrators, and executive assistants, given that role intelligence directly informs adversarial targeting of these personnel. 
- **IT helpdesk identity verification monitoring:** Implement and enforce structured identity verification protocols for all helpdesk requests involving credential resets and access provisioning for privileged accounts, and monitor for social engineering patterns characteristic of LAPSUS$-style helpdesk manipulation, including unusual escalation requests, pressure-based urgency, and out-of-band contact methods. 
- **Web scraping and profile enumeration detection:** Monitor corporate website analytics for automated scraping patterns including high-frequency sequential page requests, non-human user-agent strings, and systematic traversal of staff directory and leadership pages consistent with bulk personnel enumeration, triggering CAPTCHA enforcement or rate limiting on identified automated access attempts. 
