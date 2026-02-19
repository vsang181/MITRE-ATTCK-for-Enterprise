# Gather Victim Identity Information

Gather Victim Identity Information is a reconnaissance technique classified under **MITRE ATT&CK T1589** in which adversaries systematically collect identity-related data about individuals within a target organisation to support subsequent targeting, social engineering, and account compromise operations.  The scope of collectible identity intelligence is broad, encompassing personal identifiers such as employee names, corporate and personal email addresses, phone numbers, and security question responses, as well as highly sensitive operational data including account credentials, session tokens, and **multi-factor authentication (MFA)** configurations and enrolled methods. 

Identity intelligence is among the most operationally valuable categories of reconnaissance data, as it directly enables adversaries to impersonate legitimate users, bypass authentication controls, and craft contextually convincing social engineering campaigns.  Stolen identity data gathered during this phase can be leveraged to establish operational resources through **T1586 – Compromise Accounts**, and to achieve initial access via **T1566 – Phishing** or **T1078 – Valid Accounts**, bypassing perimeter technical controls entirely by authenticating as a legitimate user rather than exploiting a vulnerability.  Intelligence gathering may also reveal opportunities for further reconnaissance activities including **T1593 – Search Open Websites/Domains** and **T1598 – Phishing for Information**. 

***

## Collection Vectors

Adversaries employ a diverse range of active and passive methods to harvest victim identity information:

- **Authentication Service Probing and Username Enumeration:** Adversaries actively probe login portals, password reset flows, and identity federation endpoints to enumerate valid usernames. Many authentication systems inadvertently disclose username validity through differentiated error messages (e.g., returning "incorrect password" for valid usernames versus "user not found" for invalid ones), response timing discrepancies, or HTTP status code variations, all of which can be systematically exploited using tools such as [Burp Suite](https://portswigger.net/burp) and custom scripts to build a validated list of active accounts.  Additionally, Microsoft Azure AD / **Entra ID** exposes publicly queryable endpoints (e.g., the `GetCredentialType` API) that can be used to confirm whether a given email address corresponds to a valid account within a tenant and to enumerate the MFA methods associated with that account, without any authentication. 
- **Credential Repository Mining:** Adversaries source credentials from prior data breach dumps, paste sites, and dark web marketplaces. Repositories such as **RaidForums** successors, **BreachForums**, and infostealer malware log markets provide access to large volumes of username and password pairs, session cookies, and MFA bypass tokens harvested from previously compromised systems.  Tools such as [SpyCloud](https://spycloud.com/) and [Have I Been Pwned](https://haveibeenpwned.com/) are also used defensively to monitor for exposed organisational credentials. 
- **Phishing for Information (T1598):** Targeted spearphishing campaigns direct victims to adversary-controlled credential harvesting pages or solicit identity information directly through pretexted email, voice, or messaging channel communications.
- **OSINT Collection:** Social media platforms, particularly **LinkedIn**, **Twitter/X**, and **Facebook**, expose employee names, roles, contact details, and professional relationships that serve as foundational inputs for identity-targeted attack planning. Tools such as [theHarvester](https://github.com/laramies/theHarvester), [Hunter.io](https://hunter.io/), and [Maltego](https://www.maltego.com/) automate the collection and correlation of identity intelligence from open sources at scale.
- **Self-Service Password Reset (SSPR) Reconnaissance:** Adversaries probe SSPR workflows to validate whether specific email addresses or phone numbers are enrolled in identity recovery processes, confirming account existence and identifying potential SIM-swapping or social engineering attack vectors against identity recovery mechanisms. 

***

## Procedure Examples

### APT32 (OceanLotus)
**APT32**, a Vietnamese state-sponsored threat actor group, has conducted targeted surveillance operations against activists, journalists, and bloggers, collecting identity and personal data to facilitate long-term tracking, social engineering, and targeted malware deployment against individuals whose activities are considered politically sensitive.

### Contagious Interview
**Contagious Interview** is a North Korean-nexus campaign in which adversaries conduct detailed identity reconnaissance against professional communities, including software developers and cryptocurrency and blockchain technology professionals.  The group researches individual targets' professional backgrounds, skill sets, and employment histories to construct highly convincing fraudulent job offer lures delivered via LinkedIn and professional networking platforms. 

### FIN13 (Elephant Beetle)
**FIN13** is a financially motivated threat actor group primarily targeting Mexican financial institutions. The group has been observed conducting detailed employee research, identifying personnel in roles with access to financial systems and privileged credentials, to support precisely targeted social engineering and business email compromise campaigns. 

### HEXANE (Lyceum)
**HEXANE** is a threat actor group with a focus on targeting organisations in the oil and gas, telecommunications, and technology sectors across the Middle East and Africa. The group has conducted targeted individual identification operations within victim organisations, profiling specific employees to determine which individuals hold roles with access to critical infrastructure management systems. 

### LAPSUS$
**LAPSUS$** is a financially motivated extortion group known for conducting highly effective identity-centric intrusions against major technology and telecommunications organisations. The group gathered detailed personal and professional information about target employees to construct convincing social engineering narratives for help desk impersonation attacks, credential harvesting, and insider threat recruitment, publicly soliciting employees on Telegram and offering financial incentives in exchange for corporate credentials or VPN access. 

### Magic Hound (APT35 / Charming Kitten)
**Magic Hound** has been observed acquiring mobile phone numbers of identified target individuals, enabling follow-on operations including mobile-targeted phishing, SIM-swapping attacks against SMS-based MFA, and voice-based social engineering campaigns. 

### Operation Dream Job (Lazarus Group)
The **Lazarus Group's Operation Dream Job** campaign involved extensive identity reconnaissance against targeted individuals in the defence, aerospace, and cryptocurrency sectors, building detailed personal and professional profiles to craft highly believable fraudulent employment opportunity lures delivered across LinkedIn and WhatsApp. 

### Operation Wocao
During **Operation Wocao**, a Chinese state-sponsored campaign, threat actors specifically targeted individuals based on their organisational roles and the level of system privileges associated with their accounts, prioritising high-value targets such as system administrators, domain administrators, and security personnel to maximise post-compromise access. 

### Scattered Spider
**Scattered Spider** has operationally leveraged data obtained from prior breach dumps to enumerate employee names, phone numbers, and identity details, using this intelligence to navigate corporate IT help desk verification procedures during vishing-based MFA bypass and account takeover attacks.  The group's core operational philosophy centres on **"log in, not hack in"**, compromising legitimate user identities to circumvent technical perimeter controls rather than exploiting software vulnerabilities. 

### Star Blizzard (SEABORGIUM)
**Star Blizzard** is a Russian FSB-affiliated threat actor group conducting persistent spearphishing and credential harvesting operations against Western government, academic, and civil society targets. The group invests considerable effort in profiling targets' professional interests, personal connections, and social media activity to identify trusted relationships that can be impersonated and to craft highly credible and contextually relevant engagement lures. 

### Volt Typhoon
**Volt Typhoon** has conducted pre-compromise identity reconnaissance as part of its broader intelligence collection operations against critical national infrastructure targets, gathering employee identity details to support operational planning and potential social engineering vectors. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Identity reconnaissance operates primarily through passive OSINT collection, breach data repositories, and active probing of publicly accessible authentication services, placing it largely outside the effective reach of conventional enterprise perimeter controls.  Mitigation efforts should focus on reducing identity exposure and hardening authentication infrastructure against enumeration: 

- **Remediate username enumeration vulnerabilities:** Audit all public-facing authentication portals, password reset flows, and identity federation endpoints to ensure uniform, non-differentiating error responses that do not disclose account validity. Implement **account lockout and rate-limiting controls** on login and SSPR endpoints to impede automated enumeration attempts.
- **Restrict cloud identity enumeration endpoints:** Harden **Microsoft Entra ID** configurations to limit information exposed through the `GetCredentialType` and related unauthenticated API endpoints. Enable **Entra ID Identity Protection** to detect and alert on suspicious authentication probe patterns. 
- **Monitor and remediate credential exposure:** Subscribe to breach notification and credential monitoring services such as [SpyCloud](https://spycloud.com/), [Have I Been Pwned](https://haveibeenpwned.com/), and [Recorded Future Identity Intelligence](https://www.recordedfuture.com/solutions/identity-intelligence) to identify and force rotation of compromised organisational credentials before they can be operationally exploited.
- **Restrict public identity information exposure:** Audit employee LinkedIn profiles, corporate website staff directories, and press releases to minimise the volume of identity information available to adversaries. Implement clear policies governing the information employees may disclose on professional networking platforms.
- **Enforce phishing-resistant MFA:** Deploy **FIDO2/WebAuthn-based phishing-resistant MFA** (e.g., hardware security keys such as [YubiKey](https://www.yubico.com/)) across all critical accounts, replacing SMS-based OTP methods that are susceptible to SIM-swapping and social engineering bypass. 
- **Help desk identity verification hardening:** Implement robust identity verification procedures for IT help desk password reset and MFA re-enrolment requests, including out-of-band manager confirmation and callback verification to known, pre-registered phone numbers, directly addressing the social engineering vectors employed by groups such as **Scattered Spider** and **LAPSUS$**. 

***

## Detection Strategy

### Authentication Probing and Enumeration Detection

Monitor authentication infrastructure for patterns indicative of systematic identity enumeration activity. Key detection indicators include: 

- **High-frequency authentication requests** originating from a single source IP or narrow IP range against login portals, password reset endpoints, or identity API services, particularly where requests produce a high ratio of invalid account responses.
- **Sequential or pattern-based account probing**, consistent with automated username enumeration tools exploiting predictable corporate email address formats (e.g., `firstname.lastname@organisation.com`).
- **Anomalous SSPR activity**, including repeated self-service password reset initiation attempts from external IP addresses against multiple accounts within a short time window. 
- **Unusual MFA method enumeration**, including repeated queries to identity provider endpoints that expose enrolled MFA method information for given email addresses.

These patterns should be aggregated and correlated within a **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel), with source IPs enriched via threat intelligence services such as [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) to identify adversarial or botnet-associated infrastructure.

### Web Metadata and HTTP Traffic Analysis

Analyse inbound HTTP/S request metadata from public-facing authentication and web infrastructure, including `Referer` headers, `User-Agent` strings, and request timing patterns, to identify artefacts consistent with automated identity enumeration tooling or credential harvesting infrastructure.  Anomalous User-Agent strings, missing standard browser headers, and requests originating from hosting provider IP ranges or known VPN/proxy exit nodes warrant investigation. Integration of **Entra ID sign-in logs**, **Unified Audit Logs**, and **Identity Protection risk detections** into the centralised SIEM provides comprehensive visibility into cloud identity probing activity consistent with the enumeration behaviours documented across the threat actor groups profiled within this technique. 
