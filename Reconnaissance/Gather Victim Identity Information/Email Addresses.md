# Email Addresses

Email address harvesting is a sub-technique of Gather Victim Identity Information (**MITRE ATT&CK T1589.002**) in which adversaries enumerate and collect corporate and personal email addresses associated with target personnel to support spearphishing campaigns, credential attacks, and social engineering operations.  Email addresses represent one of the most readily accessible categories of identity intelligence, as organisations routinely expose staff contact details through public-facing websites, social media profiles, press releases, marketing materials, and conference registrations, making large-scale harvesting achievable with minimal technical effort. 

Valid email addresses directly enable the establishment of operational resources through **T1586.002 – Compromise Email Accounts**, and support initial access via **T1566 – Phishing** and brute force operations against **T1133 – External Remote Services**.  They additionally serve as inputs for further reconnaissance activities including **T1593 – Search Open Websites/Domains** and **T1598 – Phishing for Information**, and can be used to derive additional identity intelligence such as employee names, organisational structure, and email address format conventions that can be extended to enumerate further valid accounts. 

***

## Collection Vectors

Adversaries employ a broad range of passive and active methods to enumerate and validate email addresses associated with target organisations:

- **OSINT and Search Engine Dorking:** Public search engines can be queried using advanced operators to surface email addresses indexed from corporate websites, academic publications, conference proceedings, and publicly available documents. Google Dorking techniques such as `site:targetorg.com "@targetorg.com" filetype:pdf` can efficiently extract email addresses from publicly accessible documents. Dedicated OSINT frameworks including [theHarvester](https://github.com/laramies/theHarvester) automate email address harvesting across multiple sources simultaneously, including search engines (Google, Bing, DuckDuckGo), PGP keyservers, and DNS records, capable of returning thousands of email addresses and associated hostnames from a single domain query. 
- **Commercial Email Discovery Platforms:** Services such as [Hunter.io](https://hunter.io/), [Phonebook.cz](https://phonebook.cz/), and [Skrapp.io](https://www.skrapp.io/) provide searchable databases of email addresses indexed from public web sources, enabling adversaries to enumerate likely valid addresses and identify corporate email format conventions (e.g., `firstname.lastname@organisation.com`) with minimal effort. 
- **Social Media Enumeration:** Professional networking platforms, particularly **LinkedIn**, frequently expose work and personal email addresses directly on user profiles or allow them to be inferred from publicly visible naming conventions. Tools such as [Maltego](https://www.maltego.com/) and [SpiderFoot](https://www.spiderfoot.net/) can automate the correlation of social media profile data with email address derivation at scale.
- **Microsoft Office 365 and Entra ID API Enumeration:** A significant and technically noteworthy active enumeration vector involves the exploitation of publicly accessible **Microsoft identity platform API endpoints**. The `GetCredentialType` API endpoint (`https://login.microsoftonline.com/common/GetCredentialType`) accepts a POST request containing an email address and returns an `IfExistsResult` field indicating whether the account exists within the tenant, without requiring any authentication.  A response value of `0` confirms a valid account, while `1` indicates the account does not exist, enabling adversaries to validate email address lists against Office 365 tenants at scale programmatically.  Additionally, the **Exchange Online AutoDiscover** service endpoint (`https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc`) can be queried to confirm tenant email infrastructure and validate specific addresses without authentication.  The **AADInternals** PowerShell toolkit (`Invoke-AADIntUserEnumerationAsOutsider`) operationalises these enumeration methods, supporting three distinct enumeration modes: Normal (via `GetCredentialType`), Login (via sign-in attempts, which are logged), and Autologon (via the autologon endpoint, which is notably not logged to Entra ID sign-in logs). 
- **Website Contact Forms and Staff Directories:** Adversaries such as **EXOTIC LILY** have been observed submitting targeted queries through website contact forms and mining publicly accessible staff directory pages to enumerate individual employee email addresses without triggering any authentication-level detection. [attack.mitre]
- **Breach Dump and Dark Web Repositories:** Previously breached email addresses associated with the target organisation's domain are recoverable from breach dump aggregators, paste sites, and dark web marketplaces, providing validated email address lists without any active probing of the target environment.
- **Thread Hijacking and Previously Infected Host Data:** Groups such as **TA551** have harvested email addresses directly from the mail clients of previously compromised hosts, extracting contact lists and email thread histories to enable highly convincing thread-spoofed spearphishing campaigns against the victim's known contacts.

***

## Procedure Examples

### AADInternals
**AADInternals** is an open-source PowerShell-based toolkit developed for Microsoft Azure AD and Office 365 administration and security research. The tool operationalises the publicly accessible Microsoft `GetCredentialType` and AutoDiscover API endpoints to enumerate valid user email addresses and accounts within an Entra ID tenant without authentication, providing three distinct enumeration methods with varying levels of detection visibility within Entra ID sign-in logs. 

### APT32 (OceanLotus)
**APT32** is a Vietnamese state-sponsored threat actor group that has conducted targeted email address collection operations against activists, journalists, and bloggers, harvesting personal and professional email addresses to facilitate long-term surveillance and targeted spyware deployment campaigns against politically sensitive individuals. 

### EXOTIC LILY
**EXOTIC LILY** is an initial access broker (IAB) with assessed ties to the **FIN12** ransomware group. The group has demonstrated a methodical approach to email address harvesting, combining open-source research with direct engagement through corporate website contact forms to collect targeted individuals' email addresses ahead of highly personalised spearphishing campaigns impersonating legitimate business entities. 

### HAFNIUM
**HAFNIUM** systematically collected email addresses for specifically targeted users as part of its pre-exploitation reconnaissance operations, using harvested addresses to scope and direct its **ProxyLogon** exploitation campaigns against on-premises Microsoft Exchange Server deployments. 

### HEXANE (Lyceum)
**HEXANE** conducted targeted email address enumeration with a deliberate focus on specific high-value personnel roles, including **executives**, **human resources staff**, and **IT administrators**, at organisations within the oil and gas and telecommunications sectors, directing spearphishing operations precisely at individuals with privileged access or the authority to approve financial transactions. 

### Kimsuky
**Kimsuky** is a North Korean state-sponsored APT group conducting cyber espionage operations against South Korean government, academic, and think tank targets. The group has collected both corporate and personal email addresses of targets, using personal accounts as alternative spearphishing vectors when corporate email security controls present higher detection risk. 

### LAPSUS$
**LAPSUS$** gathered employee email addresses through a combination of OSINT research, breach dump mining, and insider contact, including personal account addresses, to support multi-channel social engineering operations and initial access efforts. 

### Lazarus Group
**Lazarus Group** conducted structured email address collection operations across multiple departments of targeted organisations, building comprehensive per-department contact lists that were subsequently used to launch coordinated, departmentally contextualised spearphishing campaigns. 

### Magic Hound (APT35 / Charming Kitten)
**Magic Hound** has operationally prioritised the identification and targeting of high-value email accounts belonging to individuals in academia, journalism, non-governmental organisations (NGOs), foreign policy institutions, and national security roles, conducting email address harvesting as a direct precursor to credential phishing operations. 

### Moonstone Sleet
**Moonstone Sleet** is a North Korean threat actor group that gathered victim email addresses as foundational intelligence for follow-on phishing and social engineering activity, targeting individuals in the defence, technology, and cryptocurrency sectors. 

### Quad7 Activity
**Quad7 Activity** gathered targeted individuals' email addresses specifically to support **password spraying** operations against Microsoft 365 and other cloud identity services, validating email addresses against authentication endpoints prior to launching low-and-slow credential attack campaigns. 

### Saint Bear
**Saint Bear** is a threat actor group associated with pro-Russian cyber operations that gathered victim email address information as preparatory intelligence ahead of targeted phishing campaigns against Ukrainian and Eastern European government and civil society organisations. 

### Sandworm Team
**Sandworm Team** conducted open-source research to enumerate valid email addresses within target organisations, subsequently using harvested addresses as delivery vectors for targeted spearphishing campaigns supporting its destructive attack operations. 

### Silent Librarian (TA407 / COBALT DICKENS)
**Silent Librarian** is an Iranian threat actor group attributed to the **Mabna Institute**, conducting systematic academic credential theft operations. The group harvested email addresses from targeted universities and research institutions through open internet searches, using collected addresses to deliver credential harvesting phishing pages impersonating university library login portals. 

### TA551 (Shathak)
**TA551** harvested email addresses and full email thread content from previously infected hosts, using this intelligence to conduct **thread hijacking attacks** in which legitimate email reply chains were spoofed to deliver malware to the original correspondents, significantly increasing the believability and success rate of phishing delivery. 

### Volt Typhoon
**Volt Typhoon** specifically targeted the **personal email addresses** of key network and IT staff at victim organisations, prioritising personal accounts as phishing and social engineering vectors in recognition that personal email accounts typically operate with weaker security controls and monitoring coverage than corporate accounts. 

### Water Curupira Pikabot Distribution
**Water Curupira** leveraged harvested email address and thread data to conduct **thread spoofing** operations, injecting **Pikabot** malware delivery messages into the reply chains of existing legitimate email conversations to maximise the perceived legitimacy and delivery success rate of their spearphishing campaigns. [attack.mitre]

***

## Mitigations: Pre-Compromise (MITRE M1056)

Email address harvesting operates predominantly through passive OSINT collection and unauthenticated API enumeration against publicly accessible infrastructure, limiting the effectiveness of conventional enterprise controls in preventing the collection activity itself.  Mitigation efforts should focus on reducing email address exposure and hardening identity infrastructure against enumeration: 

- **Minimise public email address exposure:** Implement a policy of limiting the direct publication of employee email addresses on public-facing websites, preferring generic role-based contact addresses (e.g., `contact@organisation.com`) over individual named addresses. Where individual addresses must be published, consider using web forms in place of mailto links to reduce automated harvesting effectiveness.
- **Harden Microsoft Entra ID against unauthenticated enumeration:** Implement **Entra ID Conditional Access policies** and configure tenant settings to restrict or monitor access to the `GetCredentialType` API endpoint. Enable [Entra ID Identity Protection](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection) to detect and respond to suspicious enumeration activity, and consider enabling **login-based enumeration logging** to ensure that autologon-based enumeration attempts are captured within audit logs. 
- **Deploy email security and anti-spoofing controls:** Enforce the full **SPF**, **DKIM**, and **DMARC** email authentication stack to prevent adversaries from spoofing harvested email addresses in follow-on phishing campaigns. Email security gateways such as [Proofpoint Email Security](https://www.proofpoint.com/uk/products/email-security-and-protection), [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365), and [Mimecast](https://www.mimecast.com/) provide additional phishing detection and thread hijacking protection capabilities.
- **Monitor breach exposure:** Subscribe to enterprise email breach monitoring services such as [Have I Been Pwned Enterprise](https://haveibeenpwned.com/API/Key) and [SpyCloud](https://spycloud.com/) to identify organisational email addresses exposed in data breaches and enforce targeted credential resets for affected accounts before they can be operationally exploited.
- **Security awareness training:** Educate employees on the risks of publishing personal and corporate email addresses on public platforms and professional networking sites. Platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training) provide structured training programmes covering phishing recognition and information hygiene.

***

## Detection Strategy

### Authentication Probe and Enumeration Detection

The most detectable phase of email address harvesting activity occurs when adversaries actively enumerate addresses against authentication service endpoints.  Authentication infrastructure logs, including **Entra ID sign-in logs**, **Unified Audit Logs**, and **Exchange Online AutoDiscover request logs**, should be centralised within a **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) and monitored for the following indicators: 

- **High-frequency unauthenticated requests** to the `GetCredentialType` API endpoint from a single external IP address or narrow IP range, consistent with automated email address validation tooling. 
- **Large volumes of sequential authentication attempts** against multiple distinct email addresses from a single source, characteristic of password spraying operations conducted subsequent to email enumeration. 
- **Anomalous AutoDiscover service queries** from external IP ranges with no prior interaction history, potentially indicative of email infrastructure enumeration activity.

### Web Traffic Metadata Analysis

Inbound HTTP/S request metadata from public-facing web infrastructure, including `Referer` headers, `User-Agent` strings, and request frequency patterns, should be analysed for artefacts consistent with automated email harvesting tool activity.  Anomalous `User-Agent` strings associated with known harvesting tools, including [theHarvester](https://github.com/laramies/theHarvester) and similar frameworks, high-frequency crawling of staff directory pages, and bulk form submission patterns should be flagged and investigated. Threat intelligence enrichment of source IPs via [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) can assist in assessing whether observed enumeration activity originates from known adversarial or botnet infrastructure. 
