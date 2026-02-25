# WHOIS

WHOIS is a sub-technique of Search Open Technical Databases (**MITRE ATT&CK T1596.002**) in which adversaries query the publicly accessible WHOIS registration databases maintained by **Regional Internet Registries (RIRs)** and domain registrars to gather intelligence about target organisations' domain registrations, IP address block allocations, and administrative contact details.  WHOIS is one of the most foundational open-source reconnaissance data sources available, providing structured, authoritative, and freely accessible data directly from the organisations responsible for allocating and managing internet resources — the five RIRs being **ARIN** (Americas), **RIPE NCC** (Europe, Middle East, Central Asia), **APNIC** (Asia-Pacific), **AFRINIC** (Africa), and **LACNIC** (Latin America and Caribbean). 

Intelligence gathered through WHOIS can directly inform further reconnaissance (e.g., **T1595 – Active Scanning**, **T1598 – Phishing for Information**), support resource development (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and enable initial access via **T1133 – External Remote Services** and **T1199 – Trusted Relationship**.

***

## WHOIS Data Categories and Adversarial Intelligence Value

WHOIS records expose two distinct categories of registrations — **domain name registrations** and **IP address block allocations** — each providing different categories of adversarially relevant intelligence: 

### Domain Name WHOIS Records

Domain WHOIS records are maintained by individual registrars (e.g., [Namecheap](https://www.namecheap.com/), [GoDaddy](https://www.godaddy.com/), [Cloudflare Registrar](https://www.cloudflare.com/en-gb/products/registrar/)) and queried through the authoritative WHOIS server for each top-level domain (TLD). The intelligence exposed includes:

- **Registrant contact information:** Where WHOIS privacy protection is not enabled, the registrant's name, organisation, address, email address, and phone number are published publicly. This data directly enables construction of social engineering pretexts, spearphishing targeting, and vishing campaigns against the identified contact personnel. 
- **Registration and expiry dates:** Domain creation and expiry dates reveal the organisation's registration history. Critically, **domain expiry dates** enable adversaries to monitor for registration lapses — if an organisational domain is allowed to expire, it becomes immediately available for adversary registration, enabling **domain hijacking** and highly convincing phishing infrastructure under a domain the target's own employees and partners recognise and trust. 
- **DNS nameserver assignments:** WHOIS records expose the authoritative nameservers assigned to the domain, identifying the DNS hosting provider and enabling targeted investigation of the nameserver infrastructure. Shared nameserver relationships across multiple domains can reveal infrastructure clustering patterns and undisclosed business relationships. 
- **Registrar details:** The registrar through which a domain is registered is disclosed, potentially revealing account management procedures and registrar-specific security weaknesses relevant to domain hijacking attacks targeting the registrar's authentication controls. 
- **Domain status codes:** WHOIS status codes (e.g., `clientTransferProhibited`, `clientDeleteProhibited`) reveal the domain's transfer lock status, informing adversary assessment of domain hijacking feasibility through registrar account compromise. 

### IP Address Block WHOIS Records (RDAP)

IP address block WHOIS records — increasingly served through the modern **RDAP (Registration Data Access Protocol)** standard — are maintained by RIRs and disclose: 

- **IP address block assignments:** The specific CIDR blocks assigned to the organisation, providing a definitive and authoritative mapping of IP address ranges to identify for active scanning (**T1595**) and targeted exploitation. Querying RIR WHOIS databases by organisation name reveals all IP blocks assigned to the organisation globally.
- **Network name and organisation details:** The registered organisation name, address, and abuse contact details associated with each IP block.
- **Autonomous System Number (ASN) assignments:** The ASN(s) allocated to the organisation, enabling BGP routing analysis and comprehensive IP range enumeration by querying all prefixes announced from the organisation's ASN.
- **Point of Contact (PoC) records:** Technical and administrative contacts associated with the network registration, potentially exposing additional personnel details for social engineering targeting.

***

## WHOIS Query Methods and Tools

Adversaries can conduct WHOIS reconnaissance through multiple interfaces: 

- **Command-line `whois` utility:** The standard `whois` command is available natively on Linux and macOS systems and through the Windows Subsystem for Linux (WSL), enabling direct command-line WHOIS queries against target domains and IP addresses. Example: `whois example.com` or `whois 203.0.113.0`.
- **Online WHOIS portals:** Freely accessible web-based WHOIS lookup tools including [who.is](https://who.is/), [ICANN WHOIS Lookup](https://lookup.icann.org/), [ARIN WHOIS](https://search.arin.net/), and [RIPE NCC WHOIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris) provide browser-accessible WHOIS query interfaces requiring no technical tooling. 
- **Commercial WHOIS intelligence platforms:** [DomainTools](https://www.domaintools.com/) and [SecurityTrails](https://securitytrails.com/) provide enhanced WHOIS intelligence including **historical WHOIS data** showing previous registration details, **reverse WHOIS search** enabling queries by registrant email or organisation name to discover all domains registered by the same entity, and **WHOIS change monitoring** alerting on registration detail modifications. These capabilities significantly extend the adversarial utility of WHOIS beyond point-in-time queries. 
- **RDAP (Registration Data Access Protocol):** The modern replacement for the legacy WHOIS protocol, providing structured JSON-format responses through standardised HTTPS queries. RDAP is increasingly adopted by RIRs and registries, with ICANN mandating RDAP support for gTLD registries. 
- **Bulk domain registration analysis tools:** Adversaries investigating a target organisation's complete domain registration estate use automated WHOIS enumeration tools to systematically query all identified domains and subdomains, building a comprehensive map of the organisation's domain portfolio and revealing unregistered sister domains vulnerable to adversary registration. 

***

## GDPR Impact on WHOIS Data Availability

The **General Data Protection Regulation (GDPR)**, enforced from May 2018, fundamentally altered the availability of personal registrant data in domain WHOIS records for European registrants.  ICANN's GDPR-compliant WHOIS policy requires registrars to redact personal data fields — including registrant name, email address, phone number, and physical address — from publicly accessible WHOIS responses for natural persons. Registrar privacy protection services (e.g., [Namecheap WhoisGuard](https://www.namecheap.com/security/whoisguard/), [Cloudflare WHOIS Privacy](https://www.cloudflare.com/en-gb/products/registrar/)) further mask registrant identity behind proxy registrar details for both personal and corporate registrations. 

However, the operational impact of GDPR-based WHOIS redaction on adversarial reconnaissance is limited in practice: 

- **IP block WHOIS records remain fully unredacted:** RIR WHOIS records for IP address block allocations are not subject to GDPR redaction, as they relate to organisational rather than personal registrations. The full IP block allocation data — including organisation name, contact details, and address — remains publicly accessible.
- **Historical WHOIS data persists in commercial platforms:** WHOIS intelligence platforms including [DomainTools](https://www.domaintools.com/) captured and stored registrant data prior to GDPR enforcement, making pre-2018 personal registrant details retrievable through historical WHOIS queries even where current records are redacted.
- **Corporate registrations remain largely unredacted:** WHOIS privacy protections applied to domains registered by organisations (rather than individuals) do not qualify for GDPR-based personal data redaction, meaning corporate domain registrations continue to expose organisation name, address, and abuse contact details.
- **Reverse WHOIS correlation:** Commercial platforms enabling reverse WHOIS queries by email domain pattern (e.g., searching for all domains registered using `@example.com` email addresses) can identify organisational registrations even where individual registrant names are redacted, by querying on the registrant email domain rather than the personal name field.

***

## Mitigations: Pre-Compromise (MITRE M1056)

WHOIS reconnaissance is conducted entirely through queries to external RIR and registrar databases, generating no artefacts within the target organisation's infrastructure.  Mitigation efforts should focus on reducing the quality of intelligence available through WHOIS and hardening the domain registration estate against the threats that WHOIS intelligence enables: 

- **Enable WHOIS privacy protection:** Enable registrar WHOIS privacy protection services for all organisational domain registrations to mask personal registrant contact details behind registrar proxy information, reducing the social engineering intelligence available through domain WHOIS queries. 
- **Implement domain transfer locks:** Enable all available registrar-level domain transfer and deletion locks (`clientTransferProhibited`, `clientDeleteProhibited`, `clientUpdateProhibited`) across all organisational domain registrations, preventing domain hijacking through registrar account compromise.
- **Domain expiry monitoring and auto-renewal:** Implement automated domain renewal and active monitoring of expiry dates across the entire organisational domain portfolio using registrar management platforms, preventing domain lapse and adversary registration of expired organisational domains.  Treat domain expiry monitoring as a critical operational security function rather than a routine administrative task, given the extremely high-impact consequence of an expired organisational domain being registered by an adversary for phishing infrastructure. 
- **Register defensive domain variants:** Proactively register common typosquatting variants, alternative TLD versions, and hyphenated variants of primary organisational domains to prevent adversaries from using WHOIS data about the organisation's registered domains to identify and register unregistered lookalike domains for phishing campaigns. 
- **Minimise IP block exposure:** Where operationally feasible, consider the intelligence exposure implications of IP block registration granularity in RIR WHOIS records, noting that IP blocks registered to the organisation's legal name directly map organisational identity to network infrastructure.

***

## Detection Strategy

### Complete Passive Collection Opacity

WHOIS reconnaissance queries are directed at RIR and registrar databases, not at the target organisation's own infrastructure, and generate no observable artefacts within the target's network or endpoint monitoring environment.  Direct detection of this activity is entirely infeasible. 

### Proactive WHOIS Posture Assessment and Downstream Threat Detection

- **Proactive WHOIS self-assessment:** Regularly query WHOIS databases for all organisational domains and IP blocks from the adversary's perspective, verifying that WHOIS privacy protections are correctly applied, transfer locks are active, expiry dates are adequately distant, and no unexpected registrant detail changes have occurred. 
- **Lookalike domain registration monitoring:** Monitor for newly registered domains closely resembling organisational domains using [DomainTools Iris Detect](https://www.domaintools.com/products/iris-detect/), [Recorded Future Brand Intelligence](https://www.recordedfuture.com/), and [Cloudflare Radar](https://radar.cloudflare.com/) domain monitoring, enabling rapid identification of adversary-registered typosquatting domains before they are used to launch phishing campaigns informed by WHOIS-derived domain registration intelligence. 
- **Registrar account security hardening:** Secure domain registrar management accounts with phishing-resistant **FIDO2/WebAuthn MFA** and dedicated administrative email addresses not published in WHOIS records, preventing registrar account compromise and the resultant domain hijacking that WHOIS reconnaissance can facilitate by exposing registrar identity. 
- **Active Scanning detection:** Given that WHOIS reconnaissance of IP block allocations typically precedes targeted active scanning of identified IP ranges, implement network perimeter monitoring for scanning activity against the organisation's IP ranges using **IDS** platforms such as [Suricata](https://suricata.io/) and threat intelligence enrichment in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) to detect and correlate scanning patterns against the identified IP blocks, recognising that WHOIS-derived IP range intelligence is a common precursor to **T1595 – Active Scanning** operations. 
