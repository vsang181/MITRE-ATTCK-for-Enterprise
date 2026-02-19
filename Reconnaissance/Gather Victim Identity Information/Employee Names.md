# Employee Names

Employee name harvesting is a sub-technique of Gather Victim Identity Information (**MITRE ATT&CK T1589.003**) in which adversaries systematically collect the names of individuals employed within a target organisation to support targeting, identity derivation, and social engineering operations.  Employee names serve multiple downstream offensive functions: they can be used to algorithmically derive corporate email addresses by applying known or inferred email format conventions (e.g., `firstname.lastname@organisation.com`, `f.lastname@organisation.com`), to map organisational hierarchy and identify high-value targets with privileged access, and to craft highly contextualised and believable social engineering lures that reference real colleagues, managers, or business relationships. 

Employee name intelligence is among the most readily obtainable categories of organisational reconnaissance data, as individuals routinely self-publish comprehensive professional profiles on platforms such as LinkedIn, including their full name, job title, department, reporting structure, tenure, and skills, creating a continuously updated, adversary-accessible organisational directory.  Despite its apparent benignity as a data category, employee name intelligence is operationally foundational, enabling adversaries to construct highly personalised spearphishing campaigns that, while representing less than 0.1% of all email traffic, have been responsible for **66% of all reported data breaches**.  Gathered intelligence can inform further reconnaissance activities including **T1593 – Search Open Websites/Domains** and **T1598 – Phishing for Information**, support operational resource development through **T1586 – Compromise Accounts**, and enable initial access via **T1566 – Phishing** and **T1078 – Valid Accounts**. 

***

## Collection Vectors

Adversaries leverage a broad range of passive and active collection methods to enumerate employee names at scale:

- **Professional Networking Platforms:** **LinkedIn** is the primary and most operationally valuable source for employee name harvesting, providing full name, job title, department, seniority level, and organisational hierarchy details for the majority of corporate employees. Red team research has demonstrated that by establishing a sufficient number of connections with an organisation's employees, the entire company employee list can be enumerated through LinkedIn's people search functionality.  Adversary-simulated recruiter profiles have been used to establish connections with over 100 target employees in under one hour, simultaneously creating social engineering opportunities through the established messaging channel.  Tools such as [Maltego](https://www.maltego.com/), [SpiderFoot](https://www.spiderfoot.net/), and specialised LinkedIn scraping utilities including [LinkedInt](https://github.com/vysecurity/LinkedInt) and [Peasant](https://github.com/SecurityRiskAdvisors/peasant) automate the collection and correlation of LinkedIn employee data at scale. 
- **Corporate Websites and Staff Directories:** Organisational websites frequently publish staff directories, team pages, leadership biographies, and press release author credits that directly expose employee full names, titles, and contact details. Automated web crawling tools such as [HTTrack](https://www.httrack.com/) and OSINT frameworks including [theHarvester](https://github.com/laramies/theHarvester) and [Recon-ng](https://github.com/lanmaster53/recon-ng) can systematically extract this information from victim-owned web properties. 
- **Search Engine Dorking:** Advanced search engine queries using Google operators such as `site:organisation.com "our team"`, `site:linkedin.com "organisation" "manager"`, or `filetype:pdf site:organisation.com` can surface employee names from publicly indexed pages, documents, and conference proceedings. 
- **Social Media Platforms:** Beyond LinkedIn, platforms including **Twitter/X**, **Instagram**, and **Facebook** expose employee names through public posts, event check-ins, conference attendance, and peer tagging, providing additional personal context such as current location, travel schedules, and personal interests that can be incorporated into highly targeted spearphishing lures. 
- **Breach Data Correlation:** Employee names sourced from prior data breach dumps can be correlated with current LinkedIn and social media profiles to build enriched target dossiers, pairing names with email addresses, former passwords, and associated personal accounts sourced from breach repositories. 
- **Press Releases, Annual Reports, and Conference Records:** Corporate communications including press releases, annual reports, investor presentations, and conference speaker listings publish employee names and roles for executives and senior staff, providing a high-confidence starting point for organisational mapping and targeted whaling operations. 

***

## Procedure Examples

### Kimsuky
**Kimsuky** is a North Korean state-sponsored APT group conducting persistent espionage operations against South Korean government, academic, and policy organisations. The group has been observed collecting victim employee name information as part of structured identity reconnaissance operations, using harvested names to derive email addresses and construct targeted spearphishing lures that reference real internal personnel relationships to maximise credibility. 

### Sandworm Team
**Sandworm Team** conducted comprehensive research into potential victim organisations as part of its operational planning, systematically identifying and collecting employee information to support the construction of targeted attack campaigns. This intelligence gathering activity was conducted ahead of major destructive operations, informing both technical targeting decisions and social engineering delivery mechanisms. 

### Silent Librarian (TA407 / COBALT DICKENS)
**Silent Librarian** compiled structured lists of employee and academic staff names at targeted universities and research institutions as a precursor to targeted credential phishing campaigns. Harvested names were used to derive institutional email address formats and to identify specific faculty members and researchers whose credentials would provide access to valuable academic research and intellectual property. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Employee name harvesting is conducted almost exclusively through passive collection against publicly accessible data sources, placing it entirely outside the reach of conventional enterprise network controls.  Mitigation efforts should focus on reducing the organisational and personal information surface available to adversaries through the following measures: 

- **Restrict and standardise public staff information:** Review and limit the employee information published on corporate websites, replacing individual named staff pages with generic role-based contact information where operationally possible. For organisations where staff directories are required, consider restricting detailed biographical and role information to authenticated intranet portals rather than public-facing web properties.
- **Implement LinkedIn and social media disclosure policies:** Establish and communicate clear organisational policies governing the information employees may publish on professional networking platforms, with particular guidance around disclosing specific technology platforms, internal project names, organisational structure, and colleague relationships that could be leveraged in social engineering attacks. 
- **Conduct regular OSINT self-assessments:** Periodically execute OSINT reconnaissance operations against the organisation's own public information surface using tools such as [Maltego](https://www.maltego.com/), [SpiderFoot](https://www.spiderfoot.net/), and [theHarvester](https://github.com/laramies/theHarvester) to identify and remediate unintended employee information disclosures before adversaries can exploit them. 
- **Role-targeted security awareness training:** Deliver targeted security awareness training that educates employees, with particular emphasis on those in high-value roles such as executives, finance, HR, and IT administration, on the risks of professional information oversharing and the mechanics of name-derived spearphishing and whaling attacks. Platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training) support role-specific phishing simulation programmes that reflect the attack scenarios most relevant to each personnel category. 
- **Deploy anti-spoofing email controls:** Enforce **SPF**, **DKIM**, and **DMARC** policies to prevent adversaries from spoofing harvested employee names and email addresses in follow-on phishing campaigns that impersonate known internal personnel. 

***

## Detection Strategy

### Visibility Limitations and Detection Challenges

Detection of employee name harvesting activity presents significant challenges, as collection occurs predominantly through passive observation of publicly accessible data sources with no interaction with the target organisation's network infrastructure.  There are no network-level artefacts generated by an adversary browsing LinkedIn profiles, querying search engines, or reviewing corporate website staff pages, making this sub-technique largely invisible to conventional perimeter monitoring tools. The high baseline volume of legitimate web crawling and search engine indexing activity further compounds false positive rates for any detection approach targeting web scraping behaviours. 

### Detection Pivot to Downstream Attack Stages

Given the near-total absence of detectable indicators during the collection phase, detection resources yield the highest operational return when focused on the **Initial Access** and **Phishing** stages at which harvested employee name intelligence is operationally applied.  Defenders should monitor for the following downstream indicators consistent with name-derived targeting: 

- **Highly personalised spearphishing emails** referencing specific employee names, internal project names, or colleague relationships, detectable through email security gateways such as [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) and [Proofpoint](https://www.proofpoint.com/uk) with advanced impersonation detection capabilities.
- **Lookalike domain registrations** incorporating employee names or executive identifiers, detectable through domain monitoring services such as [RiskIQ](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-threat-intelligence) and [DomainTools](https://www.domaintools.com/), which can alert on newly registered domains exhibiting similarity to the organisation's legitimate domain names.
- **Anomalous authentication attempts** using derived email addresses against corporate identity services, detectable through **Entra ID Identity Protection** and centralised **SIEM** correlation within [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel), enriched with threat intelligence from services such as [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/).
