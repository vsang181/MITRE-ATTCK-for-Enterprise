# Reconnaissance

Reconnaissance is the first tactic in the **MITRE ATT&CK Enterprise framework (TA0043)**, representing the set of techniques through which adversaries actively or passively gather information about a target to support the planning and execution of future operations.  This information may encompass details about the victim organisation's infrastructure, personnel, network architecture, and business relationships, all of which can be leveraged to facilitate subsequent phases of the attack lifecycle, including **Initial Access**, **Resource Development**, and further **Reconnaissance** efforts. [attack.mitre](https://attack.mitre.org/tactics/TA0043/)

The Reconnaissance tactic is broadly divided into two operational modes: **active reconnaissance**, in which the adversary directly interacts with target systems or infrastructure to elicit responses, and **passive reconnaissance**, in which the adversary collects intelligence from publicly available sources without engaging the target directly.  Across both modes, the intelligence gathered serves to scope and prioritise post-compromise objectives, identify exploitable weaknesses, and enable adversaries to craft highly targeted and contextually convincing attack campaigns. [netscout](https://www.netscout.com/what-is-mitre-attack/reconnaissance)

***

## Active Scanning

Active scanning encompasses techniques in which adversaries probe victim infrastructure via network traffic to enumerate hosts, identify services, and uncover exploitable weaknesses. This technique is characterised by direct network interaction with the target and is covered in full detail across three sub-techniques:

- **Scanning IP Blocks:** Systematic probing of allocated IP address ranges to enumerate live hosts, open ports, and service banners using tools such as [Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), and [Zmap](https://zmap.io/).
- **Vulnerability Scanning:** Targeted probing of services and applications to identify known exploitable vulnerabilities, commonly executed via tools such as [Nessus](https://www.tenable.com/products/nessus), [OpenVAS](https://www.openvas.org/), [Nikto](https://cirt.net/Nikto2), and [Acunetix](https://www.acunetix.com/)
- **Wordlist Scanning:** Iterative brute-force enumeration of web directories, DNS subdomains, API endpoints, and cloud storage buckets using tools such as [GoBuster](https://github.com/OJ/gobuster), [ffuf](https://github.com/ffuf/ffuf), and [Feroxbuster](https://github.com/epi052/feroxbuster).

***

## Gather Victim Host Information

Adversaries may collect detailed information about victim host systems to inform targeting decisions. Host-level intelligence enables adversaries to tailor exploits, identify defensive controls in place, and understand the operational role of specific systems within the target environment.  This technique is organised across four sub-techniques: [netscout](https://www.netscout.com/what-is-mitre-attack/reconnaissance)

- **Hardware:** Collection of information about host hardware configurations, including device types, component versions, and the presence of additional security hardware such as biometric readers, hardware security modules (HSMs), or dedicated encryption appliances. This information may be used to infer the operational significance and security posture of individual hosts.
- **Software:** Enumeration of installed software, running applications, and security tooling such as antivirus solutions, EDR agents, and SIEM integrations. Adversaries use this intelligence to identify software versions susceptible to known CVEs and to understand which defensive technologies may need to be evaded.
- **Firmware:** Gathering of firmware type and version information from host devices, which may reveal patch levels, device age, and susceptibility to firmware-level exploits. This is particularly relevant in OT/ICS environments where firmware updates may be infrequent or operationally constrained.
- **Client Configurations:** Collection of client-side configuration details including operating system version, architecture (32-bit vs. 64-bit), virtualisation status, system language, and time zone settings. These details assist adversaries in selecting appropriately compiled payloads and configuring malware to execute correctly on the target platform.

***

## Gather Victim Identity Information

Adversaries collect identity-related information about target personnel to support credential-based attacks, social engineering campaigns, and account compromise operations.  This technique covers three sub-techniques: [netscout](https://www.netscout.com/what-is-mitre-attack/reconnaissance)

- **Credentials:** Harvesting of account credentials associated with the target organisation, including usernames, passwords, and session tokens, typically sourced from prior data breaches, credential dump repositories (e.g., [Have I Been Pwned](https://haveibeenpwned.com/)), and dark web marketplaces. Adversaries exploit the common tendency for individuals to reuse passwords across personal and professional accounts.
- **Email Addresses:** Enumeration of valid corporate and personal email addresses using tools such as [Hunter.io](https://hunter.io/), [theHarvester](https://github.com/laramies/theHarvester), and [Phonebook.cz](https://phonebook.cz/). Harvested email addresses serve as direct vectors for spearphishing campaigns and can be used to derive further identity information.
- **Employee Names:** Collection of employee names from sources including corporate websites, LinkedIn profiles, press releases, and conference speaker lists. Employee names facilitate the derivation of email address formats and support the construction of highly targeted, believable social engineering lures.

***

## Gather Victim Network Information

Adversaries gather detailed information about the victim's network architecture, addressing, and operational dependencies to support network-level targeting and lateral movement planning.  This technique is divided across six sub-techniques: [netscout](https://www.netscout.com/what-is-mitre-attack/reconnaissance)

- **Domain Properties:** Collection of domain registration data, administrative contacts, registrar details, and name server configurations using WHOIS lookup services such as [DomainTools](https://www.domaintools.com/) and [WhoisXML API](https://www.whoisxmlapi.com/). This information can reveal organisational structure, third-party service dependencies, and contact details for social engineering.
- **DNS:** Enumeration of DNS records including A, MX, TXT, SPF, CNAME, and NS records to map subdomains, mail infrastructure, and third-party cloud service usage (e.g., Office 365, G Suite, Salesforce). DNS reconnaissance tools include [dnsx](https://github.com/projectdiscovery/dnsx), [Amass](https://github.com/owasp-amass/amass), and [Subfinder](https://github.com/projectdiscovery/subfinder).
- **Network Trust Dependencies:** Identification of third-party organisations, managed service providers (MSPs), and contractors with elevated or connected network access to the target. These trust relationships represent high-value lateral access pathways and supply chain attack vectors.
- **Network Topology:** Mapping of the physical and logical arrangement of internal and external network environments, including the identification of network devices such as routers, gateways, load balancers, and segmentation boundaries. This intelligence informs lateral movement strategies and assists in identifying the most direct path to high-value targets.
- **IP Addresses:** Collection of allocated IP address ranges and active host information from public sources including RIR databases (ARIN, RIPE NCC, APNIC) and scan platforms such as [Shodan](https://www.shodan.io/) and [Censys](https://censys.io/). IP address intelligence may also reveal organisational size, physical locations, and internet service provider (ISP) relationships. [shadowdragon](https://shadowdragon.io/blog/osint-techniques/)
- **Network Security Appliances:** Gathering of information about deployed perimeter security controls including firewalls, web proxies, content filters, bastion hosts, and network-based intrusion detection systems (NIDS). Identifying the type and configuration of these appliances allows adversaries to anticipate detection capabilities and select evasion strategies accordingly.

***

## Gather Victim Org Information

Adversaries gather organisational intelligence to understand the structure, operations, and key personnel of the target entity, enabling the construction of highly contextualised and convincing attack campaigns. This technique spans four sub-techniques:

- **Determine Physical Locations:** Identification of the target organisation's physical premises, data centre locations, and operational sites using sources such as corporate websites, Google Maps, Companies House filings, and satellite imagery platforms. Physical location intelligence may also reveal the legal jurisdiction under which the organisation operates, informing adversarial risk assessments.
- **Business Relationships:** Collection of information about third-party business relationships, including supply chain partners, vendors, contractors, and managed service providers. This intelligence supports supply chain compromise strategies (**T1195**) by identifying organisations with trusted network access to the primary target.
- **Identify Business Tempo:** Gathering of information about the target's operational schedule, including working hours, maintenance windows, and peak business periods. Adversaries use this intelligence to time intrusion operations for periods of reduced staffing and security monitoring coverage.
- **Identify Roles:** Enumeration of key personnel roles and responsibilities within the target organisation, including executives, system administrators, finance personnel, and security staff. Role identification enables adversaries to target individuals with privileged access or decision-making authority, supporting **Business Email Compromise (BEC)** and **privilege escalation** strategies.

***

## Phishing for Information

Phishing for information is a social engineering technique in which adversaries send deceptive communications designed to elicit sensitive information, most commonly credentials or other actionable intelligence, from target individuals.  This technique is distinct from execution-focused phishing (**T1566**) in that the primary objective is data extraction rather than malware delivery. This technique covers four sub-techniques: [attack.mitre](https://attack.mitre.org/techniques/T1598/004/)

- **Spearphishing via Service:** Delivery of targeted phishing messages through third-party platforms including LinkedIn InMail, Microsoft Teams, Slack, social media direct messaging services, and collaboration tools. The use of these platforms lends the communication an air of legitimacy, as messages arrive through channels the recipient may consider trusted.
- **Spearphishing Attachment:** Distribution of phishing messages containing malicious or deceptive attachments (e.g., credential-harvesting forms embedded in PDF or Office documents) designed to elicit sensitive information from the recipient under a believable pretext.
- **Spearphishing Link:** Delivery of phishing messages containing hyperlinks to adversary-controlled credential harvesting pages or fraudulent login portals that mimic legitimate services. These campaigns frequently employ **typosquatting**, **IDN homograph attacks**, and **open redirect vulnerabilities** to maximise URL credibility.
- **Spearphishing Voice (Vishing):** Use of voice communications, including direct phone calls, spoofed caller ID, automated robocalls, and AI-generated voice synthesis, to socially engineer targets into divulging sensitive information.  Vishing campaigns frequently involve adversaries impersonating IT support staff, financial institutions, or executive personnel to create urgency and exploit the inherent trust associated with human voice communication.  Threat actor groups such as **Scattered Spider** have operationally demonstrated the effectiveness of this technique against enterprise help desk and identity verification processes. [ek](https://www.ek.co/publications/caught-in-a-vishing-net/)

***

## Search Closed Sources

Adversaries may access paid, private, or otherwise restricted data repositories to gather intelligence about target organisations that is not available through open-source channels. This technique covers two sub-techniques:

- **Threat Intelligence Vendors:** Querying of paid threat intelligence portals and subscription feeds (e.g., [Recorded Future](https://www.recordedfuture.com/), [Mandiant Advantage](https://www.mandiant.com/advantage)) to access detailed breach data, attribution reports, and TTP documentation. Even redacted intelligence reports may contain actionable details regarding targeted industries, adversary infrastructure, and defensive countermeasure effectiveness
- **Purchase Technical Data:** Acquisition of victim-specific technical data from commercial data brokers, scan database subscriptions, or illicit dark web marketplaces. Purchased data may include network scan results, credential dumps, and proprietary vulnerability information not yet publicly disclosed.

***

## Search Open Technical Databases

Adversaries leverage freely accessible public databases and technical repositories to passively gather infrastructure intelligence about target organisations without direct interaction.  This technique spans five sub-techniques: [shadowdragon](https://shadowdragon.io/blog/osint-techniques/)

- **DNS/Passive DNS:** Querying of passive DNS databases to enumerate historical and current DNS records associated with the target, revealing subdomain structures, hosting changes, and mail server configurations. Tools include [SecurityTrails](https://securitytrails.com/) and [RiskIQ PassiveTotal](https://community.riskiq.com/).
- **WHOIS:** Querying of regional internet registry (RIR) WHOIS databases to retrieve domain registration details, IP block ownership, registrant contact information, and name server assignments.  WHOIS data is publicly accessible and can be queried via command-line utilities or web interfaces such as [who.is](https://who.is/) and [WhoisXML API](https://www.whoisxmlapi.com/). [shadowdragon](https://shadowdragon.io/blog/osint-techniques/)
- **Digital Certificates:** Searching of public certificate transparency (CT) logs to enumerate SSL/TLS certificates issued for the target organisation's domains. CT log databases such as [crt.sh](https://crt.sh/) and [Censys Certificates](https://censys.io/) can reveal internal subdomain naming conventions, staging environments, and previously undisclosed infrastructure.
- **CDNs:** Querying of content delivery network (CDN) metadata to identify origin server IP addresses behind CDN-masked infrastructure, potentially bypassing protections offered by services such as Cloudflare. Tools such as [CloudFlair](https://github.com/christophetd/CloudFlair) and historical DNS lookup services can assist in this process.
- **Scan Databases:** Querying of internet-wide scan databases including [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [FOFA](https://fofa.info/) to retrieve indexed scan results containing active IP addresses, open port information, service banners, TLS certificate data, and server configuration details for internet-facing infrastructure.

***

## Search Open Websites/Domains

Adversaries search publicly accessible websites, online platforms, and open-source information repositories for intelligence about the target organisation and its personnel.  This technique covers three sub-techniques: [netscout](https://www.netscout.com/what-is-mitre-attack/reconnaissance)

- **Social Media:** Harvesting of organisational and personnel information from platforms including LinkedIn, Twitter/X, Facebook, and Instagram. Social media profiles may disclose employee roles, organisational structure, technology stack details, physical locations, and travel patterns. Tools such as [Maltego](https://www.maltego.com/) and [SpiderFoot](https://www.spiderfoot.net/) can automate social media OSINT collection at scale. [shadowdragon](https://shadowdragon.io/blog/osint-techniques/)
- **Search Engines:** Use of search engine platforms including Google, Bing, and specialised search tools to index and query publicly available information. Adversaries may employ advanced **Google Dorking** techniques using specialised operators (e.g., `site:`, `filetype:`, `inurl:`, `intitle:`) to surface sensitive documents, exposed configuration files, and login portals indexed by search crawlers. [shadowdragon](https://shadowdragon.io/blog/osint-techniques/)
- **Code Repositories:** Searching of public source code repositories including [GitHub](https://github.com/), [GitLab](https://gitlab.com/), [SourceForge](https://sourceforge.net/), and [BitBucket](https://bitbucket.org/) for inadvertently committed sensitive data. This may include hardcoded API keys, authentication tokens, database credentials, internal hostnames, and infrastructure configuration files. Tools such as [truffleHog](https://github.com/trufflesecurity/trufflehog) and [GitLeaks](https://github.com/gitleaks/gitleaks) are commonly used to automate credential and secret detection within repository commit histories.

***

## Search Threat Vendor Data

Adversaries may monitor open and closed threat intelligence publications, including vendor reports, security blog posts, and incident disclosures, to gather indicators and behavioural intelligence about their own infrastructure and campaigns, as well as those conducted by other adversary groups operating in aligned target sectors. This intelligence can inform operational security (OPSEC) decisions, enabling adversaries to modify their TTPs, rotate infrastructure, and adapt tooling in response to public detection and attribution reporting. Sources include threat intelligence platforms such as [MISP](https://www.misp-project.org/), vendor publications from organisations such as [Mandiant](https://www.mandiant.com/), [CrowdStrike](https://www.crowdstrike.com/), and [Recorded Future](https://www.recordedfuture.com/), as well as community repositories such as [VirusTotal](https://www.virustotal.com/) and [AlienVault OTX](https://otx.alienvault.com/).

***

## Search Victim-Owned Websites

Adversaries directly browse and analyse websites owned and operated by the target organisation to extract intelligence about its internal structure, personnel, and operations. Victim-owned websites may expose division and department names, physical office locations, key employee names and roles, contact information including email addresses, and details about ongoing business operations and partnerships. This information directly enriches spearphishing campaign construction, supports organisational mapping, and feeds into broader OSINT collection workflows. Automated crawling tools such as [HTTrack](https://www.httrack.com/) and [Wget](https://www.gnu.org/software/wget/) can be used to mirror entire websites for offline analysis, while frameworks such as [Maltego](https://www.maltego.com/) can correlate extracted data with other intelligence sources to build comprehensive target profiles.
