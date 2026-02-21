# Network Trust Dependencies

Network Trust Dependencies reconnaissance is a sub-technique of Gather Victim Network Information (**MITRE ATT&CK T1590.003**) in which adversaries collect intelligence about the third-party organisations, managed service providers (MSPs), contractors, technology vendors, and cloud service providers that maintain connected or privileged network access to a target organisation.  This intelligence is operationally significant because trust relationships between organisations represent indirect attack pathways that can circumvent the technical perimeter controls protecting the primary target. By compromising a less-hardened third party with legitimate elevated network access, adversaries can establish a trusted foothold from which they can pivot directly into the primary victim environment without triggering the authentication, detection, or access control mechanisms that would otherwise block direct intrusion. 

The intelligence gathered during this sub-technique can directly enable further reconnaissance (e.g., **T1595 – Active Scanning**, **T1593 – Search Open Websites/Domains**), support resource development operations (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and most critically, facilitate initial access via **T1199 – Trusted Relationship**, in which adversaries leverage the trusted third party's pre-established network access rather than exploiting a vulnerability or conducting phishing against the primary target directly. 
***

## The Third-Party Trust Attack Surface

The modern enterprise operates within a dense ecosystem of third-party dependencies that collectively represent a substantial and often inadequately monitored attack surface. MSPs are particularly high-value targets because they typically hold privileged access credentials for multiple customer environments simultaneously, meaning a single successful compromise of an MSP can provide adversaries with simultaneous access to dozens or hundreds of downstream client networks.  This attack-one-breach-many dynamic is well documented and has been the subject of joint advisories from **CISA**, **NCSC**, and allied cybersecurity agencies following confirmed MSP-targeted campaigns. 

Common categories of trusted third parties that represent network trust dependency attack vectors include:

- **Managed Service Providers (MSPs):** Organisations that manage customer IT infrastructure often have persistent VPN or remote management tool access to customer environments, frequently using platforms such as **ConnectWise**, **Kaseya**, **NinjaRMM**, and **Datto**. Adversaries exploiting MSP access gain the ability to deploy tooling and move laterally across all MSP customer environments simultaneously. 
- **IT contractors and professional services firms:** Consultancies and implementation partners involved in infrastructure projects often hold temporary or project-long elevated access to target environments, with access credentials and connection pathways that may persist well beyond project completion.
- **Software vendors and SaaS providers:** Vendors that deliver software updates, patches, or maintenance remotely may have privileged code execution rights within the target environment, as demonstrated by the **SolarWinds Compromise** in which APT29 trojanised the Orion IT monitoring platform to deploy the SUNBURST backdoor across thousands of customer networks through a trusted software update mechanism. 
- **Cloud and infrastructure providers:** Organisations using cloud-based management, monitoring, or security platforms expose those providers as potential trust dependency vectors if the provider's own infrastructure is compromised.

***

## Collection Vectors

Adversaries use a combination of passive OSINT, active elicitation, and technical reconnaissance to enumerate network trust dependencies:

- **OSINT and Corporate Website Analysis:** Corporate websites, press releases, technology partnership pages, and case studies routinely disclose MSP and vendor relationships by name. Organisations may publish statements such as "managed by [MSP name]" or list technology partners as service endorsements, inadvertently advertising their third-party access relationships to adversaries conducting reconnaissance. 
- **Job Postings:** Employment advertisements frequently disclose the technology platforms and service providers in use, including remote management tools, VPN platforms, and monitoring solutions employed by MSPs serving the target. These postings enable adversaries to identify the specific tooling used for third-party access, which can then be targeted for credential theft or vulnerability exploitation. 
- **LinkedIn and Professional Network Profiling:** Employees of the target organisation, and employees of likely vendors and MSPs, may publish details about the relationships on professional networks. Contractor and MSP employee profiles referencing the target organisation as a client provide direct confirmation of a trust relationship. 
- **Phishing for Information (T1598):** Adversaries may directly elicit network trust dependency information through targeted phishing campaigns against target employees, impersonating IT support or procurement contacts to extract information about which third parties hold remote access to the environment. 
- **Search Open Technical Databases (T1596):** BGP routing data, WHOIS records, and DNS records can reveal shared infrastructure, common name servers, and IP address relationships between organisations that suggest managed hosting or co-managed network arrangements.

***

## Notable Exploitation Examples

### SolarWinds Compromise (APT29 / Cozy Bear)
The **SolarWinds Compromise** is the most operationally significant documented exploitation of network trust dependencies. **APT29** compromised the **SolarWinds Orion** IT performance monitoring platform, inserting the **SUNBURST** backdoor into trojanised software updates distributed to approximately **18,000** customers including US federal government agencies, defence contractors, and technology companies. Because Orion was a trusted platform with broad environmental visibility, the compromised update was deployed automatically by customers, granting APT29 covert persistent access across the entire customer base. 

### Kaseya VSA Supply Chain Attack (REvil / Sodinokibi)
In July 2021, the **REvil** ransomware group exploited a zero-day vulnerability in **Kaseya VSA**, a remote monitoring and management (RMM) platform widely used by MSPs. Because MSPs use Kaseya to manage their customers' environments, the compromise propagated ransomware from Kaseya through MSPs to their downstream customers automatically, affecting over **1,500 businesses** across multiple countries through a single point of third-party trust exploitation. 

### MSP-Targeted Campaigns (APT10 / Stone Panda)
**APT10**, a Chinese state-sponsored group, conducted a sustained global campaign specifically targeting MSPs from at least 2016, using MSP administrative credentials and remote management tools to pivot into MSP customer environments across multiple sectors and geographies, extracting sensitive intellectual property from organisations that were not themselves directly targeted. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Network trust dependency intelligence is gathered predominantly through passive OSINT and professional network analysis, placing most collection activity outside the reach of enterprise defensive controls.  Mitigation efforts should focus on limiting both the discoverability of third-party relationships and the operational impact of a trusted third-party compromise: 

- **Enforce least-privilege third-party network access:** Third-party VPN and remote access connections should be scoped to the minimum network segments, systems, and protocols operationally required for the vendor's function.  Broad VPN tunnel access that grants unrestricted network connectivity should be replaced with purpose-scoped access using **Privileged Access Workstations (PAWs)** and vendor-specific access portals. Tools such as [BeyondTrust Privileged Remote Access](https://www.beyondtrust.com/products/privileged-remote-access) and [CyberArk Alero](https://www.cyberark.com/products/vendor-privileged-access-manager/) enforce granular, session-based third-party access controls with full audit logging. 
- **Implement network segmentation for third-party access paths:** Third-party access pathways should terminate in dedicated, tightly segmented network zones that provide only the connectivity required for the vendor's function, with firewall policies preventing lateral movement from third-party access segments into core infrastructure.  The **NCSC Operational Technology Security** principles recommend explicit documentation and segmentation of all third-party access paths as a foundational OT security control. 
- **Mandate MFA for all third-party remote access:** All VPN, RMM, and remote desktop access used by third parties must be protected by **multi-factor authentication**, as credential theft from an MSP employee via phishing is one of the most common vectors for third-party trust exploitation.  Phishing-resistant MFA methods such as **FIDO2/WebAuthn hardware security keys** should be mandated where risk levels support this requirement. 
- **Conduct regular third-party security risk assessments:** Implement a formal **Third-Party Risk Management (TPRM)** programme that periodically assesses the security posture of all organisations holding network access to the environment, using security questionnaires, audit evidence review, and where appropriate, external security assessments. Frameworks including **ISO 27036 (Information Security for Supplier Relationships)** and **NIST SP 800-161 (Cybersecurity Supply Chain Risk Management)** provide structured guidance for TPRM programme design. 
- **Restrict public disclosure of third-party relationships:** Minimise the information about MSP, vendor, and contractor relationships published on corporate websites, press releases, and professional networks to reduce the intelligence yield available to adversaries conducting OSINT-based trust dependency reconnaissance.

***

## Detection Strategy

### Passive Collection Visibility Limitations

Network trust dependency reconnaissance conducted through OSINT collection from websites, job postings, and professional networking platforms generates no network-level artefacts within the target organisation's infrastructure.  There is no technically detectable footprint associated with an adversary researching an organisation's vendor partnerships or MSP relationships through publicly available sources, making direct detection of this reconnaissance sub-technique largely infeasible through conventional monitoring controls.

### Third-Party Access Anomaly Detection

The most actionable detection opportunity arises during the **Initial Access** and **Lateral Movement** stages when a compromised third party's access credentials or remote management tools are used against the target environment. Defenders should implement the following controls to detect anomalous third-party access activity:

- **Continuous monitoring of third-party access sessions:** All third-party VPN and remote management sessions should be logged and monitored in real time, with access timestamps, source IPs, session durations, and commands executed captured within a **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) for correlation and anomaly detection. 
- **Detect access outside authorised maintenance windows:** Third-party access occurring outside of pre-agreed and documented maintenance windows, from unexpected geographic locations, or from IP addresses not associated with the vendor's known infrastructure should trigger immediate alerting and session suspension. 
- **Monitor RMM tool behaviour:** Where MSP remote management platforms are deployed within the environment, monitor for anomalous tooling behaviour including unexpected process creation, lateral movement activity, or data staging operations originating from RMM agent processes, using **EDR telemetry** from platforms such as [CrowdStrike Falcon](https://www.crowdstrike.com/) and [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint). 
- **Threat intelligence integration:** Subscribe to threat intelligence feeds and vendor advisories that track active campaigns targeting MSPs and common RMM platforms, enabling proactive detection rule updates and emergency access suspension when a trusted third-party provider is reported as compromised. 
