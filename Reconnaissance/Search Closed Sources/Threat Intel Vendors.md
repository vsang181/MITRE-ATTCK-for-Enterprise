# Threat Intel Vendors

Threat Intel Vendors is a sub-technique of Search Closed Sources (**MITRE ATT&CK T1597.001**) in which adversaries search private threat intelligence vendor platforms — paid portals, subscription data feeds, and commercial intelligence databases — to gather actionable information about target organisations, industries, and defensive postures.  While these platforms are marketed to and primarily used by legitimate security teams to understand the threat landscape and enrich defensive operations, their data is equally accessible to any adversary willing to purchase a subscription, creating a significant dual-use intelligence exposure problem. 

The operational significance of this technique lies in the richness and structure of the intelligence available. Commercial threat intelligence services aggregate data from millions of sensors, honeypots, passive DNS collections, internet-wide scan operations, malware analysis sandboxes, and dark web monitoring operations — curating and correlating it into queryable, structured datasets that provide far more actionable intelligence than raw open-source collection alone.  Intelligence gathered through this technique may reveal opportunities for further reconnaissance (e.g., **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and enable initial access via **T1190 – Exploit Public-Facing Application** and **T1133 – External Remote Services**. 

***

## Intelligence Categories Available Through Threat Intel Vendors

Commercial threat intelligence platforms expose several categories of intelligence that are operationally useful to adversaries, not just to defenders: 

- **Strategic intelligence:** High-level reporting on adversary motivations, targeting trends, industry-specific threat landscapes, attribution claims for known campaigns, and successful TTPs observed across the sector. Even with sensitive customer identifiers redacted, strategic reports disclose breach trends, target industries, and countermeasure effectiveness data that adversaries can use to benchmark their own operational methods and refine targeting decisions. 
- **Operational intelligence:** Campaign-specific reporting on active threat actor operations, including TTPs, infrastructure patterns, malware families, and exploitation techniques currently in use — which adversaries searching this data can use to identify defensive blind spots, understand which techniques are currently being detected, and adapt their own operations to avoid reported indicators. 
- **Technical intelligence feeds:** Automated data streams delivering real-time indicators of compromise (IOCs) including malicious IP addresses, domains, file hashes, and C2 infrastructure identifiers.  Adversaries who query these feeds can identify which of their own infrastructure components have been listed as malicious indicators, enabling them to rotate burned infrastructure before it is widely blocked — a use case MITRE specifically notes as "Search Threat Vendor Data" (searching for information on their own activities).
- **Passive DNS and infrastructure history:** Historical DNS record data, IP-to-domain mapping histories, and SSL/TLS certificate datasets exposing an organisation's past and present internet-facing infrastructure, including previously active subdomains and historical IP ranges. Platforms including [SecurityTrails](https://securitytrails.com/) and [DomainTools](https://www.domaintools.com/) provide queryable historical infrastructure data.
- **Internet scan databases:** Aggregated internet-wide scan data indexing open ports, service banners, and exposed software versions across all publicly reachable IP addresses, queryable by organisation, autonomous system number (ASN), and network range. [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [BinaryEdge](https://www.binaryedge.io/) provide this category of infrastructure exposure intelligence.
- **Vulnerability intelligence:** Structured feeds of vulnerability disclosure data, exploitation timing, proof-of-concept availability, and patch release timelines, enabling adversaries to rapidly identify publicly disclosed vulnerabilities affecting technologies identified in a target organisation's infrastructure fingerprint.

***

## Threat Intelligence Feed Types

The commercial threat intelligence ecosystem provides intelligence across multiple tiers of specificity and technical depth, each with distinct adversarial exploitation potential:

| Feed Type | Content | Primary Legitimate Use | Adversarial Exploitation |
|---|---|---|---|
| **Strategic feeds** | Industry threat trend reports, adversary motivation assessments, attribution claims, breach pattern summaries | Security leadership and board risk briefings | Identifying target industry attack patterns and successful TTPs to replicate; assessing detection effectiveness of reported techniques |
| **Operational feeds** | Active campaign reporting, threat actor profiles, current TTPs, infrastructure patterns | Security manager decision-making, incident context enrichment | Identifying currently active detection signatures to evade; understanding which TTPs are being detected and reported |
| **Technical IOC feeds** | Malicious IP addresses, domains, file hashes, C2 server indicators, botnet infrastructure lists | SIEM enrichment, firewall and IDS signature updates, threat hunting | Checking own infrastructure against published indicators to identify burned components requiring rotation; identifying detection thresholds for specific malware families |
| **Infrastructure intelligence** | Passive DNS histories, SSL/TLS certificate datasets, historical subdomain mappings, internet scan data | Attack surface management, asset discovery, incident investigation | Enumerating target infrastructure including historical and forgotten systems; identifying unpatched or misconfigured services exposed to the internet |
| **Vulnerability feeds** | CVE details, CVSS scores, exploitation timing, PoC availability, patch release dates | Patch prioritisation, exposure management | Identifying exploitable vulnerabilities in target technologies fingerprinted through prior reconnaissance |

***

## Operational Self-Assessment: Adversaries Searching for Their Own Activity

A particularly significant adversarial use of threat intelligence vendor data is the practice of querying vendor portals and reports for indicators and reporting related to their own campaigns.  By monitoring what threat intelligence vendors have published about their TTPs, infrastructure, and malware families, adversaries can assess the degree to which their operations have been detected and attributed, identify which specific infrastructure components, domains, file hashes, or behavioural indicators have been listed in feeds being consumed by defenders, and make operational decisions about infrastructure rotation, TTP modification, and operational security improvements before defenders can act on the published intelligence.  This use case transforms threat intelligence vendor data into an adversarial operational security resource, with adversaries effectively consuming the same intelligence as defenders to optimise evasion. 
***

## Mitigations: Pre-Compromise (MITRE M1056)

Threat intelligence vendor reconnaissance generates no artefacts within the target organisation's infrastructure and cannot be prevented through conventional enterprise controls.  Mitigation efforts should focus on limiting the intelligence quality available through vendor platforms and hardening the access and exploitation pathways this intelligence reveals:

- **Suppress infrastructure exposure details:** Minimise the version, banner, and configuration detail exposed by internet-facing systems to reduce the quality of intelligence available through commercial internet scan platforms such as Shodan and Censys. Remove vendor and version strings from HTTP response headers, management interface login pages, and service banners.
- **External attack surface management:** Continuously assess the organisation's own external infrastructure posture using [Microsoft Defender EASM](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-external-attack-surface-management) and [Censys ASM](https://censys.io/) to understand precisely what intelligence is currently available to adversaries querying commercial scan platforms, enabling proactive hardening before adversaries act on it.
- **Accelerate vulnerability patching based on vendor intelligence:** Subscribe to vulnerability intelligence feeds from [NCSC](https://www.ncsc.gov.uk/), [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and commercial sources to ensure vulnerabilities disclosed in vendor threat intelligence are remediated before adversaries consuming the same feeds can exploit them against the organisation's identified infrastructure.
- **Threat intelligence platform engagement:** Consider engaging with threat intelligence vendors directly to understand what data is available about the organisation's own infrastructure and breach history within their platforms, enabling targeted remediation of the highest-risk intelligence exposures.

***

## Detection Strategy

### Complete Passive Collection Opacity
Threat intelligence vendor reconnaissance is conducted entirely within external vendor platforms, generating absolutely no observable artefacts within the target organisation's IT infrastructure.  Direct detection of this collection activity is entirely infeasible.

### Detection Pivot to Exploitation Indicators

Detection resources should focus on the downstream stages at which vendor-sourced intelligence is operationally applied:

- **Vulnerability exploitation monitoring:** Prioritise detection rule coverage for exploitation attempts targeting vulnerabilities disclosed in recent threat intelligence reporting, recognising that adversaries who have purchased vendor intelligence about vulnerability exploitation trends may rapidly operationalise newly disclosed CVEs against identified target technologies. Configure **IDS/IPS** platforms such as [Suricata](https://suricata.io/) and [Snort](https://www.snort.org/) with current exploitation signatures and monitor **SIEM** dashboards in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) for exploitation attempt patterns aligned with recently published vendor intelligence.
- **Infrastructure anomaly detection:** Monitor authentication and access logs for attempts targeting historically active IP ranges and subdomains that may have been identified through passive DNS and infrastructure history data available in vendor platforms, particularly for forgotten or decommissioned systems that may retain exploitable services.
- **Threat intelligence sharing participation:** Engage with sector-specific **Information Sharing and Analysis Centres (ISACs)** and government threat intelligence sharing schemes including [NCSC's Cyber Security Information Sharing Partnership (CiSP)](https://www.ncsc.gov.uk/section/keep-up-to-date/cisp) to receive early warning of adversary campaigns against the organisation's sector that may have been informed by vendor intelligence searches.
