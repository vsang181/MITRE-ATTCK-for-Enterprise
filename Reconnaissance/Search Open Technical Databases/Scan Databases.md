# Scan Databases

Scan Databases is a sub-technique of Search Open Technical Databases (**MITRE ATT&CK T1596.005**) in which adversaries query publicly accessible internet-wide scan services that continuously survey all publicly reachable IP addresses, indexing their open ports, service banners, software versions, TLS certificates, and HTTP response data into searchable databases. These platforms transform the enormous operational complexity of conducting internet-wide scanning into an instant, freely accessible, and queryable intelligence resource — enabling any adversary to retrieve detailed technical intelligence about a specific organisation's internet-facing infrastructure within seconds, without generating any scanning traffic against the target.

Intelligence gathered through scan database queries can directly inform further reconnaissance (e.g., **T1595 – Active Scanning**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and enable initial access via **T1133 – External Remote Services** and **T1190 – Exploit Public-Facing Application**.

***

## How Internet Scan Databases Are Built

Internet scan databases are constructed through continuous, systematic probing of every publicly routable IPv4 address — approximately 4.3 billion addresses — and increasingly IPv6 ranges, conducted from dedicated scanning infrastructure operated by the platform provider. Scanners such as [ZMap](https://zmap.io/) and [Masscan](https://github.com/robertdavidgraham/masscan) can complete a full IPv4 address space TCP port scan in under five minutes from high-bandwidth infrastructure, enabling daily or more frequent full-internet rescans. The scan results — open ports, service responses, TLS certificates, HTTP response headers and body content, and protocol-specific banner data — are normalised, enriched, and inserted into queryable indexed databases.

The major scan database platforms include:

- **[Shodan](https://www.shodan.io/):** The most widely recognised internet scan database, indexing banners and service data across hundreds of ports and protocols. Shodan supports complex queries combining service type, software version, geographic location, ASN, organisation name, and specific banner content. Free and paid tiers are available, with paid tiers providing full access to historical data, bulk export, and API integration.
- **[Censys](https://censys.io/):** Provides structured, queryable scan data with a strong focus on TLS certificate correlation and precise protocol-specific data. Censys indexes data from both active scanning and CT log ingestion, enabling correlation between certificate data and live service observations. Censys provides a free research access tier and is widely used in academic and commercial security research.
- **[FOFA](https://fofa.info/):** A Chinese internet asset search engine operated by Beijing Huashun Xin'an Technology, functionally similar to Shodan but with particularly comprehensive coverage of Asian IP ranges and Chinese-language query syntax. FOFA is frequently used by Chinese state-sponsored threat actors including APT41 and Volt Typhoon.
- **[ZoomEye](https://www.zoomeye.org/):** A Chinese scan database operated by Knownsec, providing internet asset search capabilities with particular strength in IoT and industrial control system (ICS) device indexing.
- **[BinaryEdge](https://www.binaryedge.io/):** Provides internet-wide scan data with a focus on risk scoring and threat intelligence integration, indexing exposed services, misconfigured databases, and vulnerable software across the internet.
- **[GreyNoise](https://www.greynoise.io/):** Aggregates internet scan and noise data specifically to contextualise mass scanning activity, enabling distinction between targeted and opportunistic scanning traffic. Also provides intelligence on IP addresses actively conducting internet-wide scanning.

***

## Intelligence Categories Available Through Scan Databases

Scan database queries return several categories of adversarially relevant technical intelligence:

- **Open port inventory:** The complete list of TCP and UDP ports accepting connections on each IP address, providing a definitive map of every exposed service. Open port data directly enables targeted exploitation by revealing which services are reachable without requiring any active scanning by the adversary.
- **Service banner data:** Application-layer response data including HTTP response headers, SMTP EHLO responses, FTP banners, SSH identification strings, and RDP negotiation data. Banners frequently contain software name and version information that directly enables targeted vulnerability research.
- **Software version fingerprints:** Specific software version strings exposed in banners and HTTP headers enable adversaries to cross-reference identified versions against vulnerability databases (CVE, NVD) to identify known exploitable vulnerabilities affecting the target's specific software stack — the `Server: Apache/2.4.49` banner, for example, immediately identifies a system vulnerable to CVE-2021-41773 (path traversal and RCE).
- **Operating system fingerprints:** Protocol-level responses enable passive OS fingerprinting, revealing the underlying operating system and version running each service.
- **TLS certificate data:** Full TLS certificates served by each HTTPS endpoint are indexed, enabling correlation between certificate SAN fields (exposing subdomains and organisation identity), certificate fingerprints, and specific IP addresses — supporting both infrastructure mapping and subdomain discovery.
- **HTTP response content and headers:** Full HTTP response headers and selected body content including page titles, meta tags, and framework-specific markers are indexed, enabling queries for organisations by web framework, CMS platform, login portal type, or specific HTML content patterns.
- **Exposed management interfaces:** Scan databases index exposed management interfaces including RDP (3389), VNC (5900), SSH (22), Telnet (23), SNMP (161), web-based administration panels (common ports 8080, 8443, 9090, 10000), database ports (MySQL 3306, PostgreSQL 5432, MongoDB 27017, Elasticsearch 9200, Redis 6379), and industrial control system protocols (Modbus 502, DNP3 20000, IEC 60870-5-104 2404) — all of which represent direct initial access opportunities when discovered in a target's infrastructure.
- **Default credential indicators:** Scan databases index HTTP response page titles and content patterns for devices presenting default login credentials, enabling adversaries to identify target infrastructure running unmodified default configurations.

***

## Procedure Examples

### APT41 and FOFA
**APT41** uses the Chinese internet scan database **FOFA** (fofa.su / fofa.info) as a primary tool for passive reconnaissance of victim infrastructure, querying the platform for information about target organisations' internet-facing assets before conducting active operations. APT41's use of FOFA reflects a broader pattern of Chinese state-sponsored threat actors preferring Chinese-operated scanning platforms that provide equivalent functionality to Shodan and Censys while potentially being less subject to Western law enforcement requests for query log data. The group uses scan database intelligence for target development, identifying specific vulnerable services and exposed management interfaces before committing to active exploitation operations.

### APT41 DUST
**APT41 DUST** — a sub-cluster of APT41 activity — specifically used internet scan data for **target development**, demonstrating the use of scan database intelligence as a structured pre-operational planning input. By querying scan databases to map the internet-facing infrastructure of potential targets across sectors of interest, APT41 DUST builds actionable target packages identifying the specific services, software versions, and exposed access points that offer the most viable initial access pathways for subsequent operations.

### Volt Typhoon
**Volt Typhoon**, the Chinese state-sponsored threat actor attributed to People's Liberation Army (PLA) cyber operations and known for targeting US critical infrastructure for pre-positioning purposes, has used **FOFA**, **Shodan**, and **Censys** to search for exposed victim infrastructure. Volt Typhoon's use of multiple scan database platforms simultaneously reflects a systematic approach to comprehensive infrastructure intelligence gathering, using each platform's distinct coverage and query capabilities to build the most complete possible picture of target internet-facing exposure. The group specifically uses scan database reconnaissance to identify small office/home office (SOHO) routers and network edge devices that can be compromised and incorporated into the KVBT botnet used to proxy malicious traffic, with scan databases enabling identification of specific vulnerable router models at scale.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Scan database reconnaissance is conducted entirely through queries to external scanning platforms that have already collected data about the organisation's infrastructure through their own independent scanning operations. Mitigation efforts must focus on reducing the intelligence quality available through scan databases by hardening the organisation's internet-facing exposure:

- **Minimise internet-facing attack surface:** Identify and eliminate all internet-facing services that do not require direct internet accessibility, placing management interfaces, administrative portals, database services, and non-public APIs behind VPN or Zero Trust Network Access (ZTNA) gateways such as [Microsoft Entra Private Access](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-private-access) and [Cloudflare Zero Trust](https://www.cloudflare.com/en-gb/zero-trust/). Removing services from public internet accessibility removes them from scan database indexing.
- **Suppress software version banner disclosure:** Remove or sanitise software version and vendor strings from all internet-facing service banners and HTTP response headers — including `Server:`, `X-Powered-By:`, SSH identification strings, FTP banners, and SMTP EHLO responses — eliminating the direct vulnerability cross-reference capability that version-specific banner data provides to adversaries querying scan databases.
- **Implement network access controls for management interfaces:** Block all direct internet access to management protocol ports (RDP 3389, VNC 5900, SSH 22, SNMP 161, Telnet 23) at the network perimeter through firewall policy, preventing these services from being indexed in scan databases as accessible from the internet.
- **Patch internet-facing software promptly:** Since scan database-enabled vulnerability identification depends on correlating specific version strings against known CVEs, eliminating known-vulnerable software versions from internet-facing services removes the exploitation pathway that scan database reconnaissance most commonly enables. Prioritise patching based on CISA's [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue, which reflects vulnerabilities actively being operationalised by adversaries.
- **Proactive external attack surface assessment:** Conduct regular self-assessment using [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [Microsoft Defender EASM](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-external-attack-surface-management) to understand precisely what intelligence is currently available to adversaries querying scan databases for the organisation's IP ranges and domain names, enabling targeted hardening of the highest-risk indexed exposures before adversaries act on them.

***

## Detection Strategy

### Complete Passive Collection Opacity
Scan database queries are directed entirely at external third-party platforms and generate no observable artefacts within the target organisation's IT infrastructure. Direct detection of this reconnaissance activity is entirely infeasible.

### Downstream Exploitation Detection

Detection resources yield the highest value when focused on the exploitation attempts that scan database reconnaissance enables:

- **Exploitation attempt detection for known-vulnerable services:** Configure **IDS/IPS** rules in [Suricata](https://suricata.io/) and [Snort](https://www.snort.org/) with signatures targeting exploitation of vulnerabilities affecting software versions currently indexed in scan databases for the organisation's IP ranges. Cross-reference scan database entries against the CISA KEV catalogue and align IDS signature coverage accordingly.
- **Management interface access monitoring:** Monitor authentication logs for all internet-facing management interfaces — particularly those that should not be directly accessible from the internet — for inbound connection attempts from unexpected external IP addresses, alerting on access patterns consistent with credential stuffing or brute-force operations enabled by scan database-sourced target identification. Correlate source IPs against threat intelligence feeds in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel).
- **Honeypot service deployment:** Deploy low-interaction honeypot services on non-production IP addresses within the organisation's registered IP ranges using tools such as [OpenCanary](https://github.com/thinkst/opencanary) and [Canarytokens](https://canarytokens.org/). These services will be indexed by scan database platforms and may attract opportunistic exploitation attempts, providing early warning of adversarial targeting of the organisation's IP ranges and enabling collection of adversary infrastructure indicators for threat intelligence enrichment.
- **Network perimeter scanning detection:** Monitor for scanning activity against the organisation's IP ranges from external sources using **IDS** alerting on port scan patterns, correlating scan source IPs against GreyNoise mass-scanner classifications to distinguish opportunistic automated scanning from targeted reconnaissance campaigns. Targeted scanning against specific services identified through scan database queries — rather than sequential port sweeps — is a particularly significant indicator of pre-operational targeted reconnaissance.
