# DNS/Passive DNS

DNS/Passive DNS is a sub-technique of Search Open Technical Databases (**MITRE ATT&CK T1596.001**) in which adversaries query DNS records and passive DNS repositories to enumerate a target organisation's internet-facing infrastructure, subdomain landscape, and network addressing.  DNS is a foundational reconnaissance data source because every public-facing internet service — web servers, mail servers, VPN gateways, and cloud-hosted resources — must be registered in DNS to be accessible, meaning the DNS record set for an organisation's domains constitutes a near-complete map of its internet-facing infrastructure.

Intelligence gathered through DNS and passive DNS reconnaissance can directly inform further reconnaissance (e.g., **T1593 – Search Open Websites/Domains**, **T1595 – Active Scanning**), support resource development (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and enable initial access via **T1133 – External Remote Services** and **T1199 – Trusted Relationship**.

***

## Active DNS vs. Passive DNS Reconnaissance

These two approaches to DNS-based intelligence gathering are complementary and serve distinct adversarial purposes:

| Dimension | Active DNS Querying | Passive DNS Reconnaissance |
|---|---|---|
| **Method** | Directly querying authoritative nameservers for the target domain using tools such as `dig`, `nslookup`, and `nmap` | Querying centralised databases of historically logged DNS resolution data collected from sensor networks positioned above recursive resolvers |
| **Target interaction** | Generates DNS query traffic observable in the target's nameserver logs | Entirely passive — no contact with target infrastructure whatsoever |
| **Data currency** | Returns current live DNS records only | Returns both current and historical records with timestamps showing when resolutions were active |
| **Key intelligence** | Current A, AAAA, MX, NS, TXT, CNAME, and SOA records; zone transfer vulnerabilities | Historical IP mappings, previously active subdomains, domain infrastructure evolution, co-hosted domain relationships |
| **Primary tools** | `dig`, `nslookup`, [DNSdumpster](https://dnsdumpster.com/), [theHarvester](https://github.com/laramies/theHarvester) | [Farsight DNSDB](https://www.farsightsecurity.com/), [SecurityTrails](https://securitytrails.com/), [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/), [DomainTools Iris](https://www.domaintools.com/), [Spamhaus Passive DNS](https://www.spamhaus.com/), [PassiveTotal/RiskIQ](https://www.riskiq.com/) |

***

## How Passive DNS Databases Are Built

Passive DNS was conceived by **Florian Weimer in 2005** as a mechanism to log DNS resolution traffic without requiring cooperation from zone administrators or active DNS communication.  Sensors are positioned at strategic points in the DNS resolution path — above recursive resolvers, within ISP infrastructure, inside large enterprise networks, and at hosting providers — where they capture inter-server DNS messages in transit and forward them to centralised collection points.  The collected data is anonymised, normalised, and inserted into queryable databases:

- **[Spamhaus Passive DNS](https://www.spamhaus.com/)** processes more than **200 million DNS records per hour** and stores hundreds of billions of records per month, sourced from thousands of recursive DNS servers globally through partnerships with hosting companies, enterprises, and ISPs.
- **[Farsight DNSDB](https://www.farsightsecurity.com/)** was one of the pioneer passive DNS platforms, collecting data through a global sensor array supplemented by ICANN-sponsored zone file access for multiple TLDs, providing both passive observation data and authoritative zone file coverage.
- **[RiskIQ PassiveTotal](https://www.riskiq.com/)** ingests approximately **400 million unique DNS records per day** through a geographically dispersed sensor and partner network.
- **[CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/)** provides a freely accessible historical DNS record database maintained by the Computer Incident Response Center Luxembourg.

***

## DNS Record Types and Adversarial Intelligence Value

Each DNS record type provides a distinct category of adversarially relevant intelligence:

- **A / AAAA records:** Map domain and subdomain names to IPv4 and IPv6 addresses, directly revealing the IP address of every named internet-facing service. Historical A record data reveals past IP allocations, identifying IP ranges previously used by the organisation that may still host legacy systems.
- **MX records:** Identify the organisation's mail exchange servers by hostname and priority, enabling adversaries to enumerate email infrastructure for email spoofing campaign planning and to identify mail server software through subsequent banner queries.
- **NS records:** Identify the authoritative nameservers for the domain, revealing DNS provider relationships and enabling targeted nameserver queries. Shared nameserver relationships across multiple domains can reveal infrastructure clustering and business relationships.
- **TXT records:** Contain miscellaneous machine-readable data including **SPF policy records** (revealing all authorised mail-sending infrastructure), **DKIM public keys**, **DMARC policies**, **domain verification tokens** for third-party SaaS services (revealing which platforms the organisation uses), and **BIMI records**.
- **CNAME records:** Reveal aliasing relationships between subdomains and their target hostnames, exposing third-party services and CDN providers in use and identifying potential **subdomain takeover** opportunities where a CNAME target has been deprovisioned but the CNAME record persists.
- **SOA records:** Provide zone administrative information including the primary nameserver, responsible party contact, and zone serial number, useful for infrastructure mapping.

***

## DNS Zone Transfers and Misconfiguration Exploitation

A historically significant — and still occasionally encountered — DNS reconnaissance technique is the **DNS zone transfer (AXFR request)**, in which an adversary sends a request to a target's authoritative nameserver asking for a complete copy of the DNS zone file.  A correctly configured nameserver will reject zone transfer requests from non-authorised IP addresses (typically limited to secondary nameservers). However, misconfigured nameservers that permit unrestricted zone transfers expose the complete DNS zone — every subdomain, every internal hostname, every network address mapping — in a single query, effectively providing the adversary with a complete organisational network map.

Modern passive DNS collection approaches have largely superseded the need for zone transfer exploitation, as passive DNS databases now provide equivalent or superior subdomain enumeration capability without triggering the detectable AXFR query. However, zone transfer misconfiguration testing remains a standard component of DNS security assessment because misconfigured nameservers continue to be identified in production environments.

***

## Subdomain Enumeration: The Primary Adversarial Use Case

The most operationally significant output of DNS/Passive DNS reconnaissance is typically **subdomain enumeration** — the construction of a comprehensive map of all subdomains registered under the target organisation's apex domains.  Adversaries enumerate subdomains to identify:

- **Forgotten or undocumented assets:** Subdomains created for development, testing, or one-time projects that were never properly decommissioned but may still be reachable and running unpatched software.
- **Third-party service integrations:** Subdomains pointing to SaaS platforms and cloud services through CNAME records reveal the specific third-party services integrated into the organisation's infrastructure, including HR portals, customer support platforms, marketing tools, and collaboration services.
- **CDN origin server bypasses:** Subdomains that resolve directly to origin server IP addresses rather than CDN infrastructure enable adversaries to reach origin servers directly, bypassing CDN-layer DDoS protection and WAF filtering.
- **Subdomain takeover opportunities:** CNAME records pointing to deprovisioned third-party service hostnames (e.g., unclaimed GitHub Pages, Heroku, or AWS S3 bucket addresses) can be claimed by adversaries who register the target resource, enabling them to serve malicious content under the target organisation's subdomain — a highly convincing phishing vector.

Automated subdomain enumeration tools such as [subfinder](https://github.com/projectdiscovery/subfinder) query dozens of passive DNS, certificate transparency, and search engine sources simultaneously, returning hundreds or thousands of subdomains for large organisations within minutes.

***

## Mitigations: Pre-Compromise (MITRE M1056)

DNS reconnaissance is conducted entirely through queries to external passive DNS platforms and live nameserver queries, generating no artefacts within the target organisation's security monitoring infrastructure beyond routine DNS query traffic at its own nameservers.  Mitigation efforts should focus on reducing the quality and breadth of DNS intelligence available to adversaries:

- **Restrict zone transfers:** Configure all authoritative nameservers to permit zone transfer (AXFR) requests **only from explicitly whitelisted secondary nameserver IP addresses**, rejecting all other zone transfer requests. Validate this configuration regularly through external DNS security assessment.
- **Minimise internal hostname exposure in public DNS:** Avoid publishing internal network hostnames, private IP addresses, and internal service names in public DNS zones. Split-horizon DNS configurations using separate internal and external DNS views prevent internal network addressing from appearing in externally accessible DNS records.
- **DNSSEC deployment:** Enable **DNSSEC** on all organisational domains to cryptographically authenticate DNS responses, preventing DNS record tampering and cache poisoning attacks that could redirect DNS queries to adversary-controlled infrastructure.
- **Subdomain hygiene:** Conduct regular audits of all DNS records across organisational domains, identifying and removing CNAME records pointing to deprovisioned third-party resources that may be vulnerable to subdomain takeover. Tools such as [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) document known subdomain takeover vulnerabilities for specific service providers.
- **Proactive passive DNS self-assessment:** Regularly query passive DNS databases ([SecurityTrails](https://securitytrails.com/), [DomainTools Iris](https://www.domaintools.com/)) using the organisation's own domains to understand the historical subdomain and IP mapping data available to adversaries, identifying undocumented or forgotten assets requiring remediation.
  
***

## Detection Strategy

### Complete Passive Collection Opacity
Passive DNS database queries generate no contact with the target organisation's infrastructure and are entirely invisible to the target's monitoring controls.  Active DNS queries against the organisation's authoritative nameservers do generate query log entries, but these are indistinguishable from legitimate resolver traffic at normal volumes and have an extremely high false positive rate.

### Downstream Exploitation Detection
- **Subdomain takeover monitoring:** Continuously monitor CNAME records across all organisational domains for records pointing to deprovisioned or unclaimed third-party service hostnames using tools such as [SubOver](https://github.com/Ice3man543/SubOver) and cloud-native monitoring, alerting on CNAME targets that resolve to service provider "resource not found" pages indicative of takeover vulnerability.
- **Unexpected subdomain access monitoring:** Monitor web server and load balancer access logs for inbound traffic to subdomains not included in the known active asset inventory, which may indicate adversaries testing access to forgotten assets discovered through passive DNS enumeration. Correlate with **SIEM** alerting in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel).
- **Certificate Transparency cross-referencing:** Cross-reference CT log monitoring (via [crt.sh](https://crt.sh/) and [Certstream](https://certstream.calidog.io/)) against passive DNS subdomain enumeration findings to identify adversary-registered lookalike domains targeting the organisation's brand, enabling proactive takedown before phishing campaigns are launched using discovered subdomain naming patterns.
