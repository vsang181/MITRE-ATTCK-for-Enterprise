# DNS

DNS reconnaissance is a sub-technique of Gather Victim Network Information (**MITRE ATT&CK T1590.002**) in which adversaries collect detailed intelligence about a target organisation's Domain Name System configuration to inform targeting, infrastructure mapping, and attack planning.  DNS data can reveal a broad range of operationally useful intelligence, including registered name servers, subdomain structures, mail server configurations, and host-to-IP address mappings.  DNS MX, TXT, and SPF records are of particular value as they frequently expose the use of third-party cloud and SaaS providers, including **Office 365**, **Google Workspace**, **Salesforce**, and **Zendesk**, enabling adversaries to identify which external services an organisation relies upon and to target those services as entry points or impersonation vectors. 

DNS intelligence may be gathered through direct DNS queries, large-scale automated enumeration, passive DNS databases, and open technical data sources.  Adversaries may also attempt **DNS zone transfers (AXFR)** against misconfigured authoritative name servers to retrieve a complete copy of the zone file in a single query, dramatically accelerating infrastructure discovery and exposing assets that may never have been directly disclosed.  The gathered intelligence can drive further reconnaissance (e.g., **T1596 – Search Open Technical Databases**, **T1593 – Search Open Websites/Domains**, **T1595 – Active Scanning**), support resource development (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and enable initial access via **T1133 – External Remote Services**. 

***

## Key DNS Record Types Relevant to Reconnaissance

Different DNS record types yield distinct categories of intelligence about a target's network infrastructure: 
| Record Type | Purpose | Reconnaissance Value |
|---|---|---|
| **A / AAAA** | Map hostnames to IPv4 and IPv6 addresses | Identifies specific servers and internet-facing services by IP address |
| **NS** | Identifies authoritative name servers | Reveals name server infrastructure for further probing and zone transfer attempts |
| **MX** | Specifies mail server routing | Exposes corporate email infrastructure and potential exploitation or phishing targets |
| **TXT (SPF, DKIM, DMARC)** | Stores email authentication policies and arbitrary text | Reveals third-party email providers, security vendors, and SaaS platform dependencies |
| **CNAME** | Aliases one hostname to another | Exposes CDN providers, proxy services, and upstream origin infrastructure |
| **SOA** | Provides zone administrative metadata | Discloses primary name server identity and zone maintenance contact details |
| **PTR** | Enables reverse DNS lookups (IP to hostname) | Supports reverse infrastructure enumeration when rDNS records are populated |

***

## Collection Vectors

Adversaries employ several active and passive methods to gather DNS intelligence:

- **Direct DNS Querying:** Standard command-line tools including `dig`, `nslookup`, and `host` are used to query individual record types against authoritative or public resolvers. Queries such as `dig targetdomain.com ANY` attempt to retrieve all available records for a domain in a single request, while targeted queries for MX, TXT, and NS record types extract specific categories of intelligence. 
- **Subdomain Brute-Forcing:** Automated tools including [Amass](https://github.com/owasp-amass/amass), [Subfinder](https://github.com/projectdiscovery/subfinder), [dnsx](https://github.com/projectdiscovery/dnsx), and [MassDNS](https://github.com/blechschmidt/massdns) query the target DNS server using large wordlists of common prefixes such as `dev`, `staging`, `vpn`, `api`, and `mail` to enumerate valid subdomains by identifying those that return a resolving IP address.  Discovering subdomains through this method can expose legacy, unpatched, or staging environments that represent lower-resistance entry points into the target infrastructure. 
- **DNS Zone Transfer (AXFR):** Where name servers are misconfigured to permit transfers from arbitrary clients, adversaries issue AXFR queries using `dig AXFR @nameserver domain.com` or specialised tools such as [DNSrecon](https://github.com/darkoperator/dnsrecon) and [Fierce](https://github.com/mschwager/fierce) to retrieve the complete zone file, exposing all subdomains, internal hostnames, and associated records in a single operation.  Zone transfer exposure dramatically reduces the time and effort required for comprehensive subdomain enumeration and may reveal internal-only hostnames inadvertently included in externally authoritative zones. 
- **DNS Pivoting:** Adversaries use individual DNS records as pivot points to discover additional infrastructure. Shared NS records can reveal other domains hosted on the same name server infrastructure, CNAME chains expose CDN and proxy origin servers, and reverse PTR lookups map IP addresses back to hostnames across an organisation's allocated address space.  Each pivot expands the enumerated infrastructure footprint iteratively, enabling comprehensive attack surface discovery from a single initial data point. 
- **Passive DNS Databases:** Platforms including [SecurityTrails](https://securitytrails.com/), [RiskIQ PassiveTotal](https://community.riskiq.com/), and [WhoisXML DNS History](https://main.whoisxmlapi.com/) aggregate historical DNS query and response data, enabling adversaries to access prior DNS records, subdomain changes, and historical IP resolutions for a domain without issuing a single query to the target's authoritative name servers.  This entirely passive collection method leaves no observable trace in the target's DNS or network logs. 
- **Open Technical Databases and Scan Platforms:** [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [DNSDumpster](https://dnsdumpster.com/) index DNS records and associated network data from internet-wide scanning operations, providing pre-enumerated DNS intelligence accessible through a web interface or API.
- **Certificate Transparency Logs:** Public SSL/TLS certificate logs including [crt.sh](https://crt.sh/) expose all issued certificates for a domain, with Subject Alternative Names (SANs) frequently revealing internal subdomain naming conventions and previously undisclosed infrastructure.

***

## DNS Zone Transfer (AXFR) in Detail

Zone transfer is a legitimate DNS replication mechanism used to synchronise zone data from primary to secondary authoritative name servers.  When misconfigured to permit transfers from arbitrary sources rather than only from designated secondary servers, AXFR requests can be fulfilled for any external client, exposing: 

- A complete and authoritative list of all hostnames and records within the zone. 
- Internal naming conventions that may reveal environment type (e.g., `dev-`, `staging-`, `prod-`) and server function.
- Internal-only hostnames inadvertently included in externally published zones.
- Comments and metadata embedded in zone files by administrators that may disclose additional operational details. 

Tools commonly used to test for and exploit misconfigured zone transfers include [DNSrecon](https://github.com/darkoperator/dnsrecon), `dig` (`dig AXFR @nameserver domain.com`), [Fierce](https://github.com/mschwager/fierce), and the online [HackerTarget Zone Transfer Test](https://hackertarget.com/zone-transfer/). 

***

## Mitigations

### Software Configuration (MITRE M1054)
DNS servers must be configured with **zone transfer access control policies** that explicitly restrict AXFR to a tightly defined list of authorised secondary name server IP addresses.  This is typically enforced through: 

- Access Control Lists (ACLs) within the DNS server configuration (e.g., `allow-transfer` directive in **BIND**, equivalent constructs in **Microsoft DNS**, **PowerDNS**, and **Unbound**).
- Network-layer firewall rules limiting inbound TCP port 53 AXFR traffic to approved secondary server IP addresses only.
- Cloud DNS provider configuration hardening, as default settings on some providers may permit unrestricted zone transfers until explicitly customised by the account operator. 
Additional defensive measures include:

- Implementing **DNSSEC** to cryptographically sign DNS records and protect zone data integrity, preventing spoofing or cache poisoning of enumerated records even when record data itself is publicly accessible. 
- Regularly auditing published DNS records to remove stale, obsolete, or overly informative entries including deprecated subdomain records, legacy MX configurations, and TXT records exposing decommissioned service dependencies. 
- Enforcing **DNS split-horizon** configurations to prevent internal-only hostnames from appearing in externally authoritative zones, ensuring that zone transfer exposure, if it occurs, does not reveal internal infrastructure details. 

***

## Detection Strategy

### Passive Collection Limitations

The majority of DNS reconnaissance consists of standard query activity — A, MX, TXT, and NS record lookups — that is indistinguishable from legitimate resolver traffic and generates a high volume of benign events.  Passive DNS collection and open platform querying occur entirely off the target's infrastructure and leave no observable trace, making precise detection of DNS reconnaissance largely infeasible through conventional perimeter monitoring alone. 

### Zone Transfer and Anomalous Query Detection

The highest-confidence detection opportunity within this sub-technique arises from active enumeration activity, particularly unauthorised zone transfer attempts. Defenders should implement the following detection controls:

- **Monitor DNS traffic for unauthorised AXFR requests:** DNS server logs and network traffic captures (using tools such as [Wireshark](https://www.wireshark.org/) filtering on TCP port 53) should be monitored for AXFR requests originating from IP addresses not designated as authorised secondary name servers.  Many **IDS/IPS platforms** including [Suricata](https://suricata.io/) and [Zeek](https://zeek.org/) include signatures for unauthorised zone transfer attempts and can generate real-time alerts when such traffic is detected. 
- **Identify anomalous query volume and structure:** High-frequency, sequential DNS queries consistent with automated subdomain brute-forcing, reverse PTR sweep activity, or exhaustive record type enumeration should be flagged as indicative of active DNS reconnaissance.  DNS log analysis platforms and **SIEM solutions** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) can be configured with correlation rules to alert on sustained enumeration patterns from single external source IPs. 
- **DNS log cross-referencing with threat intelligence:** DNS query logs should be continuously cross-referenced against threat intelligence feeds using platforms such as [Cisco Umbrella](https://umbrella.cisco.com/), [Recorded Future](https://www.recordedfuture.com/), and [VirusTotal](https://www.virustotal.com/) to identify queries resolving to known malicious infrastructure or originating from adversary-associated IP ranges. 
- **Detection pivot to Initial Access:** Given the inherent limitations of detecting passive DNS reconnaissance, defenders should correlate DNS telemetry with downstream activity at the **Initial Access** and **Exploitation** stages, including scanning of hosts discovered via DNS enumeration, phishing campaigns impersonating services revealed through MX and SPF records, and exploitation attempts against subdomains identified through enumeration activity. 
