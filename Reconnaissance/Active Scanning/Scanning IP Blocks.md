# Scanning IP Blocks

Scanning IP blocks is a sub-technique of Active Scanning (**MITRE ATT&CK T1595.001**) in which adversaries systematically probe allocated IP address ranges belonging to a target organisation in order to enumerate live hosts, identify active services, and collect detailed infrastructure information for use in subsequent attack phases.

Public IP address blocks are typically allocated to organisations in contiguous ranges by Regional Internet Registries (RIRs) such as **ARIN**, **RIPE NCC**, or **APNIC**. This allocation model allows adversaries to efficiently scope and target an organisation's entire externally reachable IP space. Scanning techniques range from basic **ICMP echo requests (ping sweeps)** used to identify live hosts, to more sophisticated probing methods such as **TCP SYN scans**, **banner grabbing**, and **OS fingerprinting**, which can reveal host operating systems, running services, software versions, and open ports. Intelligence derived from these scans may feed directly into further reconnaissance activities (e.g., **T1593 – Search Open Websites/Domains**, **T1596 – Search Open Technical Databases**), resource development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and initial access operations (e.g., **T1133 – External Remote Services**).

***

## Procedure Examples

### Ember Bear
Ember Bear (also tracked as **UAC-0056** or **GhostWriter**) is a Russian-nexus threat actor group with a history of targeting government bodies and critical national infrastructure organisations. The group has been observed conducting targeted IP block scanning operations to identify vulnerable internet-facing systems within government and critical infrastructure networks, using the intelligence gathered to inform subsequent exploitation activity.

### TeamTNT
**TeamTNT** is a cloud-focused threat actor group known primarily for targeting misconfigured cloud environments, container infrastructure, and exposed APIs. The group has been observed maintaining and operating against curated lists of target IP addresses, conducting automated scans to identify exposed **Docker APIs**, **Kubernetes dashboards**, and **AWS credential files** for cryptojacking and credential harvesting campaigns.

***

## Mitigations: Pre-Compromise (MITRE M1056)

This sub-technique presents a limited preventive control surface, as the scanning activity is conducted entirely outside the bounds of the target organisation's enterprise defences, operating against externally reachable infrastructure from adversary-controlled systems. Conventional perimeter controls such as firewalls or intrusion prevention systems cannot block an adversary from probing publicly routable IP addresses. Mitigation efforts should therefore focus on the following principles:

- **Minimise external exposure:** Reduce the number of internet-facing services and open ports to the absolute minimum required for business operations. Enforce strict firewall egress and ingress rules and disable unnecessary protocols.
- **Obscure service banners:** Configure web servers, SSH daemons, and other network services to suppress or obfuscate version and software banners (e.g., disable Apache `ServerTokens`, modify SSH `Banner` directives) to limit the intelligence value of banner grabbing scans.
- **Manage IP block visibility:** Where operationally feasible, avoid registering unnecessarily large IP blocks in public RIR databases and ensure WHOIS records contain only the minimum required information.
- **Continuous EASM monitoring:** Proactively monitor your own external attack surface using tools such as [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [Attack Surface Management platforms](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-external-attack-surface-management) to identify exposed assets before adversaries do.

***

## Detection Strategy

### Network Traffic Monitoring
Deploy continuous network traffic monitoring to identify patterns consistent with systematic IP block scanning. Key indicators include repeated inbound connection attempts across multiple sequential IP addresses, high-frequency probes against closed or filtered ports, and unsolicited ICMP traffic originating from external IP ranges with no prior interaction history. Tools such as [Zeek (formerly Bro)](https://zeek.org/) and [Suricata](https://suricata.io/) can be deployed as network intrusion detection systems (NIDS) to detect and alert on these patterns in real time.

### Anomalous Data Flow Detection
Monitor network telemetry for uncommon or previously unseen data flows, particularly inbound connections initiated by external hosts that exhibit no legitimate business relationship with the organisation. Processes or services receiving network traffic that fall outside their established communication baseline should be flagged for investigation. **SIEM platforms** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) can be configured with correlation rules to aggregate and alert on scan-indicative behaviours, including high connection attempt rates, sequential port probing, and source IP anomalies. Threat intelligence enrichment via platforms such as [VirusTotal](https://www.virustotal.com/) or [AbuseIPDB](https://www.abuseipdb.com/) can further contextualise source IPs identified in scanning activity.
