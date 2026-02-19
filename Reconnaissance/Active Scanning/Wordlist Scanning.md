# Wordlist Scanning

Wordlist scanning is a sub-technique of Active Scanning (**MITRE ATT&CK T1595.003**) in which adversaries employ iterative, brute-force-driven probing techniques to enumerate web content, directories, DNS subdomains, API endpoints, and cloud storage resources. Unlike credential-based brute force attacks (**T1110**), the objective of wordlist scanning is not the discovery of valid authentication credentials but rather the identification of hidden or obscure infrastructure, legacy content, and misconfigured resources that may represent exploitable attack vectors.

Wordlists used in these operations may consist of generic dictionaries containing commonly used directory names, file extensions, and administrative path conventions (e.g., `/admin`, `/backup`, `/config`, `.env`, `.git`), or they may be purpose-built, target-specific lists constructed from intelligence gathered during prior reconnaissance phases, such as **T1591 – Gather Victim Org Information** or **T1594 – Search Victim-Owned Websites**. Custom wordlists may incorporate an organisation's internal terminology, product names, employee identifiers, or application-specific path structures to increase enumeration accuracy and efficiency.

***

## Procedure Examples

### APT41
**APT41** (also tracked as **Winnti** or **Barium**) is a Chinese state-sponsored threat actor group known for conducting both espionage and financially motivated intrusion operations. The group has been observed leveraging a variety of directory brute-forcing tools and custom frameworks to systematically enumerate web server directory structures, identifying legacy, unpatched, or otherwise hidden web application components as precursors to exploitation.

### Volatile Cedar
**Volatile Cedar** is a threat actor group with suspected ties to Lebanese Hezbollah, known for targeting organisations across the telecommunications, defence, and media sectors. The group has operationally deployed [DirBuster](https://www.kali.org/tools/dirbuster/) and [GoBuster](https://github.com/OJ/gobuster) to brute-force web directories and DNS subdomains against victim-facing web infrastructure, enabling the identification of exposed administrative panels, sensitive files, and unprotected application endpoints.

***

## Mitigations

### Disable or Remove Unnecessary External Resources (MITRE M1042)
Organisations should enforce a strict principle of least exposure by removing or disabling access to any systems, services, or infrastructure components that are not explicitly required to be publicly accessible. This includes decommissioning legacy web applications, removing deprecated API endpoints, disabling directory listing on web servers, and restricting access to administrative portals (e.g., `/wp-admin`, `/phpmyadmin`, `/manager`) via IP allowlisting or VPN-gated access controls. Web Application Firewalls (WAFs) such as [Cloudflare WAF](https://www.cloudflare.com/en-gb/application-services/products/waf/), [AWS WAF](https://aws.amazon.com/waf/), or [Imperva](https://www.imperva.com/products/web-application-firewall-waf/) can be configured with rate-limiting rules to throttle or block high-frequency enumeration requests.

### Cloud Storage Hardening
As cloud storage services such as **Amazon S3**, **Google Cloud Storage**, and **Azure Blob Storage** rely on globally unique, publicly resolvable naming conventions, adversaries can leverage target-specific wordlists alongside tools such as [s3recon](https://github.com/clarketm/s3recon) and [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) to enumerate both public and private cloud storage buckets. Organisations should enforce strict bucket access policies, disable public access by default, enable **Object-Level Logging** (e.g., AWS S3 Server Access Logging or AWS CloudTrail data events), and regularly audit bucket permissions using tools such as [ScoutSuite](https://github.com/nccgroup/ScoutSuite) or [Prowler](https://github.com/prowler-cloud/prowler) to prevent unauthorised data access via **T1530 – Data from Cloud Storage**.

### Pre-Compromise Posture (MITRE M1056)
As with other active scanning sub-techniques, the scanning activity itself occurs outside enterprise defensive boundaries and cannot be directly prevented through conventional controls. Mitigation efforts should focus on reducing the intelligence value of any discovered resources by ensuring that sensitive files, backup archives, configuration data, and administrative interfaces are never exposed to the public internet, and that web server configurations suppress directory listing and verbose error messages that could assist adversary enumeration.

***

## Detection Strategy

### High-Volume and Anomalous Request Monitoring
Monitor inbound web server and application logs for indicators of automated wordlist scanning activity. Key behavioural signatures include:

- **High-frequency HTTP requests** originating from a single source IP or a narrow IP range within a short time window, particularly targeting non-existent or uncommon paths resulting in a high volume of **HTTP 404 (Not Found)** or **HTTP 403 (Forbidden)** responses.
- **Sequential or pattern-based URL structures** consistent with dictionary enumeration, such as iterating through alphabetically ordered directory names or systematically appending common file extensions.
- **User-agent strings** associated with known scanning tools such as [DirBuster](https://www.kali.org/tools/dirbuster/), [GoBuster](https://github.com/OJ/gobuster), [ffuf](https://github.com/ffuf/ffuf), or [Feroxbuster](https://github.com/epi052/feroxbuster), though sophisticated adversaries may spoof legitimate browser user-agent strings to evade signature-based detection.
- **Traffic originating from known adversarial infrastructure**, botnets, or Tor exit nodes, identifiable through threat intelligence enrichment using services such as [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/).

### SIEM Correlation and Alerting
Aggregate web application logs, WAF telemetry, and network flow data within a **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) and implement correlation rules to detect and alert on enumeration-indicative patterns, including sustained 404 response rate spikes and abnormal request velocity thresholds from individual source IPs. Network intrusion detection systems such as [Suricata](https://suricata.io/) and [Zeek](https://zeek.org/) can complement SIEM alerting with real-time packet-level visibility into scanning tool signatures.
