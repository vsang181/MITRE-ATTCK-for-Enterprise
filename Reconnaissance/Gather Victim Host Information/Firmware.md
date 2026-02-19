# Firmware

Firmware reconnaissance is a sub-technique of Gather Victim Host Information (**MITRE ATT&CK T1592.003**) in which adversaries collect intelligence about the firmware installed on victim host devices, network appliances, and embedded systems. Firmware-level intelligence may include the firmware type, vendor, and version running on specific devices such as routers, switches, firewalls, VPN concentrators, BIOS/UEFI components, industrial controllers, and IoT devices. This information allows adversaries to infer broader contextual details about the target environment, including device age, patch level, operational purpose, and susceptibility to publicly disclosed firmware-level vulnerabilities.

Unlike software reconnaissance, firmware enumeration is a more constrained collection activity. Firmware version information is rarely exposed through direct network interaction, as most firmware does not surface version details through standard service banners or port responses. As a result, adversaries predominantly rely on **indirect and passive collection methods** to obtain firmware intelligence, making this sub-technique particularly difficult to detect and attribute. The intelligence gathered can directly inform further reconnaissance (e.g., **T1593 – Search Open Websites/Domains**, **T1596 – Search Open Technical Databases**), capability development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and targeted initial access operations (e.g., **T1195 – Supply Chain Compromise**, **T1190 – Exploit Public-Facing Application**).

***

## Collection Vectors

Due to the limited direct exposure of firmware information through network-facing services, adversaries typically gather firmware intelligence through a combination of passive OSINT collection and targeted social engineering:

- **Open Source Intelligence (OSINT):** Firmware details are frequently and inadvertently disclosed through a range of publicly accessible sources including:
  - **Job postings** specifying required experience with particular network device platforms, firmware management tools, or vendor certification requirements (e.g., Cisco IOS, Juniper Junos, Palo Alto PAN-OS).
  - **Employee resumes and LinkedIn profiles** listing specific network device platforms, firmware environments, and associated certifications such as CCNA, CCNP, or Juniper JNCIA.
  - **Network architecture and assessment reports** inadvertently published or leaked, which may include device inventories with firmware version details.
  - **Procurement records and purchase invoices** accessible through public tender portals, government procurement databases, or financial disclosures.
  - **Vendor case studies and product deployment announcements** referencing specific hardware and firmware deployments at named organisations.
- **Phishing for Information (T1598):** Adversaries may conduct targeted spearphishing campaigns against IT and network operations personnel to directly elicit firmware inventory details, network device configurations, or maintenance schedules through pretexting as vendor support representatives, auditors, or regulatory bodies.
- **Active Scanning via Management Interfaces:** Where network device management interfaces such as **SNMP**, **Cisco Smart Install**, **Netconf/YANG**, or vendor-specific web management portals are exposed to the internet, adversaries may query these services to extract device model and firmware version information. Tools such as [Shodan](https://www.shodan.io/) and [Censys](https://censys.io/) index firmware version data from exposed management interfaces and login pages, making this intelligence passively accessible without any direct engagement with the target.
- **Exploit-DB and CVE Cross-Referencing:** Once a firmware version is identified through any of the above methods, adversaries cross-reference it against public vulnerability databases including the **National Vulnerability Database (NVD)**, [Exploit-DB](https://www.exploit-db.com/), and vendor security advisories to identify unpatched firmware vulnerabilities that can be targeted during the exploitation phase. Firmware vulnerabilities in widely deployed network appliances, such as those historically identified in **Fortinet FortiOS**, **Cisco IOS XE**, **Citrix NetScaler**, and **Pulse Secure VPN**, have been extensively exploited by nation-state threat actors following firmware version disclosure.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Firmware reconnaissance occurs predominantly outside the target organisation's network perimeter and through passive data collection methods, placing it largely beyond the reach of conventional enterprise defensive controls. Mitigation efforts should focus on minimising the exposure and intelligence value of firmware-related information accessible to external parties:

- **Audit and restrict public information disclosure:** Conduct regular reviews of job postings, corporate websites, press releases, and employee professional profiles to identify and remediate references to specific network device vendors, platforms, and firmware environments. Ensure procurement records and network assessment outputs are appropriately classified and not exposed through public-facing systems.
- **Restrict and secure management interfaces:** Ensure that all network device management interfaces, including **SNMP**, **SSH**, **Telnet**, **HTTP/HTTPS management portals**, **Cisco Smart Install**, and **IPMI**, are never exposed to the public internet. Place management interfaces on dedicated, isolated management VLANs accessible only from authorised jump hosts or bastion servers. Disable legacy protocols such as SNMP v1/v2c and Telnet entirely in favour of **SNMPv3 with authentication and privacy** and **SSHv2**.
- **Proactive firmware patch management:** Implement a structured firmware patch management programme to ensure all network devices, appliances, and embedded systems are running current, vendor-supported firmware versions. Utilise network configuration and compliance management platforms such as [SolarWinds Network Configuration Manager](https://www.solarwinds.com/network-configuration-manager), [ManageEngine Network Configuration Manager](https://www.manageengine.com/network-configuration-manager/), or [Cisco DNA Center](https://www.cisco.com/c/en/us/products/cloud-systems-management/dna-center/index.html) to maintain firmware version baselines and automate compliance reporting.
- **Supply chain integrity controls:** Implement hardware and firmware supply chain verification procedures including vendor-provided **firmware signing validation**, **Secure Boot** enforcement, and tamper-evident packaging inspection upon device receipt, mitigating the risk of **T1195.003 – Compromise Hardware Supply Chain** in which firmware may be modified prior to delivery.
- **Suppress firmware version disclosure on management portals:** Configure network device web management interfaces and login pages to suppress firmware version banners and device model information that could be indexed by internet scanning platforms such as [Shodan](https://www.shodan.io/).

***

## Detection Strategy

### Passive and Out-of-Band Collection Challenges

Detection of firmware-focused reconnaissance activity presents considerable challenges for defenders. The majority of firmware intelligence collection occurs through entirely passive OSINT methods, operating against publicly accessible data sources with no interaction with the target organisation's network infrastructure whatsoever. As such, there are no network-level indicators of compromise generated during the collection phase, and detection through conventional perimeter monitoring tools is not feasible.

Internet-facing management interfaces should be monitored for anomalous inbound queries from external IP ranges, including unsolicited SNMP requests, automated HTTP requests to device management login pages bearing scanning tool User-Agent strings, and authentication attempts against SSH management interfaces. Network intrusion detection systems such as [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/) can be configured with rules to alert on these patterns, and identified source IPs should be enriched using threat intelligence services such as [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) to assess adversarial attribution.

### Detection Pivot to Firmware Exploitation Indicators

Given the near-invisibility of the reconnaissance phase, detection resources are most effectively deployed against the **Initial Access** and **Execution** stages at which collected firmware intelligence is operationally applied. Defenders should implement monitoring controls specifically aligned with firmware-level exploitation indicators, including:

- **Unexpected firmware modification attempts** or unauthorised firmware update activity on network devices, detectable through configuration change monitoring within platforms such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel).
- **Exploitation attempts against known firmware CVEs** relevant to devices deployed within the environment, identifiable through correlation of IDS/IPS alerts with published vulnerability intelligence from platforms such as [Recorded Future](https://www.recordedfuture.com/) and [MISP](https://www.misp-project.org/).
- **Anomalous outbound connections from network appliances**, which may indicate successful firmware-level implantation consistent with threats such as **Volt Typhoon's** deployment of the **KV-Botnet** within edge network devices, or **Sandworm Team's** **VPNFilter** malware targeting consumer and small business routers.
