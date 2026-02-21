# Network Topology

Network Topology reconnaissance is a sub-technique of Gather Victim Network Information (**MITRE ATT&CK T1590.004**) in which adversaries collect intelligence about the physical and logical arrangement of a target organisation's network environment, encompassing both external-facing and internal infrastructure.  Topology intelligence may include the arrangement of network segments and VLANs, routing configurations, inter-segment connectivity, the location and function of network devices such as gateways, routers, switches, and load balancers, as well as the positioning of critical infrastructure components such as domain controllers, databases, and OT/ICS systems relative to network boundaries. 

This intelligence is operationally foundational to attack planning. A comprehensive network topology map enables adversaries to identify the most direct paths to high-value targets, anticipate network-based detection and prevention controls, select appropriate lateral movement techniques, and scope the blast radius of destructive payloads before deployment.  Gathered topology intelligence can inform further reconnaissance (e.g., **T1596 – Search Open Technical Databases**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and enable initial access via **T1133 – External Remote Services**.

***

## Collection Vectors

Adversaries use a structured combination of passive and active methods to enumerate and reconstruct network topology:

- **Active Network Scanning:** [Nmap](https://nmap.org/) is the most widely used network topology mapping tool, supporting host discovery through ICMP sweep (`nmap -sn 192.168.1.0/24`), SYN scanning for open port identification, OS fingerprinting, service version detection, and traceroute-integrated topology mapping (`nmap -sS --traceroute <target>`).  [Masscan](https://github.com/robertdavidgraham/masscan) and [ZMap](https://zmap.io/) extend this capability to internet-scale scanning, capable of processing millions of hosts per minute to identify exposed services across large IP ranges. 
- **Traceroute-Based Topology Inference:** Tools including `traceroute`, `tracert`, and [Paris Traceroute](https://paris-traceroute.net/) map the routing path between adversary infrastructure and target hosts by analysing ICMP TTL-exceeded responses from intermediate routers, progressively revealing the network path, hop count, and intermediate routing devices between the adversary's position and the target system. 
- **SNMP Reconnaissance:** Where **Simple Network Management Protocol (SNMP)** is exposed on network devices with default or weak community strings, adversaries can query device MIBs (Management Information Bases) to retrieve routing tables, ARP caches, connected device inventories, interface configurations, and network topology data directly from network infrastructure devices without requiring a privileged host compromise. Tools such as [SNMPwalk](https://linux.die.net/man/1/snmpwalk) and [snmp-check](https://gitlab.com/kalilinux/packages/snmp-check) automate bulk SNMP data extraction.
- **Living-Off-the-Land (LotL) Internal Enumeration:** Following initial access, adversaries exploit native operating system utilities to enumerate internal network topology without deploying third-party tooling that would trigger EDR detection.  Commonly used LotL commands for network topology mapping include: 
  - `ipconfig /all` — local interface configurations, default gateway, and DNS server assignments.
  - `arp -a` — ARP cache revealing recently contacted hosts and their MAC addresses.
  - `netstat -ano` — active network connections and listening ports.
  - `tracert <target>` — routing path to specific hosts, revealing intermediate network devices.
  - `net view` and `net view /domain` — discovery of network shares and domain-joined host names.
  - `route print` — routing table exposing subnet layout and gateway assignments.
- **Network Device Configuration Exploitation:** Following the compromise of network devices such as routers, switches, or firewalls, adversaries extract configuration files that contain complete routing tables, interface configurations, access control lists, and VLAN assignments, providing a highly authoritative topology map of the surrounding network environment.  **Salt Typhoon** operationally exploited this approach, using configuration files extracted from compromised network devices to enumerate upstream and downstream network segments connected to the initially compromised device. 
- **Search Victim-Owned Websites:** Network topology information may be inadvertently exposed through publicly accessible content including leaked architecture diagrams, case studies published by technology vendors, conference presentation slides, and job postings describing internal network infrastructure requirements. 
- **SharpHound and Active Directory Enumeration:** Tools such as [SharpHound](https://github.com/BloodHoundAD/SharpHound) and [BloodHound](https://github.com/BloodHoundAD/BloodHound) map Active Directory topology including domain trust relationships, user and group memberships, computer objects, and ACL configurations, generating a comprehensive graph of authentication and authorisation relationships within the internal network environment. 

***

## Procedure Examples

### FIN13 (Elephant Beetle)
**FIN13** is a financially motivated threat actor group with a sustained focus on Mexican financial institutions. During its reconnaissance operations, FIN13 actively searched for infrastructure that could provide persistent remote access to target environments, enumerating internet-facing services, VPN appliances, and remote desktop infrastructure to identify accessible external entry points as precursors to targeted intrusion campaigns. 

### Salt Typhoon
**Salt Typhoon** is a Chinese state-sponsored APT group associated with telecommunications sector targeting. The group exploited compromised network devices to extract configuration files, using the routing table and interface configuration data contained within those files to enumerate upstream and downstream network segments connected to the compromised device.  This technique enables rapid and authoritative topology reconstruction from a single compromised network appliance, providing far more reliable and complete network mapping data than active scanning alone. Salt Typhoon's operational approach demonstrates the compounding intelligence yield achievable when network device compromise is combined with configuration file analysis. 

### Volt Typhoon
**Volt Typhoon** conducted extensive pre-compromise and post-compromise reconnaissance of victim networks, including detailed identification and mapping of network topologies.  Consistent with its **Living Off the Land (LotL)** operational philosophy, the group relied on native Windows and network utilities for topology mapping, using `netsh`, `ipconfig`, `arp`, `net`, and `tracert` to enumerate network configurations and connectivity from within compromised endpoints without deploying third-party tooling.  Volt Typhoon's network topology intelligence directly supported its sustained, low-detectability persistent access operations within US critical infrastructure environments, enabling precise lateral movement and the identification of high-value operational technology systems while evading conventional EDR and antivirus detection. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Network topology reconnaissance conducted through passive OSINT and publicly accessible data sources falls entirely outside the reach of enterprise perimeter controls.  Post-compromise topology enumeration using LotL techniques is inherently difficult to prevent, as the underlying utilities have legitimate administrative uses. Mitigation efforts should focus on reducing external topology exposure and limiting the scope and utility of internal enumeration: 

- **Suppress topology information from public sources:** Ensure network architecture diagrams, infrastructure documentation, and topology-sensitive materials are classified as internal documents and stored exclusively within access-controlled repositories, never exposed through public-facing websites, cloud storage, or employee-published presentations. Audit vendor case studies and conference presentations for inadvertent topology disclosures before publication. 
- **Harden SNMP configurations:** Disable SNMP on all devices where it is not operationally required. Where SNMP is needed, upgrade to **SNMPv3** with strong authentication and encryption, replace default community strings with strong randomly generated values, and restrict SNMP access using ACLs to authorised management hosts on dedicated management VLANs only. 
- **Implement network micro-segmentation:** Deploy network micro-segmentation using solutions such as [Illumio Core](https://www.illumio.com/products/illumio-core) and [Akamai Guardicore Segmentation](https://www.akamai.com/products/guardicore-segmentation) to restrict lateral movement between network segments, limiting the scope of topology that can be enumerated from any single compromised host. 
- **Restrict unnecessary routing protocol exposure:** Disable routing protocols and services on endpoints and servers that are not required to participate in routing (e.g., OSPF, BGP, RIP), and implement route filtering to prevent unauthorised hosts from obtaining detailed routing table information. 
- **Harden network device access:** Restrict access to network device management interfaces (SSH, HTTPS, SNMP) to authorised management hosts on isolated management VLANs, and implement configuration integrity monitoring to detect unauthorised access or modification of network device configurations.
- **Implement topology obfuscation:** Consider deploying network topology obfuscation controls, such as dynamic ARP inspection, VLAN hopping prevention, and suppression of ICMP responses from routing devices, to degrade the fidelity of topology data obtainable through active scanning and traceroute-based inference.

***

## Detection Strategy

### Passive Collection Visibility Limitations

Network topology reconnaissance conducted through passive OSINT collection against public sources generates no observable artefacts within the target organisation's infrastructure.  Detection is most feasible when adversaries engage in active topology mapping or, most productively, during post-compromise internal enumeration.
### Active Scanning Detection

Active topology mapping through port scanning, ICMP sweeps, and SNMP queries produces observable network traffic that can be detected through the following controls:

- **Network traffic analysis:** Deploy **network flow analysis** tools such as [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/) to monitor for structured scanning patterns, ICMP sweep activity, high-frequency sequential port connection attempts, and SNMP queries originating from hosts outside authorised management subnets. 
- **IDS/IPS signature coverage:** Ensure deployed **NIDS/NIPS** platforms carry signatures for common network topology mapping tools including Nmap and Masscan, and configure alerts for the characteristic timing and packet patterns these tools produce. Platforms such as [Palo Alto Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr) and [Darktrace](https://www.darktrace.com/) provide behavioural network anomaly detection that can identify scanning activity without requiring signature matches.

### Post-Compromise LotL Enumeration Detection

The highest-fidelity post-compromise detection opportunities involve monitoring for anomalous execution of native enumeration utilities:

- **Process and command-line monitoring:** Monitor for execution of `tracert`, `arp -a`, `netstat -ano`, `route print`, `net view`, and `ipconfig /all` from unexpected parent processes, non-administrative user accounts, or scripting hosts such as `powershell.exe` and `cmd.exe`, using **Sysmon** Event ID 1 (Process Create) with command-line argument capture and **EDR telemetry** from [CrowdStrike Falcon](https://www.crowdstrike.com/) or [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint). 
- **BloodHound and SharpHound detection:** Monitor for LDAP query volumes and patterns consistent with Active Directory topology enumeration using **BloodHound/SharpHound** collection, detectable through **Microsoft Defender for Identity** (formerly Azure ATP) and **Sysmon** network connection events logging high-volume LDAP queries against domain controllers from endpoint hosts. 
- **Network device configuration access monitoring:** Log and alert on all access to network device management interfaces, configuration file downloads, and show command execution sessions through centralised **SIEM correlation** in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel), with particular attention to access from hosts not assigned to authorised management VLANs. 
