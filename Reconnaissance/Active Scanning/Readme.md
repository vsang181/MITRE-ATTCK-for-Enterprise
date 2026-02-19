# Active Scanning

Active scanning is a reconnaissance technique in which adversaries directly probe victim infrastructure by sending network traffic to target systems and analysing the responses. Unlike passive reconnaissance, which relies on collecting publicly available information without direct interaction, active scanning involves deliberate engagement with target networks, hosts, or services. This technique is classified under **MITRE ATT&CK T1595** and encompasses a range of methods including host discovery, port scanning, service enumeration, and vulnerability identification.

Active scans may leverage native network protocol features, such as ICMP echo requests (ping sweeps), TCP/UDP port probing, or protocol-specific handshakes to elicit responses from target infrastructure. Intelligence gathered through active scanning can directly inform subsequent stages of the attack lifecycle, including identifying avenues for further reconnaissance (e.g., **T1593 – Search Open Websites/Domains**, **T1596 – Search Open Technical Databases**), resource development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and initial access vectors (e.g., **T1133 – External Remote Services**, **T1190 – Exploit Public-Facing Application**).

***

## Procedure Example: Triton / TRISIS (TEMP.Veles)

The **Triton Safety Instrumented System (SIS) Attack** is a highly sophisticated ICS-targeted campaign attributed to the threat actor group **TEMP.Veles**, believed to operate on behalf of a Russian government-linked research institute (CNIIHM). The campaign deployed the **Triton malware framework** (also referred to as TRISIS or HatMan) against a Middle Eastern petrochemical facility, specifically targeting **Schneider Electric Triconex Safety Controllers**, which are hardware components designed to trigger emergency shutdowns in industrial environments.

As part of the pre-exploitation phase, TEMP.Veles conducted active network reconnaissance to map the operational technology (OT) environment, identify reachable safety system components, and understand the communication protocols in use (primarily **TriStation**, a proprietary UDP-based protocol). The malware was designed to overwrite the firmware of Triconex controllers to allow the adversary to either inhibit emergency shutdowns or cause physical damage to industrial processes. The intrusion was ultimately discovered when a safety instrumented system initiated an unintended safety trip, a direct result of a logic error within the malware, rather than through conventional security detection mechanisms.

This incident underscores the risk active scanning poses in OT/ICS environments, where even low-level network probing can inadvertently trigger physical consequences.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Pre-compromise mitigations encompass proactive defensive measures deployed during the **Reconnaissance** and **Resource Development** phases of the MITRE ATT&CK framework, before an adversary achieves any foothold within the target environment. The objective is to reduce the organisation's externally visible attack surface, degrade adversarial intelligence-gathering efforts, and increase the operational cost of a successful intrusion.

### Limit Information Exposure
Conduct regular audits of publicly accessible data sources, including corporate websites, job postings, GitHub repositories, and employee social media profiles, to identify and remediate unintentional information disclosures. Leverage **Open Source Intelligence (OSINT)** frameworks such as [SpiderFoot](https://www.spiderfoot.net/) and [Recon-ng](https://github.com/lanmaster53/recon-ng) to simulate adversarial reconnaissance and surface exposed data before it can be weaponised.

### Domain and DNS Infrastructure Hardening
Enable **DNSSEC (Domain Name System Security Extensions)** to protect DNS integrity and prevent DNS spoofing or cache poisoning attacks. Apply **WHOIS privacy protection** to reduce domain ownership exposure. Continuously monitor for domain hijacking attempts and lookalike/typosquatting domains using dedicated services such as [RiskIQ (Microsoft Defender Threat Intelligence)](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-threat-intelligence) and [DomainTools](https://www.domaintools.com/).

### External Attack Surface Monitoring
Deploy external attack surface management (EASM) solutions to maintain continuous visibility into internet-facing assets. Tools such as [Shodan](https://www.shodan.io/) and [Censys](https://censys.io/) can be leveraged defensively to identify exposed services, open ports, and misconfigured systems before adversaries do. Complement this with external vulnerability scanners such as [Tenable.io](https://www.tenable.com/products/tenable-io) or [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) to proactively remediate weaknesses.

### Threat Intelligence Integration
Integrate structured threat intelligence feeds into security operations workflows using platforms such as [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/), [Recorded Future](https://www.recordedfuture.com/), or [Anomali ThreatStream](https://www.anomali.com/products/threatstream). These platforms enable tracking of adversarial infrastructure, tooling, and TTPs (Tactics, Techniques, and Procedures), providing early warning of targeted reconnaissance activity.

### Email and Content Security Controls
Deploy enterprise-grade email security gateways and threat protection solutions including [Proofpoint Email Security](https://www.proofpoint.com/uk/products/email-security-and-protection), [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365), and [Mimecast](https://www.mimecast.com/). Enforce the full **email authentication stack**, comprising **SPF (Sender Policy Framework)**, **DKIM (DomainKeys Identified Mail)**, and **DMARC (Domain-based Message Authentication, Reporting and Conformance)**, to mitigate email spoofing and phishing campaigns that may accompany or follow reconnaissance activity.

### Security Awareness and Training
Implement structured security awareness training programmes to educate personnel on identifying **spear-phishing** attempts, securing professional social media profiles (e.g., LinkedIn), and recognising inadvertent information disclosure risks. Platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training) provide simulated phishing exercises and measurable training metrics.

***

## Detection Strategy

### Network Traffic Analysis
Monitor network telemetry for anomalous or unsolicited inbound traffic patterns indicative of active scanning activity. Particular attention should be given to:
- **Unusual data flows** from external IP ranges not associated with known business partners or services.
- **Processes initiating network connections** that do not ordinarily do so, or that have no established baseline of network communication.
- **Protocol anomalies**, including traffic that does not conform to expected standards, such as malformed packets, unexpected flag combinations in TCP headers, or non-standard use of ICMP.

### Packet-Level Inspection and Correlation
Employ **deep packet inspection (DPI)** and protocol analysis to identify extraneous or gratuitous traffic patterns inconsistent with established network flows. Correlate network anomalies with **endpoint process monitoring** and **command-line argument logging** (e.g., via **Sysmon**, **Windows Event Logs**, or **EDR telemetry**) to detect tooling such as [Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), or [Zmap](https://zmap.io/) executing internally or on compromised hosts. SIEM platforms such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) can be used to build correlation rules and alert on scanning signatures.

***

## Sub-Techniques

| Sub-Technique | Description |
|---|---|
| [Scanning IP Blocks](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Active%20Scanning/Scanning%20IP%20Blocks.md) | Systematic probing of IP address ranges to enumerate live hosts and map network topology |
| [Vulnerability Scanning](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Active%20Scanning/Vulnerability%20Scanning.md) | Automated probing of services to identify known vulnerabilities using tools such as [Nessus](https://www.tenable.com/products/nessus), [OpenVAS](https://www.openvas.org/), or [Nikto](https://cirt.net/Nikto2) |
| [Wordlist Scanning](https://github.com/vsang181/MITRE-ATTCK-for-Enterprise/blob/main/Reconnaissance/Active%20Scanning/Wordlist%20Scanning.md) | Directory and resource enumeration against web servers using predefined wordlists, commonly executed via tools such as [Gobuster](https://github.com/OJ/gobuster), [ffuf](https://github.com/ffuf/ffuf), or [Dirbuster](https://www.kali.org/tools/dirbuster/) |
