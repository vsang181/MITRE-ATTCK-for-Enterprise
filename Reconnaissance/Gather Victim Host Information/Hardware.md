# Hardware

Hardware reconnaissance is a sub-technique of Gather Victim Host Information (**MITRE ATT&CK T1592.001**) in which adversaries collect detailed intelligence about the physical hardware infrastructure of target hosts and network devices. This information may encompass device types and model versions, CPU architecture, presence of dedicated security hardware components such as **Hardware Security Modules (HSMs)**, **Trusted Platform Modules (TPMs)**, biometric authentication readers, smart card readers, and dedicated hardware encryption appliances. The presence or absence of these components directly indicates the security maturity of the target environment and can inform adversary decisions regarding the viability and complexity of planned exploitation or physical access operations.

Hardware intelligence also extends to network infrastructure components such as routers, switches, firewalls, and load balancers, including vendor models and firmware versions, which may align with publicly known hardware-level vulnerabilities or default credential exposure. Identifying specific hardware configurations enables adversaries to pursue highly targeted attack paths, including **T1195.003 – Compromise Hardware Supply Chain**, in which adversaries intercept or tamper with hardware devices prior to delivery to the target organisation, or **T1200 – Hardware Additions**, in which rogue hardware implants are physically introduced into the target environment.

***

## Collection Vectors

Adversaries may gather hardware intelligence through multiple active and passive collection methods:

- **Active Scanning:** Network-facing services frequently expose hardware-identifying information through server banners, SNMP (Simple Network Management Protocol) responses, IPMI (Intelligent Platform Management Interface) interfaces, and HTTP response headers. Tools such as [Nmap](https://nmap.org/) with OS and hardware detection scripts (`-O`, `--osscan-guess`), [Shodan](https://www.shodan.io/), and [Censys](https://censys.io/) can enumerate device types, vendors, and firmware versions from internet-facing infrastructure passively or via direct probing.
- **User-Agent and Browser Fingerprinting:** Adversary-controlled or compromised websites can passively collect CPU architecture, device type, and OS platform details from visiting users' HTTP `User-Agent` strings and JavaScript-based fingerprinting scripts, without any interaction with the target's own network perimeter.
- **Watering Hole Attacks:** Adversaries may compromise websites frequently visited by target personnel and embed malicious JavaScript designed to enumerate hardware characteristics including screen resolution, GPU renderer strings (via WebGL), CPU core count, and available memory, all of which contribute to a detailed host hardware profile.
- **Open Source Intelligence (OSINT):** Hardware infrastructure details are frequently unintentionally disclosed through publicly accessible sources including:
  - **Job postings**, which often specify hardware requirements, vendor preferences, and technology stack details.
  - **Network architecture diagrams and assessment reports** that may be inadvertently published or leaked.
  - **Employee resumes and LinkedIn profiles** listing hardware platforms and technologies worked with.
  - **Purchase invoices and procurement records** accessible through public tender portals or financial disclosures.
  - **Vendor case studies and press releases** referencing specific hardware deployments at named organisations.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Hardware reconnaissance operates predominantly outside the bounds of the target organisation's enterprise defences, as collection activity typically occurs against publicly accessible data sources or via adversary-controlled infrastructure that the target visits. Direct preventive mitigation of the reconnaissance activity itself is not readily achievable through conventional controls. Mitigation efforts should focus on the following:

- **Restrict hardware information disclosure in public-facing content:** Conduct regular audits of publicly accessible materials including job postings, corporate blog posts, press releases, and social media content to identify and remove references to specific hardware vendors, models, and deployment configurations. Ensure procurement activities do not result in publicly accessible purchase records that expose hardware inventory details.
- **Suppress device and service banners:** Configure network devices, servers, and management interfaces to disable or obfuscate vendor and model information in SNMP community strings, SSH banners, web management portal login pages, and HTTP response headers. For example, restrict SNMP access to authorised management subnets only and disable SNMP v1/v2c in favour of **SNMPv3 with authentication and encryption**.
- **Secure and restrict management interfaces:** Ensure that out-of-band management interfaces such as **IPMI**, **iDRAC**, **iLO**, and **DRAC** are never exposed to the public internet, are placed on isolated management VLANs, and are protected with strong authentication credentials. Historically, exposed IPMI interfaces have been a significant source of hardware intelligence for adversaries.
- **Browser and endpoint hardening:** Deploy **browser isolation** solutions such as [Cloudflare Browser Isolation](https://www.cloudflare.com/en-gb/zero-trust/products/browser-isolation/) or enforce strict **Content Security Policies (CSP)** on internal web applications to restrict JavaScript-based fingerprinting capabilities. Endpoint security platforms such as [CrowdStrike Falcon](https://www.crowdstrike.com/) and [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) can monitor for and alert on anomalous script execution patterns consistent with browser-based hardware fingerprinting.
- **Supply chain integrity controls:** To mitigate the risk of **hardware supply chain compromise (T1195.003)**, implement hardware procurement controls including vendor verification processes, tamper-evident packaging inspection procedures, and **firmware integrity validation** upon receipt of new devices.

***

## Detection Strategy

### Internet-Facing Content and Scanner Detection

Detection of hardware-focused reconnaissance is inherently difficult due to the high volume of legitimate internet scanner traffic and the fact that a significant portion of collection activity occurs outside the target's visibility entirely. Internet-facing systems should be monitored for scanning patterns associated with hardware enumeration, including automated SNMP queries from unexpected source IP ranges, repeated IPMI or iDRAC login attempts, and high-frequency requests to network device management portals. Network intrusion detection systems such as [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/) can be configured with rules to alert on known hardware enumeration tool signatures.

### Detection Pivot to Initial Access and Supply Chain Indicators

Given that much of this reconnaissance activity takes place outside the organisation's defensive perimeter, detection efforts yield the highest return when focused on the downstream stages at which collected hardware intelligence is operationally applied. Defenders should implement monitoring controls aligned with **Initial Access** indicators, particularly those associated with **hardware supply chain compromise** and **hardware addition** attacks, such as the introduction of unrecognised USB devices, unexpected new network hosts appearing on authorised device inventories, or firmware version anomalies detected during routine integrity scanning. Asset management and configuration baseline tools such as [Tenable.io](https://www.tenable.com/products/tenable-io), [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/), and **network access control (NAC)** solutions such as [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) can enforce hardware inventory baselines and alert on deviations that may indicate adversarial hardware activity downstream of the reconnaissance phase.
