# Gather Victim Host Information

Gather Victim Host Information is a reconnaissance technique classified under **MITRE ATT&CK T1592** in which adversaries collect detailed data about victim host systems prior to initiating offensive operations.  Host-level intelligence may include administrative details such as assigned hostnames and IP addresses, as well as granular configuration specifics including operating system type and version, installed software, hardware components, and system language settings.  This intelligence directly enables adversaries to tailor exploitation capabilities, select appropriately compiled payloads, and anticipate defensive controls present within the target environment. 

Adversaries may collect host information through multiple channels, including **direct active scanning** (**T1595**), **phishing for information** (**T1598**), and **watering hole attacks**, in which adversaries compromise third-party websites and embed malicious scripts designed to silently collect browser and host metadata from visiting users.  Host information may also be passively gathered from publicly accessible data sources including social media profiles, corporate websites, and online technical databases.  Intelligence derived from host enumeration can directly inform subsequent stages of the adversary lifecycle, including further reconnaissance (e.g., **T1593 – Search Open Websites/Domains**, **T1596 – Search Open Technical Databases**), capability development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and initial access operations (e.g., **T1195 – Supply Chain Compromise**, **T1133 – External Remote Services**). 

### User-Agent Based Host Fingerprinting

A notable and increasingly prevalent collection vector within this technique involves the exploitation of **HTTP User-Agent headers**.  Every HTTP request transmitted by a browser or application includes a `User-Agent` string that identifies the requesting client's application type, operating system, CPU architecture, rendering engine, and version information.  Adversaries operating malicious or compromised web infrastructure can passively harvest these headers from inbound requests to build a detailed profile of visiting victims' host configurations, without any direct interaction with the target's own network.  This intelligence may then be used to implement **targeted payload delivery**, in which a malicious server dynamically serves operating system-specific malware only to hosts matching a desired profile (e.g., serving a Windows PE executable exclusively to requests bearing a Windows `User-Agent`), while returning benign content to all other visitors to evade sandbox analysis and detection. 

***

## Procedure Example: Volt Typhoon

**Volt Typhoon** is a People's Republic of China (PRC) state-sponsored advanced persistent threat (APT) group assessed to have been active since at least 2021, with a primary focus on cyber espionage operations targeting **critical national infrastructure (CNI)** in the United States and allied nations, including sectors such as communications, energy, transportation, and water systems. 
Prior to gaining initial access, Volt Typhoon has been observed conducting extensive pre-compromise reconnaissance, leveraging platforms such as [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and [FOFA](https://fofa.info/) to search for and enumerate exposed victim infrastructure, including internet-facing systems, open ports, and service banners.  A defining characteristic of Volt Typhoon's operational methodology is its near-exclusive reliance on **Living Off the Land (LotL)** techniques, utilising built-in Windows system utilities including `wmic`, `netsh`, `ntdsutil`, `PowerShell`, and `ping` to perform host discovery, network topology enumeration, and system configuration collection, deliberately avoiding the introduction of third-party tooling that would trigger **EDR (Endpoint Detection and Response)** alerts.  Post-compromise, the group has been observed enumerating file system types, drive configurations, running processes, open network connections, and virtual environment indicators to build a comprehensive understanding of the compromised host's role and defensive posture. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

This technique is largely conducted from outside the target organisation's defensive perimeter, making direct preventive mitigation through conventional enterprise controls impractical.  Mitigation efforts should therefore concentrate on reducing the volume and sensitivity of host information accessible to external parties through the following measures: 

- **Suppress service and application banners:** Configure internet-facing web servers, SSH daemons, FTP services, and application frameworks to minimise version disclosure in HTTP response headers (e.g., disable `Server:`, `X-Powered-By:`, and `X-AspNet-Version:` headers), reducing the intelligence value of passive and active host enumeration.
- **Browser fingerprint and User-Agent hardening:** Where operationally feasible, consider deploying **browser isolation** solutions or enforcing **uniform User-Agent string policies** across enterprise endpoints to reduce the fingerprinting surface exposed to adversary-controlled web infrastructure. Enterprise browsers and solutions such as [Cloudflare Browser Isolation](https://www.cloudflare.com/en-gb/zero-trust/products/browser-isolation/) can assist in this regard.
- **Watering hole detection and web filtering:** Deploy **DNS filtering** and **web proxies** (e.g., [Zscaler Internet Access](https://www.zscaler.com/products/zscaler-internet-access), [Cisco Umbrella](https://umbrella.cisco.com/)) to restrict access to known malicious or newly registered domains that may be used as watering hole infrastructure.
- **Minimise public data exposure:** Conduct regular audits of externally accessible systems using OSINT and EASM tools such as [SpiderFoot](https://www.spiderfoot.net/), [Shodan Monitor](https://monitor.shodan.io/), and [Censys ASM](https://censys.io/) to proactively identify and remediate unnecessarily exposed host information before it can be weaponised.

***

## Detection Strategy

### Internet-Facing Content Monitoring

Detection of host information gathering activity presents a significant challenge, as much of the collection effort occurs outside the visibility of the target organisation's security controls, particularly in cases involving passive data harvesting from public databases, watering hole infrastructure, or HTTP User-Agent logging.  Internet-facing web servers and application gateways should be configured to log all inbound HTTP request metadata, including `User-Agent` strings, source IP addresses, referrer headers, and requested resources, and these logs should be forwarded to a centralised **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) for correlation and anomaly detection. 

### Detection Pivot to Adjacent Lifecycle Stages

Given the inherently low-visibility nature of pre-compromise host information gathering, detection efforts are most effective when pivoted to related and observable stages of the adversary lifecycle.  Specifically, defenders should focus monitoring resources on **Initial Access** indicators (e.g., exploitation of public-facing applications, spearphishing delivery), where the intelligence gathered during host reconnaissance is operationally applied. Correlation of inbound exploit attempts with prior scanning activity logged in network telemetry, enriched with threat intelligence from platforms such as [Recorded Future](https://www.recordedfuture.com/) and [VirusTotal](https://www.virustotal.com/), can help retrospectively identify the reconnaissance phase that preceded an access attempt. 

***

## Sub-Techniques

| Sub-Technique | Key Intelligence Collected | Relevance to Adversary Operations |
|---|---|---|
| **Hardware** | Device types, component versions, presence of security hardware (HSMs, biometric readers, TPM chips, encryption appliances) | Informs payload architecture selection and identifies physical security controls that may need to be bypassed |
| **Software** | Installed applications, software versions, presence of AV/EDR agents, SIEM integrations, and security tooling  [tenable](https://www.tenable.com/attack-path-techniques/T1592.002_PRE) | Enables identification of software CVEs to exploit and security tools to evade |
| **Firmware** | Firmware type and version on network devices, IoT hardware, and embedded systems | Reveals patch levels and susceptibility to firmware-level exploits, particularly relevant in OT/ICS environments |
| **Client Configurations** | OS version, CPU architecture (x86/x64/ARM), virtualisation status, system language, and time zone | Supports targeted payload compilation and malware configuration tuning for the specific target environment |
