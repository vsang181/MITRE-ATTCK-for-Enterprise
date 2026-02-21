# Business Relationships

Business Relationships reconnaissance is a sub-technique of Gather Victim Org Information (**MITRE ATT&CK T1591.002**) in which adversaries collect intelligence about the third-party relationships maintained by a target organisation, encompassing managed service providers, contractors, technology vendors, legal and financial advisors, and supply chain partners.  This intelligence is operationally significant for two primary reasons: first, trusted third-party relationships represent indirect attack pathways that can circumvent perimeter controls through **T1199 – Trusted Relationship** or **T1195 – Supply Chain Compromise**; second, knowledge of an organisation's supplier, partner, and customer ecosystem enables adversaries to construct contextually convincing social engineering lures that impersonate known trusted entities, dramatically increasing the plausibility and delivery success rate of phishing campaigns. 

Beyond network access relationships, business relationship intelligence may expose supply chain and shipment paths for the victim's hardware and software resources, enabling adversaries to identify and target specific points in the hardware or software delivery chain to pre-compromise equipment or software before it reaches the victim organisation.  The intelligence gathered can directly inform further reconnaissance (e.g., **T1598 – Phishing for Information**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1585 – Establish Accounts**, **T1586 – Compromise Accounts**), and enable initial access via **T1195 – Supply Chain Compromise**, **T1189 – Drive-by Compromise**, and **T1199 – Trusted Relationship**. 

***

## The Business Relationship Attack Surface

Modern organisations operate within dense and often extensively documented webs of third-party relationships that collectively represent a substantial and frequently undermonitored attack surface. Adversaries who enumerate an organisation's business relationships gain two compounding operational advantages: the identification of less-hardened third parties with privileged access whose compromise provides an indirect intrusion pathway, and the acquisition of trusted entity identities whose impersonation dramatically enhances the credibility of social engineering operations. 

Common categories of business relationships representing adversarially relevant attack vectors include:

- **Managed Service Providers (MSPs) and IT Vendors:** Organisations providing IT infrastructure management, helpdesk, security monitoring, or cloud management services often hold persistent privileged access to customer environments through remote management platforms. 
- **Software and Technology Suppliers:** Vendors providing enterprise software, security tooling, or development platforms may have code execution rights within the target's environment through update mechanisms and remote support channels, as exploited in supply chain attacks such as the SolarWinds Compromise and the Kaseya VSA attack.
- **Hardware Supply Chain Partners:** Manufacturers, distributors, and logistics providers handling hardware procurement and delivery for the target represent supply chain compromise targets, as adversaries who identify and compromise specific hardware supply chain links can pre-compromise equipment before it reaches the target environment through **T1195.003 – Compromise Hardware Supply Chain**.
- **Professional Services Providers:** Legal advisors, accounting firms, and management consultants frequently hold sensitive organisational documentation and may have remote access to specific client systems, representing both data exposure risks and trusted relationship exploitation vectors.
- **Business Partners and Customers:** Organisations in customer or partner relationships with the target may be used as impersonation vehicles for business email compromise, invoice fraud, and spearphishing campaigns, or may themselves have network connectivity to the target that can be exploited following their compromise.

***

## Collection Vectors

Adversaries use a combination of passive OSINT, active elicitation, and technical data source querying to enumerate business relationships:

- **Corporate Websites and Partnership Pages:** Organisations routinely publish technology partner directories, customer testimonials, and vendor acknowledgement pages that directly disclose specific business relationships by name. **Sandworm Team's** pre-Olympic attack research involved reviewing official partnership pages on the **PyeongChang 2018 Winter Olympics** official website to identify and research partner organisations as secondary attack targets. 
- **Press Releases and Business News:** Corporate press releases, business newswires, and industry publications routinely disclose new partnership signings, technology deployments, merger and acquisition activity, and supplier relationships. Databases such as [Crunchbase](https://www.crunchbase.com/), [ZoomInfo](https://www.zoominfo.com/), [Bloomberg](https://www.bloomberg.com/), and [Dun & Bradstreet](https://www.dnb.com/) aggregate and index this information at scale, making comprehensive business relationship enumeration achievable through a single platform subscription.
- **Regulatory and Financial Filings:** Companies registered in the UK (via [Companies House](https://www.gov.uk/government/organisations/companies-house)) and in the US (via **SEC EDGAR**) must submit annual reports, accounts, and event-driven filings that frequently disclose material business relationships, significant suppliers, and key technology dependencies. These filings are publicly accessible and represent a high-confidence, authoritative source of business relationship intelligence.
- **Social Media and LinkedIn:** LinkedIn company pages and employee profiles routinely disclose business relationships through partnership announcements, shared posts, and employee endorsements of partner organisations. The LinkedIn "People Also Viewed" and shared connection features further enable adversaries to map organisational relationship networks.
- **Vendor Case Studies and Technology Certifications:** Technology vendors frequently publish case studies and reference customer lists identifying specific organisations as users of their platforms, providing adversaries with direct confirmation of specific software and service deployments without any active interaction with the target. Certifications pages on vendor websites (e.g., "Certified [Vendor] Partner") can further confirm specific MSP and reseller relationships.
- **Phishing for Information (T1598):** Adversaries may directly elicit business relationship information through targeted phishing campaigns against procurement, legal, or executive personnel, impersonating known vendors or requesting confirmation of supplier relationships under pretexted business communication scenarios. 

***

## Procedure Examples

### Dragonfly (Energetic Bear)
**Dragonfly** is a Russian state-sponsored APT group conducting espionage and pre-positioning operations against energy sector organisations in Europe and North America. The group conducted systematic open-source intelligence collection to identify and map relationships between targeted organisations and their supply chain partners, using discovered relationships to identify secondary targets whose compromise would provide indirect access to primary targets through trusted network and software delivery relationships. 

### LAPSUS$
**LAPSUS$** gathered highly detailed knowledge of target organisations' supply chain relationships as part of its pre-intrusion reconnaissance operations. The group used business relationship intelligence to identify specific vendors and third parties that held privileged access to target environments or possessed sensitive credentials, enabling the group to pursue indirect compromise pathways through less-hardened supply chain partners and to construct convincing impersonation scenarios targeting IT help desk and support personnel. 

### Sandworm Team
In preparation for its **Olympic Destroyer** attack against the **2018 PyeongChang Winter Olympics**, **Sandworm Team** conducted structured online research of the partner organisations listed on the official PyeongChang Olympics partnership website.  By identifying the specific organisations holding formal partnership relationships with the Olympic Games, Sandworm Team was able to enumerate potential secondary targets whose IT infrastructure and network access relationships with the Olympic Games organisation could be leveraged as indirect attack pathways, and to craft impersonation lures exploiting the established trust between the Olympics organisation and its disclosed partners. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Business relationship intelligence is gathered predominantly through passive OSINT collection against publicly accessible data sources, placing collection activity outside the reach of conventional enterprise network controls.  Mitigation efforts should focus on reducing the business relationship intelligence available to adversaries and hardening the access pathways that this intelligence enables: 

- **Restrict public disclosure of specific vendor and partner relationships:** Audit corporate websites, press releases, and vendor partnership pages to minimise the specificity of third-party relationship information exposed to external parties. Where technology vendor partnerships must be disclosed for commercial purposes, consider whether the specific products and access levels associated with those relationships should also be publicly stated.
- **Implement third-party access controls and monitoring:** Enforce least-privilege access principles for all third-party connections, using purpose-scoped remote access solutions such as [BeyondTrust Privileged Remote Access](https://www.beyondtrust.com/products/privileged-remote-access) and [CyberArk Alero](https://www.cyberark.com/products/vendor-privileged-access-manager/) with full session logging and time-bounded access grants, reducing the risk posed by the exploitation of identified third-party access relationships. 
- **Supply chain security assessment:** Implement a formal **Third-Party Risk Management (TPRM)** programme that periodically assesses the security posture of hardware and software suppliers, conducting supply chain integrity verification for critical equipment deliveries and applying frameworks such as **NIST SP 800-161 (Cybersecurity Supply Chain Risk Management)** to structure supplier security requirements.
- **Email security and partner impersonation detection:** Deploy email security platforms such as [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) and [Proofpoint Email Protection](https://www.proofpoint.com/uk/products/email-security-and-protection) with supplier impersonation detection capabilities, establishing trusted sender registries for known business partners to detect spearphishing campaigns impersonating disclosed business relationships. 

***

## Detection Strategy

### Passive Collection Visibility Limitations

Business relationship reconnaissance conducted through OSINT collection against corporate websites, press releases, regulatory filings, and professional networking platforms generates no observable artefacts within the target organisation's IT infrastructure.  Direct detection of this collection activity is therefore largely infeasible through conventional monitoring controls. 

### Detection Pivot to Downstream Attack Stages

Detection resources yield the highest operational return when focused on the stages at which collected business relationship intelligence is operationally applied:

- **Supply chain compromise indicators:** Monitor software update mechanisms and hardware delivery processes for integrity anomalies, using cryptographic code signing validation and firmware integrity verification to detect tampering consistent with **T1195 – Supply Chain Compromise** targeting the organisation's disclosed software suppliers. 
- **Trusted relationship exploitation:** Monitor all third-party remote access sessions for anomalous behaviour patterns including unexpected process creation, lateral movement, and data staging activity using **EDR telemetry** from platforms such as [CrowdStrike Falcon](https://www.crowdstrike.com/) and **SIEM** correlation in [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel), detecting adversary activity conducted through compromised third-party access credentials. 
- **Business partner impersonation phishing:** Configure email security gateway detection rules for emails impersonating known business partners and vendors, and implement **DMARC** policy enforcement to prevent adversaries from spoofing the email domains of disclosed business relationships in follow-on phishing campaigns targeting the organisation. 
