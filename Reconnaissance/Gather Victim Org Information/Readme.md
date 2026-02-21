# Gather Victim Org Information

Gather Victim Org Information is a reconnaissance technique classified under **MITRE ATT&CK T1591** in which adversaries collect detailed intelligence about the structure, operations, and personnel of a target organisation to support targeting, social engineering, and attack planning.  Collectible organisational intelligence encompasses a broad range of details including division and department names, business functions and operational processes, key personnel roles and responsibilities, business relationships, physical locations, and operational schedules. 

Adversaries gather this intelligence through a combination of passive OSINT collection against social media platforms, corporate websites, press releases, regulatory filings, and professional networking profiles, as well as through active elicitation via **Phishing for Information (T1598)** and direct social engineering.  The operational value of organisational intelligence is substantial: detailed knowledge of an organisation's internal structure, business relationships, key roles, and operational tempo enables adversaries to construct highly contextualised and believable social engineering lures, identify the highest-value personnel to target for initial access, and anticipate the human and procedural factors that may constrain or facilitate a successful intrusion.  Gathered intelligence can reveal opportunities for further reconnaissance (e.g., **T1598 – Phishing for Information**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1585 – Establish Accounts**, **T1586 – Compromise Accounts**), and enable initial access via **T1566 – Phishing** and **T1199 – Trusted Relationship**. 

***

## Procedure Examples

### APT28 (Fancy Bear)
**APT28** is a Russian GRU-affiliated APT group with a broad targeting mandate spanning government, military, political, and critical infrastructure organisations. The group has adopted **Large Language Models (LLMs)** as a force-multiplication tool for organisational intelligence gathering, using LLM-powered research to collect and synthesise information about satellite capabilities of targeted organisations, accelerating the production of targeting intelligence at a scale and speed that would be significantly more resource-intensive through manual OSINT processes. 

### FIN7
**FIN7** is a sophisticated, financially motivated threat actor group responsible for large-scale payment card theft and ransomware operations against retail, hospitality, and financial sector organisations. The group operationalised commercial business intelligence services for victim selection, using **ZoomInfo** — a business intelligence platform providing revenue figures, employee counts, industry classifications, and contact details — to filter and prioritise potential victims by annual revenue, ensuring that targeting efforts were directed toward organisations above specific financial thresholds that would maximise the return on investment from successful compromise operations. 

### Kimsuky
**Kimsuky** is a North Korean state-sponsored APT group conducting espionage operations against South Korean government, academic, and policy research targets. The group has conducted comprehensive organisational intelligence collection including organisational hierarchy mapping, departmental function identification, press release and public statement analysis, and personnel profiling.  Kimsuky has additionally leveraged **Large Language Models (LLMs)** to accelerate the gathering and synthesis of information about potential targets, integrating AI-assisted research into its pre-compromise intelligence cycle. 

### Lazarus Group
**Lazarus Group** has studied publicly available information about targeted organisations to tailor spearphishing campaigns with high precision, crafting lures that reference the specific departments, business functions, and internal contexts of the targeted organisation to maximise plausibility and delivery success rates.  The group's **Operation Dream Job** campaign integrated organisational intelligence gathering directly into victim identification operations, using collected organisational data to scope and filter targets and to construct highly personalised fraudulent job offer lures relevant to the specific roles and career interests of targeted individuals. 

### Moonstone Sleet
**Moonstone Sleet** is a North Korean threat actor group assessed to have conducted operations primarily against defence, technology, and cryptocurrency sectors. The group has gathered victim organisational intelligence through both **email** and **social media interaction**, directly engaging with target organisation personnel under cover personas to elicit organisational context, relationship information, and operational details that would inform subsequent targeting and social engineering operations. 

### Volt Typhoon
**Volt Typhoon** conducted extensive pre-compromise reconnaissance operations against targeted critical national infrastructure organisations, gathering comprehensive organisational intelligence as a component of its broader reconnaissance campaign to support long-term, low-detectability persistent access operations within US critical infrastructure. 

***

## Mitigations: Pre-Compromise (MITRE M1056)

Organisational intelligence gathering is conducted predominantly through passive OSINT collection against publicly accessible data sources, placing collection activity entirely outside the reach of conventional enterprise network controls.  Mitigation efforts should focus on limiting the organisational intelligence available to adversaries through the following measures: 
- **Restrict publicly available organisational detail:** Audit corporate websites, press releases, annual reports, and regulatory filings to minimise the granularity of organisational structure, departmental function, and personnel role information disclosed to external parties. Consider replacing specific role and department naming conventions in public-facing materials with generic functional descriptions.
- **Social media and professional network governance:** Establish and enforce policies governing the level of organisational and operational detail employees may publish on platforms including LinkedIn, Twitter/X, and industry forums. Provide specific guidance on avoiding disclosure of internal project names, system names, and operational schedules.
- **AI-assisted OSINT self-assessment:** Conduct regular OSINT self-assessments against the organisation's own public information surface, including LLM-assisted synthesis of publicly available intelligence, to understand what organisational profile adversaries can build from open sources and identify specific disclosure risks requiring remediation.
- **Security awareness training:** Train employees to recognise and resist social engineering attempts that leverage organisational intelligence, using platforms such as [KnowBe4](https://www.knowbe4.com/) and [Proofpoint Security Awareness Training](https://www.proofpoint.com/uk/products/security-awareness-training) to deliver role-specific training scenarios reflecting the most relevant attack vectors for each personnel category.

***

## Detection Strategy

Organisational intelligence gathering conducted through passive OSINT collection against public websites, social media platforms, and professional networks generates no observable artefacts within the target organisation's infrastructure, making direct detection largely infeasible through conventional monitoring controls.  Detection efforts yield the highest operational return when focused on the **Initial Access** and **Phishing** stages at which collected organisational intelligence is applied. 

***

## Sub-Techniques

| Sub-Technique | ID | Key Intelligence Collected | Common Collection Methods | Mitigations and Detection Focus |
|---|---|---|---|---|
| **Determine Physical Locations** | T1591.001 | Office addresses, data centre locations, satellite facilities, employee work locations, building access arrangements | Corporate websites, LinkedIn profiles, Google Maps, job postings specifying office locations, company registration documents, press releases | Limit publication of specific facility and data centre location details; monitor for physical surveillance indicators near facilities; detect downstream phishing lures referencing physical locations |
| **Business Relationships** | T1591.002 | Partner organisations, suppliers, customers, investment relationships, contracted service providers, legal and financial advisors | Press releases, company websites, SEC/Companies House filings, LinkedIn partnership pages, vendor case studies, industry news databases such as [Crunchbase](https://www.crunchbase.com/) and [ZoomInfo](https://www.zoominfo.com/) | Restrict disclosure of specific vendor and partner identities in public communications; conduct partner and supplier security risk assessments; monitor for phishing impersonating disclosed business partners |
| **Identify Business Tempo** | T1591.003 | Operational schedules, maintenance windows, financial reporting cycles, peak business periods, staffing patterns, geographic time zones of operations | Job postings referencing shift patterns, press releases disclosing operational events, social media activity patterns, financial reporting calendars, industry event participation | Avoid publishing detailed operational schedule information publicly; train staff on pretexted elicitation targeting operational tempo details; detect social engineering attempts referencing specific business schedules |
| **Identify Roles** | T1591.004 | Specific job titles and responsibilities, reporting structures, privileged personnel with system access, decision-making authority holders, personnel with financial approval rights | LinkedIn profiles, corporate website team pages, conference speaker biographies, press releases, regulatory filings naming executives and directors | Limit granularity of role and responsibility information in public profiles; implement targeted security training for high-value roles (executives, finance, IT admins); detect spearphishing campaigns targeting specific organisational roles using email security platforms such as [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) |
