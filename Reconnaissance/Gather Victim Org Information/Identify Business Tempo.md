# Identify Business Tempo

Identify Business Tempo is a sub-technique of Gather Victim Org Information (**MITRE ATT&CK T1591.003**) in which adversaries collect intelligence about the operational scheduling, working patterns, and procurement rhythms of a target organisation.  Business tempo intelligence encompasses a range of operationally relevant details including the days and hours during which the organisation's facilities and IT systems are actively staffed and monitored, the geographic time zones within which key operational functions are conducted, and the timing and frequency of hardware and software procurement cycles and shipment schedules. 
This sub-technique is operationally significant because knowledge of when an organisation is most and least actively monitored enables adversaries to time intrusion operations, payload execution, and lateral movement to coincide with periods of reduced defensive attention, such as nights, weekends, public holidays, and periods between shifts.  Adversaries can additionally use hardware and software shipment schedule intelligence to identify specific windows during which procurement deliveries occur, enabling supply chain compromise operations targeting hardware and software resources during transit or pre-delivery staging, through **T1195 – Supply Chain Compromise**.  Gathered business tempo intelligence can inform further reconnaissance (e.g., **T1598 – Phishing for Information**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1585 – Establish Accounts**, **T1586 – Compromise Accounts**), and enable initial access via **T1195 – Supply Chain Compromise** and **T1199 – Trusted Relationship**. 

***

## Operational Value of Business Tempo Intelligence

Understanding an organisation's business tempo provides adversaries with several compounding operational advantages:

- **Attack timing optimisation:** Major ransomware deployment operations are frequently executed during nights, weekends, and public holidays when IT and security staff coverage is reduced, maximising the time available for encryption to propagate before detection and response can be initiated. Prominent examples include the **Kaseya VSA** ransomware deployment on a Friday afternoon ahead of the Fourth of July weekend (2021) and the **Colonial Pipeline** ransomware execution on a weekend. Knowledge of organisational operating hours directly informs this timing calculus.
- **Security operations coverage gaps:** Understanding when a Security Operations Centre (SOC) operates — whether 24/7 or within specific business hours — reveals periods during which real-time monitoring and alerting capacity may be diminished, reducing the risk of rapid detection and response to intrusion activity.
- **Phishing delivery optimisation:** Business tempo intelligence informs the timing of phishing campaign delivery, with adversaries scheduling email delivery to coincide with periods of peak inbox activity (e.g., early morning on working days) or periods of reduced scrutiny (e.g., immediately before a major holiday period) to maximise open and click rates.
- **Supply chain timing attacks:** Knowledge of hardware procurement schedules and anticipated delivery dates enables adversaries to identify specific windows during which IT equipment is in transit between supplier and the target organisation, creating opportunities for hardware implant insertion through **T1195.003 – Compromise Hardware Supply Chain**.

***

## Collection Vectors

Adversaries use a broad range of passive and active methods to enumerate business tempo intelligence:

- **Corporate Websites and Contact Pages:** "Contact Us" pages, office listing pages, and customer service sections of corporate websites frequently publish official operational hours for specific offices, support functions, and service desks, directly exposing the operational schedule of customer-facing and internal functions.
- **Social Media Activity Pattern Analysis:** Analysis of the posting patterns, engagement timing, and content of organisational and employee social media accounts on platforms including **LinkedIn**, **Twitter/X**, and **Facebook** can reveal the geographic time zones, working hours, and operational rhythms of the organisation and its personnel without any direct interaction.
- **Job Postings:** Employment advertisements routinely specify operational shift patterns, on-call requirements, working hours expectations, and time zone coverage requirements for advertised roles. Security operations roles in particular may disclose shift structures and coverage hours that directly reveal SOC operational tempo.
- **Press Releases and Financial Reporting Calendars:** Publicly disclosed financial reporting schedules, board meeting dates, annual general meeting dates, and major business event calendars reveal predictable periods of elevated executive and operational activity, as well as periods of reduced staffing such as summer or holiday periods.
- **Procurement and Shipping Intelligence:** Hardware procurement timelines may be inferred from job postings referencing procurement cycles, from vendor lead time information published on supplier websites, or through direct elicitation via **Phishing for Information** targeting procurement or IT operations personnel.
- **Phishing for Information (T1598):** Adversaries may directly elicit business tempo information through targeted social engineering campaigns against administrative, HR, or operations personnel, using pretexted requests for scheduling information under the guise of a vendor coordination or business relationship context.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Business tempo reconnaissance operates predominantly through passive collection against publicly accessible data sources, placing collection activity entirely outside the reach of conventional enterprise network controls.  Mitigation efforts should focus on reducing the operational scheduling intelligence available to adversaries and hardening the security coverage posture against the attack timing windows that this intelligence reveals: 

- **Restrict operational schedule disclosure:** Avoid publishing specific IT support hours, security operations coverage windows, and maintenance schedule details on public-facing platforms. Where customer service hours must be published, consider whether the specific working patterns of security and IT functions should be separately disclosed.
- **Implement 24/7 security monitoring:** Transition **Security Operations Centre (SOC)** operations to continuous 24/7 monitoring coverage using managed detection and response (MDR) providers such as [CrowdStrike Falcon Complete](https://www.crowdstrike.com/endpoint-security-products/falcon-complete-managed-detection-response/) and [Microsoft Sentinel with managed SOC services](https://azure.microsoft.com/en-us/products/microsoft-sentinel), eliminating the reduced-coverage periods that adversaries exploit through business tempo intelligence.
- **Holiday and weekend alerting uplift:** Implement enhanced monitoring sensitivity and faster alerting escalation during identified high-risk periods including public holidays, extended weekends, and major leave periods, recognising that these are disproportionately targeted by adversaries exploiting business tempo intelligence.
- **Hardware supply chain integrity controls:** Implement procurement process controls requiring tamper-evident packaging verification, chain of custody documentation, and hardware integrity validation upon receipt for all critical IT equipment deliveries, reducing the exploitability of supply chain timing intelligence.
- **Operational security training:** Educate employees on the risk of disclosing operational schedule details through social media posts, public forums, and unsolicited external enquiries, as even seemingly innocuous disclosures of working patterns and staffing arrangements contribute to the business tempo intelligence profile available to adversaries.

***

## Detection Strategy

### Passive Collection Visibility Limitations

Business tempo reconnaissance conducted through passive OSINT collection against corporate websites, social media platforms, and professional networks generates no observable artefacts within the target organisation's IT infrastructure.  Direct detection of this collection activity is therefore largely infeasible through conventional monitoring controls. 

### Detection Pivot to Temporal Attack Pattern Analysis

The most meaningful detection contribution from business tempo intelligence awareness is its application to **alerting and response posture enhancement**, rather than to direct detection of the reconnaissance activity itself. Defenders should implement the following time-aware controls:

- **Temporal anomaly detection in SIEM:** Configure **SIEM** correlation rules in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) to apply elevated severity scoring and reduced detection thresholds to alerts triggered outside of normal operational hours (e.g., nights, weekends, public holidays), recognising that adversaries exploiting business tempo intelligence are disproportionately likely to initiate high-impact actions during these periods. 
- **After-hours authentication anomaly detection:** Monitor **Entra ID** and VPN authentication logs for successful logins occurring at times inconsistent with the authenticated account holder's established access patterns, particularly during off-hours periods, using **Entra ID Identity Protection** risk-based conditional access policies to apply step-up authentication requirements for anomalous-timing login attempts.
- **Supply chain delivery monitoring:** Implement physical and logical controls to verify the integrity of hardware deliveries, particularly those arriving outside of expected procurement windows or from unexpected shipping intermediaries, detecting potential supply chain timing exploitation attempts. 
