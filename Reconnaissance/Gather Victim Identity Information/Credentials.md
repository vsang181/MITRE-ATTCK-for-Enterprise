# Credentials

Credential gathering is a sub-technique of Gather Victim Identity Information (**MITRE ATT&CK T1589.001**) in which adversaries collect account credentials associated with target personnel or the victim organisation to support authentication-based intrusion operations. Gathered credentials may include username and password pairs, session cookies, API tokens, OTP codes, and MFA bypass tokens directly associated with corporate accounts, or personal credentials that can be tested against business systems by exploiting the widespread tendency for users to reuse passwords across personal and professional platforms. The operational value of valid credentials is exceptionally high, as they enable adversaries to authenticate as legitimate users, entirely bypassing perimeter technical controls and significantly reducing the forensic footprint of an intrusion compared to vulnerability exploitation.

Credential intelligence gathered during this phase directly enables the establishment of operational resources through **T1586 – Compromise Accounts**, and supports initial access via **T1078 – Valid Accounts** and **T1133 – External Remote Services**, as well as informing further reconnaissance activities including **T1593 – Search Open Websites/Domains** and **T1598 – Phishing for Information**.

***

## Collection Vectors

Adversaries employ a broad and increasingly sophisticated range of methods to acquire valid credentials:

- **Phishing and Credential Harvesting Pages (T1598):** Adversaries deploy adversary-in-the-middle (AiTM) phishing frameworks such as [Evilginx](https://github.com/kgretzky/evilginx2), [Modlishka](https://github.com/drk1wi/Modlishka), and [Muraena](https://github.com/muraenateam/muraena) to proxy legitimate authentication flows in real time, capturing not only plaintext credentials but also post-authentication session cookies that bypass MFA protections entirely.
- **Infostealer Malware Logs:** Commodity infostealer malware families including **RedLine Stealer**, **Raccoon Stealer**, **Vidar**, and **LummaC2** harvest saved browser credentials, session cookies, and autofill data from compromised endpoints and exfiltrate them to adversary infrastructure. The resulting credential logs are subsequently sold through dark web marketplaces such as **Russian Market** and **2easy**, and distributed through dedicated **Telegram channels**, making large volumes of fresh, validated credentials commercially accessible to threat actors of varying sophistication.
- **Breach Dump Repositories and Dark Web Markets:** Credentials from prior data breaches are aggregated into large corpus databases and made available for purchase or download through dark web forums and marketplaces, as well as through publicly accessible paste sites. Credential stuffing tools such as [Snipr](https://github.com/dafthack/MailSniper) and [OpenBullet](https://github.com/openbullet/OpenBullet2) are commonly used to validate harvested credentials at scale against target authentication endpoints.
- **Code Repository Mining:** Credentials inadvertently committed to public source code repositories including **GitHub**, **GitLab**, and **Bitbucket** represent a significant and persistent exposure vector. Hardcoded API keys, OAuth tokens, database connection strings, and plaintext passwords are routinely discovered in repository commit histories using tools such as [truffleHog](https://github.com/trufflesecurity/trufflehog), [GitLeaks](https://github.com/gitleaks/gitleaks), and [GitHub's secret scanning feature](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning).
- **MFA Interception via Service Provider Compromise:** In environments using out-of-band MFA methods such as **SMS-based OTP** or **phone call verification**, adversaries may compromise telecommunications service providers or conduct **SIM-swapping attacks** to intercept one-time passwords in transit, enabling complete MFA bypass without requiring the victim's cooperation.
- **Authentication Cookie Theft via Watering Hole:** Adversaries compromise high-traffic websites and inject malicious JavaScript designed to exfiltrate authenticated session cookies from visiting users, enabling session hijacking attacks that bypass password and MFA requirements entirely.
- **Help Desk Social Engineering:** Adversaries impersonate target employees when contacting IT help desk services, using harvested identity intelligence to pass verification procedures and request credential resets or MFA re-enrolment to adversary-controlled devices.

***

## Procedure Examples

### APT28 (Fancy Bear)
**APT28** is a Russian GRU-affiliated APT group with an extensive operational history of credential harvesting campaigns targeting government, military, political, and critical infrastructure organisations. The group has deployed credential phishing infrastructure, spearphishing campaigns, and purpose-built credential theft tooling to harvest login credentials from target users across multiple sectors.

### C0027 (Scattered Spider – UNC3944)
During the **C0027** campaign, **Scattered Spider** conducted targeted **SMS phishing (smishing)** operations, sending crafted messages to target employees containing links to adversary-controlled credential harvesting pages that mimicked legitimate corporate SSO and VPN login portals, capturing credentials and session tokens for use in subsequent account takeover and lateral movement operations.

### Chimera
**Chimera** is a Chinese state-sponsored threat actor group targeting the aviation, semiconductor, and pharmaceutical sectors. The group has collected and operationally reused credentials sourced from prior data breaches against target organisations, conducting credential stuffing and brute force attacks to identify valid account combinations across corporate authentication services.

### LAPSUS$
**LAPSUS$** pursued a multi-vector credential acquisition strategy, combining targeted OSINT-based identity profiling, dark web credential purchases, direct recruitment of malicious insiders, and help desk social engineering to obtain valid credentials and initiate MFA re-enrolment to adversary-controlled devices. The group famously called corporate IT help desk services while impersonating target employees, exploiting weak identity verification procedures to reset credentials and bypass MFA protections for privileged accounts at major technology and telecommunications organisations.

### Leviathan (APT40)
**Leviathan** has operationally collected and leveraged compromised credentials sourced from prior breach operations to facilitate targeted intrusions, using valid credentials to authenticate against external-facing services and avoid generating exploitation-related detection artefacts.

### Magic Hound (APT35 / Charming Kitten)
**Magic Hound** demonstrated a systematic and scalable approach to credential exploitation, validating credentials harvested from two specific victims across **75 different websites** to identify instances of password reuse across personal and professional accounts. The group additionally collected credentials from over **900 Fortinet VPN servers** across the United States, Europe, and Israel, leveraging the **CVE-2018-13379** Fortinet FortiOS SSL VPN path traversal vulnerability to extract plaintext VPN credentials from vulnerable appliances without authentication.

### SolarWinds Compromise (APT29 / Cozy Bear)
As part of the **SolarWinds supply chain compromise**, **APT29** conducted extensive credential theft operations within compromised environments, harvesting credentials to establish persistent authenticated access across victim tenants and cloud environments. Stolen credentials enabled lateral movement from on-premises networks into **Microsoft 365** and **Azure AD** environments, facilitating long-term, low-footprint espionage operations across numerous government and private sector organisations.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Credential collection predominantly occurs outside the target organisation's network perimeter through breach repositories, dark web markets, phishing infrastructure, and infostealer distribution channels, limiting the effectiveness of conventional enterprise controls in preventing the collection activity itself. Mitigation efforts should focus on minimising credential exposure and hardening authentication infrastructure against the operational use of harvested credentials:

- **Continuous credential exposure monitoring:** Subscribe to enterprise credential breach monitoring services such as [SpyCloud](https://spycloud.com/), [Have I Been Pwned Enterprise](https://haveibeenpwned.com/API/Key), [Entra ID Identity Protection's leaked credentials detection](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), and [Recorded Future Identity Intelligence](https://www.recordedfuture.com/solutions/identity-intelligence) to identify and enforce immediate credential rotation for exposed accounts before adversaries can operationally leverage them.
- **Enforce phishing-resistant MFA:** Deploy **FIDO2/WebAuthn hardware security keys** (e.g., [YubiKey](https://www.yubico.com/), [Google Titan Key](https://store.google.com/gb/product/titan_security_key)) across all privileged and remote access accounts, replacing SMS-based OTP and voice call MFA methods that are susceptible to SIM-swapping, AiTM phishing, and social engineering bypass.
- **Implement anti-phishing protections:** Deploy **AiTM-resistant Conditional Access policies** within **Microsoft Entra ID** enforcing token binding and compliant device requirements, preventing adversaries from using captured session cookies on unmanaged devices. Email security platforms such as [Proofpoint](https://www.proofpoint.com/uk) and [Microsoft Defender for Office 365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) should be configured with anti-phishing policies that detect and block credential harvesting page redirections.
- **Secret scanning and repository controls:** Enforce pre-commit secret scanning hooks using [GitLeaks](https://github.com/gitleaks/gitleaks) or [truffleHog](https://github.com/trufflesecurity/trufflehog) within developer workflows, and enable [GitHub Advanced Security secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) and push protection to prevent credentials from being committed to public or private repositories.
- **Password manager and unique credential enforcement:** Mandate the use of enterprise **password managers** such as [1Password Business](https://1password.com/business) or [Bitwarden Teams](https://bitwarden.com/products/business/) to enforce unique, randomly generated passwords across all accounts, eliminating credential reuse risk across personal and professional platforms.
- **Help desk identity verification hardening:** Implement multi-factor identity verification procedures for all help desk credential reset and MFA re-enrolment requests, requiring out-of-band manager approval and callback verification to pre-registered numbers, directly countering the social engineering credential reset vectors operationally employed by **LAPSUS$** and **Scattered Spider**.

***

## Detection Strategy

### Credential Stuffing and Brute Force Detection

The primary detectable manifestation of harvested credential use occurs at the **Initial Access** stage when adversaries authenticate against corporate services. Authentication telemetry from all externally accessible services, including **VPN gateways**, **SSO portals**, **OWA/Exchange Online**, and **cloud management consoles**, should be centralised within a **SIEM platform** such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) and monitored for the following indicators:

- **Credential stuffing patterns:** High volumes of failed authentication attempts from a single source IP or distributed IP range against multiple distinct accounts within a short time window, consistent with automated credential validation tooling.
- **Impossible travel and geographic anomalies:** Successful authentications from geographic locations inconsistent with the account holder's established access patterns or that represent physically impossible travel windows between consecutive logins.
- **New device and unfamiliar location authentications:** Successful logins from previously unseen device fingerprints, IP addresses, or ASN ranges, particularly following periods of failed authentication attempts from the same source.
- **MFA fatigue and re-enrolment anomalies:** Unusual volumes of MFA push notification requests or unexpected MFA method re-enrolment events, potentially indicative of **MFA fatigue attacks** or social engineering-driven help desk reset operations.

**Entra ID Identity Protection**, **Defender for Cloud Apps (MCAS)**, and **Conditional Access** policies provide native cloud identity telemetry and risk-based signal enrichment to complement SIEM-based detection, enabling automated response actions such as session revocation and step-up authentication challenges when anomalous credential use is detected.
