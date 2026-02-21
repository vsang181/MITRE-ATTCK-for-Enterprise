# Spearphishing Link

Spearphishing Link is a sub-technique of Phishing for Information (**MITRE ATT&CK T1598.003**) in which adversaries deliver targeted emails containing malicious links to credential harvesting infrastructure, with the objective of tricking recipients into voluntarily submitting sensitive information — most commonly account credentials and session tokens — to adversary-controlled resources.  It is distinct from its initial access counterpart **T1566.002** in that the link leads to information elicitation rather than malware delivery, and from **T1598.002** in that the credential capture occurs through a web portal reached via link rather than through an attachment-embedded form or document. 

The technique's operational effectiveness stems from the combination of social engineering precision and technical URL obfuscation, with adversaries leveraging prior reconnaissance intelligence to craft highly contextualised lures and deploying sophisticated URL manipulation techniques to defeat both automated security controls and manual recipient URL inspection. 

***

## Link-Based Credential Harvesting Mechanisms

Adversaries implement credential collection through spearphishing links using a range of techniques that have progressively evolved to defeat successive generations of defensive controls: 

- **Clone and typosquatting credential portals:** Adversaries create pixel-accurate replicas of legitimate login portals — Microsoft 365, Okta, VPN gateways, corporate intranets — hosted on adversary-controlled domains designed to closely resemble the legitimate service through typosquatting (e.g., `micros0ft.com`), homograph attacks (replacing Latin characters with visually identical Cyrillic equivalents), or subdomain manipulation (e.g., `login.microsoft.com.adversary-domain.com`). Recipients who navigate to these portals and submit credentials deliver them directly to the adversary's collection infrastructure. 
- **Adversary-in-the-Middle (AiTM) reverse proxy frameworks:** Phishing kits including [EvilProxy](https://github.com/kgretzky/evilginx2) and [Evilginx2](https://github.com/kgretzky/evilginx2) transparently proxy the legitimate authentication service, presenting the genuine login interface to the target while intercepting submitted credentials **and authenticated session cookies** in real time.  Because session cookies are captured post-authentication, AiTM frameworks defeat time-based MFA protections including TOTP codes and push notification approvals — the adversary's proxy submits the captured OTP to the real service before it expires while simultaneously logging it. This enables subsequent **T1539 – Steal Web Session Cookie** operations, allowing adversaries to authenticate to victim accounts using the captured session token without ever knowing the account password. 
- **Browser-in-the-Browser (BitB) attacks:** Adversaries generate fake browser popup windows using HTML and CSS that visually replicate a legitimate browser authentication dialog, including a fake address bar displaying a trusted URL (e.g., `login.microsoft.com`) within the fabricated popup.  Because the address bar is rendered in HTML rather than displayed by the actual browser chrome, standard URL verification behaviours — hovering to preview the URL, checking the address bar — fail to detect the deception, as the displayed URL appears entirely legitimate despite rendering within an adversary-controlled page context. 
- **Tracking pixel and web beacon embedding:** Adversaries embed invisible **1×1 pixel images** or other obfuscated HTML objects within phishing emails that, when the email is opened or previewed, trigger an automatic HTTP request to an adversary-controlled server.  This request logs the recipient's **IP address**, approximate geographic location, email client type, operating system, and timestamp of email open, providing the adversary with confirmation of delivery, target profiling data, and initial location intelligence — all without any deliberate interaction from the recipient beyond opening the email. Groups including **Moonstone Sleet**, **Mustang Panda**, **Patchwork**, **Kimsuky**, and **ZIRCONIUM** have all operationally deployed tracking pixels.
- **QR code phishing ("quishing"):** Adversaries encode credential harvesting URLs within QR codes embedded in phishing email bodies or attachments.  Because most automated email security gateways perform URL inspection on text and hyperlink content rather than on embedded image data, QR-encoded URLs evade automated scanning and are delivered to recipient inboxes without triggering link reputation checks. Recipients scanning the QR code on a mobile device are redirected to credential harvesting pages in a mobile browser, where the reduced screen real estate makes visual verification of URL legitimacy significantly more difficult than on a desktop browser. 
- **URL obfuscation techniques:** Adversaries apply several schema-level obfuscation methods to defeat URL inspection: 
  - **Integer and hexadecimal hostname encoding:** URLs accept numeric IP addresses expressed in decimal integer format (e.g., `http://1157586937`) or hexadecimal (e.g., `http://0x4500f001`), which resolve to standard IPv4 addresses but are not visually recognisable as domain names.
  - **Pre-`@` symbol text discarding:** Browsers discard all text before an `@` symbol in a URL, meaning `http://google.com@adversary-site.com` navigates to `adversary-site.com` while displaying `google.com` as a seemingly legitimate prefix.
  - **URL shorteners:** Services including Bitly and TinyURL obscure the destination URL, preventing recipients and automated scanners from inspecting the final target without following the redirect.
  - **IDN homograph attacks:** Unicode characters visually identical to ASCII characters (e.g., Cyrillic `а` vs Latin `a`) are used in domain names to construct URLs that are visually indistinguishable from legitimate domains.

***

## Procedure Examples

### APT28 (Fancy Bear)
**APT28** has conducted sustained credential phishing campaigns using links that redirect targets to adversary-controlled credential harvesting sites, typically impersonating trusted webmail and corporate login portals.  The group's link-based campaigns are precisely targeted at high-value individuals in government, military, and political organisations, with lure content informed by extensive prior OSINT reconnaissance. 

### Kimsuky
**Kimsuky** has embedded **web beacons** within spearphishing emails to profile targets prior to credential harvesting, using the IP address and open-event data collected through tracking pixels to confirm target engagement and to build location and access pattern intelligence before delivering follow-on credential harvesting links. 

### Scattered Spider
**Scattered Spider** has deployed domains mirroring corporate login portals — including SSO portals for Okta and Microsoft 365 — to socially engineer victims into submitting credentials.  The group combined domain impersonation with real-time AiTM session proxying through Evilginx2, capturing both credentials and authenticated session tokens to defeat MFA protections and gain immediate authenticated access to victim environments. 

### Silent Librarian (TA407)
**Silent Librarian** conducted a multi-year credential harvesting campaign specifically targeting university and research institution personnel, using links in spearphishing emails to direct victims to credential harvesting websites designed to precisely replicate the targeted institution's own library and VPN login pages.  By creating institution-specific login page replicas with domain names closely resembling each targeted university's actual URL, the group harvested credentials from academic personnel across dozens of institutions in multiple countries. 

### Star Blizzard (SEABORGIUM)
**Star Blizzard** integrated link-based credential harvesting into a structured multi-stage engagement approach, first establishing extended rapport through legitimate-appearing email exchanges over days or weeks before transitioning to messages containing links to credential-stealing sites.  The rapport-building phase leverages the accumulated trust of an established correspondence to suppress the recipient's scepticism at the moment the credential harvesting link is delivered. 

### ZIRCONIUM (APT31)
**ZIRCONIUM** deployed **web beacons** in targeting emails to track hits to adversary-controlled URLs, building a confirmed recipient-engagement list and profiling target access patterns before delivering credential harvesting links in subsequent campaign phases. 

### Additional Group Examples
A broad range of threat actors have operationally deployed spearphishing links: **APT32** directed users to web pages harvesting credentials; **CURIUM** used malicious links to adversary-controlled credential harvesting resources; **Dragonfly** used PDF attachments containing embedded malicious links redirecting to harvesting websites; **Magic Hound** used both SMS and email messages containing credential theft links; **Mustang Panda** delivered web bugs for target profiling; **Patchwork** used per-recipient tracking links to identify which targets opened messages; **Sandworm Team** crafted hyperlinks to trick recipients into revealing account credentials; and **Sidewinder** and **Moonstone Sleet** have both used malicious links for credential harvesting and tracking purposes. 
***

## Mitigations

### Email Authentication (MITRE M1054 – Software Configuration)
The complete email authentication stack remains foundational: 

- **SPF, DKIM, and DMARC (p=reject):** Validate sender authenticity and message integrity, blocking spoofed sender domains from delivering link-bearing phishing emails. Monitor DMARC aggregate reports through [Dmarcian](https://dmarcian.com/) or [PowerDMARC](https://powerdmarc.com/) before hardening to `p=reject` to avoid legitimate mail disruption. 
- **Anti-IDN browser extensions:** Enforce browser extension deployment through policy (e.g., GPO for Chrome/Edge) that detects and alerts on IDN homograph domain visits, protecting against visually deceptive Cyrillic and Unicode domain impersonation. 
- **Browser password manager URL binding:** Configure browser password managers (including enterprise-deployed solutions such as [1Password for Business](https://1password.com/business/) and [Bitwarden Teams](https://bitwarden.com/products/business/)) to autofill credentials only when the current URL exactly matches the stored entry. This provides a technical backstop against cloned login portals — even if the recipient navigates to a convincing fake, the password manager will not autofill, alerting the recipient that the URL does not match the expected site. 

### URL Inspection and Filtering
- **Email gateway URL detonation:** Deploy email security platforms including [Microsoft Defender for Office 365 Safe Links](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-office-365) and [Proofpoint Targeted Attack Protection](https://www.proofpoint.com/uk/products/advanced-threat-protection/targeted-attack-protection) with real-time URL rewriting and time-of-click detonation to evaluate link destinations at the moment of click, catching adversary infrastructure deployed after initial email delivery that bypasses pre-delivery scanning. 
- **DNS-layer filtering:** Block access to adversary-controlled credential harvesting domains and known-malicious URL categories through [Cisco Umbrella](https://umbrella.cisco.com/) and [Zscaler Internet Access](https://www.zscaler.com/), including QR code destination URLs where QR code scanning feeds into a monitored browser session. 

### User Training (MITRE M1017)
Security awareness training must specifically address link-based credential harvesting techniques: 

- Visual URL verification skills including identification of typosquatting, subdomain manipulation, and homograph domain patterns.
- Awareness of AiTM phishing frameworks and the fact that MFA does not provide complete protection against real-time session token capture.
- QR code scepticism — training recipients to avoid scanning QR codes received in unsolicited emails without independent URL verification.
- Recognition of tracking pixel behaviour and the risks of enabling HTML email rendering in high-sensitivity contexts.

***

## Detection Strategy

### Email-Layer Detection
- **DMARC reporting and SPF/DKIM enforcement:** Monitor aggregate DMARC reports for spoofing attempts against the organisation's domains and enforce `p=reject` to block spoofed sender domains delivering link-bearing phishing. 
- **Bulk sender pattern detection:** Alert on multiple internal mailboxes receiving messages from the same unusual external sender within a short window, characteristic of mass link-based credential harvesting campaigns targeting multiple personnel. 
- **URL expansion and shortlink analysis:** Configure email security gateways to automatically expand URL shorteners and evaluate final destination reputation before delivery, preventing obfuscated links from bypassing URL reputation checks. 

### Network and Browser-Layer Detection
- **Homograph and IDN domain monitoring:** Monitor browser logs and DNS query logs for IDN domain visits involving non-ASCII characters in domains that closely resemble the organisation's own domains or those of trusted services, using **SIEM** correlation in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) to alert on homograph domain resolution events. 
- **Cloned website detection:** Analyse inbound network traffic and HTTP response content for indicators of website cloning tools, including `Mirrored from` metadata embedded in HTML by tools such as HTTrack, using network inspection through [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/). 
- **SSL/TLS inspection for encrypted traffic:** Apply SSL/TLS inspection on outbound web traffic to enable full content inspection of HTTPS sessions to unknown or low-reputation domains, detecting credential form submission events to adversary-controlled portals that would otherwise be obscured by encryption. 

### Authentication and Session Anomaly Detection
- **AiTM session cookie theft detection:** Monitor **Entra ID** sign-in logs for authentication patterns consistent with AiTM session token replay — particularly successful MFA authentications from unfamiliar devices or IP addresses immediately following a phishing email delivery event.  Implement **Entra ID Identity Protection** risk-based conditional access to require re-authentication for token sessions evaluated as high-risk. Deploy **Continuous Access Evaluation (CAE)** to revoke session tokens in real time when anomalous access conditions are detected. 
- **Tracking pixel request detection:** Implement email client policies that block automatic loading of external images in email previews, preventing tracking pixel requests from profiling recipients without explicit interaction. Configure email security gateways to scan for and alert on 1×1 pixel image embeds with external URLs, characteristic of tracking beacon deployment. 
