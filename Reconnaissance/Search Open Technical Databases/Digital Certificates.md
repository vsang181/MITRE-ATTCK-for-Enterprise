Understood, Victor. Here is the Digital Certificates entry rewritten without citations:

***

# Digital Certificates

Digital Certificates is a sub-technique of Search Open Technical Databases (**MITRE ATT&CK T1596.003**) in which adversaries query publicly accessible **Certificate Transparency (CT) logs** and digital certificate databases to gather intelligence about a target organisation's registered domains, subdomains, internal hostnames, and infrastructure relationships. Digital certificates are a uniquely high-value open reconnaissance source because every organisation deploying HTTPS must obtain a certificate from a trusted Certificate Authority (CA) — and since 2013, all publicly trusted CAs are required to log every certificate they issue to publicly accessible CT logs, creating a permanent, queryable, and authoritative record of every certificate ever issued for any domain.

Intelligence gathered through digital certificate reconnaissance can directly inform further reconnaissance (e.g., **T1595 – Active Scanning**, **T1598 – Phishing for Information**), support resource development (e.g., **T1587 – Develop Capabilities**, **T1588 – Obtain Capabilities**), and enable initial access via **T1133 – External Remote Services** and **T1199 – Trusted Relationship**.

***

## Certificate Transparency: The Foundational Data Source

**Certificate Transparency (CT)** is an IETF standard framework (RFC 6962) in which all publicly trusted Certificate Authorities are required to submit every issued certificate to at least two publicly accessible, cryptographically append-only CT logs before it will be trusted by major browsers including Chrome, Firefox, and Safari. This requirement was introduced following several high-profile incidents of unauthorised certificate issuance — most notably the DigiNotar breach in 2011 — and is now universally enforced by browser vendors. The result is a globally accessible, independently verifiable, and continuously updated database of every certificate ever issued by every trusted CA, including certificates for every subdomain registered by every organisation that deploys HTTPS.

CT logs are publicly queryable through several interfaces:

- **[crt.sh](https://crt.sh/):** A free, publicly accessible CT log search tool maintained by Sectigo (formerly Comodo CA) that enables full-text search across all logged certificates by domain name, including wildcard searches (e.g., `%.example.com` returns all certificates ever issued for any subdomain of `example.com`).
- **[Censys Certificates](https://censys.io/):** Provides a queryable index of CT log data combined with active internet scan data, enabling correlation of certificate data with live service banners and open port information.
- **[Google Certificate Transparency](https://certificate.transparency.dev/):** Google operates several CT logs including Argon and Xenon, and maintains the `cert-spotter` open-source monitoring tool.
- **[Certstream](https://certstream.calidog.io/):** Provides a real-time stream of newly issued certificates as they are logged to CT infrastructure, enabling both defenders and adversaries to monitor for certificate issuance events in near real-time.
- **[Facebook CT Monitor](https://developers.facebook.com/tools/ct/):** Facebook operates its own CT monitoring service with domain-specific alerting capabilities for certificate issuance.

***

## Intelligence Categories in Digital Certificate Data

Digital certificates expose several categories of adversarially relevant intelligence:

- **Subject Alternative Names (SANs):** Modern TLS certificates use the SAN extension to list all domain names and IP addresses covered by a single certificate. SAN fields frequently enumerate dozens or hundreds of subdomains in a single certificate — including internal staging environments, development servers, VPN gateways, and administrative portals — that the organisation may not have intended to expose publicly. A single wildcard certificate query against CT logs for a large organisation can reveal its entire subdomain estate in seconds.
- **Registered organisation metadata:** Certificate Subject fields contain the organisation's legal name (`O=`), country (`C=`), state (`ST=`), and locality (`L=`). Where an Extended Validation (EV) certificate is used, the organisation's verified legal identity and registration details are also disclosed, confirming organisational identity and geographic location with high confidence.
- **Certificate issuance and expiry timestamps:** Certificate validity periods reveal operational security practices. Short-lived certificates (e.g., 90-day Let's Encrypt certificates) indicate automated certificate management, while longer-lived certificates may indicate manual management patterns and predict expiry windows useful to adversaries.
- **Certificate Authority relationships:** The issuing CA is disclosed in every certificate, revealing CA vendor relationships used by the organisation. This can inform targeted attacks against the organisation's CA account and reveals whether an internal private CA is in use.
- **Internal hostname leakage:** Certificates inadvertently submitted to a public CA for internal-facing services expose internal network naming conventions, internal service hostnames, and potentially internal IP address ranges in SAN fields — providing adversaries with insight into internal network architecture without requiring any network access.
- **Historical certificate data:** CT logs are append-only and permanent, meaning historical certificates for decommissioned services and legacy infrastructure remain permanently queryable. This reveals the evolution of the organisation's infrastructure, including previously active services that may still be reachable but no longer actively maintained.

***

## Certificate-Based Subdomain Enumeration in Practice

CT log-based subdomain enumeration has become one of the most effective and widely used reconnaissance techniques available to adversaries, largely superseding traditional brute-force subdomain enumeration in both speed and coverage. The workflow is straightforward:

1. Query [crt.sh](https://crt.sh/) or [Censys](https://censys.io/) with the target apex domain (e.g., `%.example.com`) to retrieve all certificates ever issued for the domain and any subdomain.
2. Extract all unique domain names from the SAN fields of returned certificates, constructing a comprehensive subdomain enumeration list.
3. Resolve each enumerated subdomain against live DNS to identify which subdomains are currently active and what IP addresses they resolve to.
4. Cross-reference live subdomains against scan database entries in [Shodan](https://www.shodan.io/) and [Censys](https://censys.io/) to identify exposed services, software versions, and exploitable configurations on each active subdomain.

Automated reconnaissance frameworks such as [Amass](https://github.com/owasp-amass/amass), [subfinder](https://github.com/projectdiscovery/subfinder), and [theHarvester](https://github.com/laramies/theHarvester) integrate CT log querying as a primary subdomain enumeration source, enabling fully automated end-to-end subdomain discovery in a single command.

***

## Certificate Data Served Directly from Content

Beyond CT log querying, digital certificate intelligence is also directly available to adversaries during active interaction with the target's services. When a browser or any TLS client connects to an HTTPS endpoint, the server presents its full certificate chain as part of the TLS handshake — exposing all SAN fields, organisation metadata, and CA relationships without requiring any prior CT log query. Network scanning tools including [Nmap](https://nmap.org/) with the `ssl-cert` script and [SSLyze](https://github.com/nabla-c0d3/sslyze) can retrieve and parse certificate data from identified HTTPS endpoints at scale, enabling bulk certificate intelligence collection during active scanning operations.

***

## Mitigations: Pre-Compromise (MITRE M1056)

Digital certificate reconnaissance exploits publicly mandated CT logging infrastructure, making the fundamental data source entirely outside organisational control. Mitigation efforts should focus on minimising sensitive intelligence exposure within certificates and proactively monitoring for adversarial use of certificate data:

- **Minimise SAN field scope:** Issue separate certificates for logically distinct service categories rather than bundling large numbers of subdomains into single certificates with expansive SAN fields. Audit SAN contents to ensure no internal or sensitive hostnames are inadvertently included.
- **Avoid internal hostname exposure in public CA certificates:** Implement an **internal Private Certificate Authority** (e.g., [Microsoft Active Directory Certificate Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview), [HashiCorp Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki)) for certificates covering internal hostnames and services, issuing publicly trusted certificates only for genuinely internet-facing services. Certificates issued by private CAs are not submitted to CT logs and do not expose internal naming conventions.
- **CT log monitoring for the organisation's domains:** Implement continuous CT log monitoring using [Certstream](https://certstream.calidog.io/) and [Facebook CT Monitor](https://developers.facebook.com/tools/ct/) to receive real-time alerts whenever a new certificate is issued for the organisation's domains or close variants, enabling rapid identification of adversary-issued phishing domain certificates, unauthorised issuance for legitimate domains, and newly exposed subdomains in certificate SAN fields.
- **CAA records (Certification Authority Authorisation):** Publish **DNS CAA records** for all organisational domains specifying which CAs are authorised to issue certificates for the domain. CAA records prevent unauthorised CAs from issuing new certificates for the domain, limiting the adversarial utility of any CA account compromise.
- **Certificate expiry management:** Implement automated certificate lifecycle management through platforms such as [Venafi TLS Protect](https://venafi.com/solutions/tls-protect/) and [Sectigo Certificate Manager](https://www.sectigo.com/enterprise-solutions/certificate-manager) to maintain complete visibility of the certificate estate and prevent operationally disruptive certificate lapses.

***

## Detection Strategy

### Complete Passive Collection Opacity
CT log queries are directed at external logging infrastructure — not at the target organisation's own systems — and generate no observable artefacts within the target's monitoring environment. Direct detection of this reconnaissance activity is therefore entirely infeasible.

### Proactive CT Monitoring and Downstream Exploitation Detection

- **Real-time CT alerting integration:** Integrate CT log monitoring alerts from [Certstream](https://certstream.calidog.io/) directly into **SIEM** correlation workflows in [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel), triggering automated investigation workflows for newly issued certificates covering lookalike or typosquatting variants of organisational domains. Certificate issuance for an adversary-controlled lookalike domain is frequently one of the earliest observable indicators of a phishing or credential harvesting campaign in preparation.
- **Periodic certificate estate audit:** Conduct regular audits of all certificates in CT logs associated with the organisation's domains using [crt.sh](https://crt.sh/) and [Censys](https://censys.io/) to identify unauthorised certificate issuance, inadvertently exposed internal hostnames in SAN fields, and historical certificates for decommissioned services that may remain exploitable.
- **Active Scanning correlation:** Recognising that CT log-derived subdomain enumeration typically precedes targeted active scanning of identified hosts, monitor for scanning activity against enumerated hosts using **IDS** platforms such as [Suricata](https://suricata.io/) and [Zeek](https://zeek.org/), correlating scanning source IPs against threat intelligence feeds in [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) to identify reconnaissance scanning campaigns leveraging certificate-derived target lists.
