# CDNs

CDNs is a sub-technique of Search Open Technical Databases (**MITRE ATT&CK T1596.004**) in which adversaries gather intelligence about a target organisation's Content Delivery Network infrastructure — including the CDN provider in use, origin server IP addresses potentially exposed despite CDN masking, and CDN misconfigurations that may expose sensitive content or bypass CDN-layer security controls. CDNs are deployed by organisations to serve web content from geographically distributed edge nodes, providing performance benefits, redundancy, and — critically — an additional security layer that masks the true origin server IP address behind the CDN provider's infrastructure. When CDN reconnaissance succeeds, adversaries can bypass these protections entirely.

Intelligence gathered through CDN reconnaissance can directly inform further reconnaissance (e.g., **T1595 – Active Scanning**, **T1593 – Search Open Websites/Domains**), support resource development (e.g., **T1583 – Acquire Infrastructure**, **T1584 – Compromise Infrastructure**), and enable initial access via **T1189 – Drive-by Compromise**.

***

## How CDNs Create an Adversarial Intelligence Opportunity

CDNs are intended to provide both performance and security benefits by interposing a distributed proxy layer between clients and the origin server. From a security perspective, this masking provides two key protections: the origin server's real IP address is hidden behind CDN edge node IPs, and CDN-layer Web Application Firewall (WAF) and DDoS protection services inspect and filter inbound traffic before it reaches the origin. Adversaries who successfully identify the origin server IP address can bypass both protections simultaneously — reaching the origin server directly without passing through CDN filtering, and exposing the origin to direct DDoS and exploitation attacks that the CDN layer was designed to absorb. This makes CDN origin IP discovery one of the highest-value outcomes of open technical database reconnaissance.

***

## CDN Provider Identification

Before attempting origin server discovery, adversaries first identify which CDN provider the target organisation uses. This is straightforward through several passive methods:

- **HTTP response header analysis:** CDN providers embed characteristic headers in HTTP responses that identify the serving infrastructure. Cloudflare responses include `CF-Ray` and `CF-Cache-Status` headers; Akamai responses include `X-Check-Cacheable` and `Akamai-*` headers; Fastly responses include `X-Served-By` and `X-Cache` headers; AWS CloudFront responses include `X-Amz-Cf-Id` and `Via: CloudFront` headers. These headers are visible in any browser developer tools session or through command-line tools such as `curl -I`.
- **DNS record analysis:** CDN deployments typically manifest as CNAME records pointing to CDN provider domains (e.g., `www.example.com` CNAME to `example.com.cdn.cloudflare.net`), directly disclosing the CDN provider through passive DNS queries.
- **TLS certificate inspection:** CDN providers may issue certificates on behalf of customers, with issuing CA patterns and certificate organisation details revealing CDN vendor relationships.
- **CDN fingerprinting tools:** Online tools such as [WhatCDN](https://www.whatcdn.com/) and [CDNFinder](https://www.cdnfinder.io/) automate CDN provider identification, and reconnaissance frameworks including [wafw00f](https://github.com/EnableSecurity/wafw00f) detect WAF and CDN provider signatures from HTTP response characteristics.

***

## Origin Server IP Discovery Techniques

Identifying the real IP address of the origin server behind CDN masking is the primary adversarial objective of CDN reconnaissance. Several techniques are used to discover this:

- **Historical DNS record analysis:** Passive DNS databases including [SecurityTrails](https://securitytrails.com/) and [DomainTools](https://www.domaintools.com/) retain historical DNS A records from before the organisation deployed its CDN. If the domain previously resolved directly to the origin server IP before CDN deployment, that IP address remains queryable through historical passive DNS, and may still be the active origin server IP if the server has not been moved since CDN deployment.
- **Certificate Transparency log subdomain enumeration:** CT log queries frequently reveal subdomains that resolve directly to origin server IP addresses rather than CDN edge nodes, because organisations typically deploy CDN protection on primary web-facing domains but neglect to route all subdomains through CDN infrastructure. API endpoints, staging environments, development servers, and administrative portals enumerated through CT log SAN fields may resolve directly to origin IPs.
- **Mail server (MX) record correlation:** Mail servers are commonly hosted on the same IP ranges as origin web servers, and MX records must resolve to the mail server's actual IP address (CDN proxying does not apply to email delivery). Querying MX records and cross-referencing the resolved IP against scan databases can reveal origin server IP address ranges.
- **Direct subdomain probing:** Adversaries test common subdomain naming patterns for administrative and origin-specific functionality (e.g., `origin.example.com`, `direct.example.com`, `backend.example.com`, `api.example.com`) that may have been created without CDN routing, resolving directly to origin infrastructure.
- **Internet scan database reverse lookups:** Querying scan databases such as [Shodan](https://www.shodan.io/) and [Censys](https://censys.io/) for the organisation's name, SSL certificate fingerprints, or specific HTTP response content patterns can identify IP addresses serving the same content as the CDN-fronted domain but without CDN masking — revealing origin server IP addresses directly.
- **SSL certificate common name matching:** TLS certificates served by origin servers directly may have the same common name and SANs as the CDN-fronted certificate. Searching scan databases for the specific certificate fingerprint or common name can identify all IPs where that certificate is being served, including origin servers not routed through the CDN.
- **SPF record analysis:** TXT SPF records frequently enumerate IP ranges authorised to send mail on behalf of the domain, which may include internal infrastructure IP ranges co-located with web origin servers.

***

## CDN Misconfiguration Intelligence

Beyond origin server discovery, adversaries specifically seek CDN misconfigurations that expose sensitive content or reduce the protection level available to specific resources:

- **Sensitive content hosted on CDN-cached paths:** CDN misconfigurations may cause sensitive content — including backup files, configuration files, development artefacts, and API response data — to be cached and served by CDN edge nodes without the authentication controls applied on the origin. Adversaries enumerate cached paths through directory brute-forcing and historical URL analysis to identify sensitive resources served directly from CDN cache.
- **Cache poisoning opportunities:** CDN cache key misconfigurations may enable adversaries to poison cached responses for legitimate URLs with adversary-controlled content, enabling large-scale client-side attacks through **T1189 – Drive-by Compromise** against users of a widely used CDN-hosted resource.
- **Login portal and authentication bypass:** Administrative portals and login interfaces hosted on subdomains that are CDN-routed but lack equivalent WAF policy configurations to the primary domain may be accessible with reduced protection, enabling more effective credential brute-forcing or exploitation against the underprotected authentication surface.
- **CDN provider configuration leakage:** CDN provider management APIs and misconfigured CDN configuration files (e.g., publicly accessible `.htaccess` equivalents, CDN configuration JSON files in web roots) may expose CDN routing rules, origin server addresses, access control configurations, and authentication bypass patterns.

***

## Mitigations: Pre-Compromise (MITRE M1056)

CDN reconnaissance is conducted entirely through passive queries to external data sources and direct HTTP inspection, generating limited observable artefacts within the target organisation's own monitoring infrastructure. Mitigation efforts should focus on protecting origin server IP addresses from discovery and eliminating CDN misconfiguration exposure:

- **Route all internet-facing services through CDN:** Ensure that every internet-facing service — including subdomains enumerated through DNS and CT log reconnaissance, API endpoints, administrative portals, and staging environments — is routed through CDN infrastructure. Unprotected subdomains that resolve directly to origin IPs are the most common CDN bypass vector.
- **Change origin server IP after CDN deployment:** After deploying CDN protection, migrate the origin server to a new IP address not previously associated with the domain in historical DNS records, eliminating the most common passive DNS-based origin IP discovery method.
- **Restrict origin server access by CDN IP ranges only:** Configure the origin server's firewall to accept inbound HTTPS connections exclusively from the CDN provider's published IP ranges (e.g., [Cloudflare IP Ranges](https://www.cloudflare.com/en-gb/ips/), [Akamai Edge IPs](https://techdocs.akamai.com/origin-ip-acl/docs/welcome-origin-ip-acl)). This ensures that even if the origin IP is discovered through reconnaissance, direct connections to the origin bypass the CDN layer and are blocked at the network perimeter.
- **Suppress identifying HTTP headers:** Remove or minimise CDN provider-identifying headers from HTTP responses where operationally feasible, reducing the ease of CDN provider fingerprinting. Some CDN providers offer header suppression configuration options for security-conscious deployments.
- **CDN WAF policy consistency:** Ensure that WAF and access control policies are uniformly applied across all routed domains and subdomains, not just the primary domain, eliminating the reduced-protection surface that adversaries exploit through subdomain-specific CDN misconfiguration.
- **Audit CDN-cached content:** Regularly audit CDN-cached URL paths for sensitive content that should not be publicly accessible or cacheable, implementing appropriate `Cache-Control` headers and CDN cache exclusion rules for authenticated and sensitive resources.

***

## Detection Strategy

### Passive Collection Opacity
CDN provider identification through HTTP header analysis and DNS record queries generates minimal observable signal within the target organisation's monitoring infrastructure, and passive DNS queries for historical origin IP addresses generate no artefacts whatsoever. Direct detection of CDN reconnaissance is largely infeasible.

### Origin Server Direct Access Detection
The most actionable detection signal from CDN reconnaissance is generated at the point where a discovered origin IP is directly accessed, bypassing CDN infrastructure:

- **Origin server access log monitoring:** Monitor origin web server access logs for inbound connections arriving directly from IP addresses not belonging to the CDN provider's published IP ranges. Legitimate user traffic routed through the CDN will originate exclusively from CDN edge node IPs; direct connections from arbitrary client IPs indicate either a CDN bypass attempt or a misconfigured routing path. Alert on all non-CDN inbound connections to origin servers in **SIEM** platforms such as [Splunk](https://www.splunk.com/) or [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel).
- **Scanning activity detection against origin IP ranges:** Monitor for active scanning patterns against origin server IP addresses that are not routed through CDN — particularly port scans, HTTP enumeration, and vulnerability scanning — using **IDS** platforms such as [Suricata](https://suricata.io/) and [Zeek](https://zeek.org/), correlating source IPs against threat intelligence feeds to identify reconnaissance-phase scanning campaigns.
- **CDN configuration change monitoring:** Monitor CDN provider management console audit logs for unexpected routing rule changes, WAF policy modifications, and origin server configuration changes that may indicate CDN account compromise enabling adversary manipulation of CDN routing to expose origin infrastructure directly.
- **Detection pivot to Drive-by Compromise:** Given that CDN reconnaissance frequently precedes **T1189 – Drive-by Compromise** through cache poisoning or origin compromise, implement client-side security controls including **Content Security Policy (CSP)** headers, **Subresource Integrity (SRI)** for third-party scripts, and browser-level monitoring through [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) to detect and block malicious content served through compromised or cache-poisoned CDN resources.
