# Search Open Websites/Domains

Search Open Websites/Domains is a reconnaissance technique classified under **MITRE ATT&CK T1593** in which adversaries search freely accessible websites and online platforms to gather intelligence about target organisations and individuals. Unlike closed source or technical database reconnaissance, this technique exploits the vast body of information organisations and their employees voluntarily and inadvertently publish across the open web, including social media platforms, news sites, job boards, corporate websites, public code repositories, and government contract databases.

Intelligence gathered through open website and domain reconnaissance can directly inform further reconnaissance (e.g., **T1598 - Phishing for Information**, **T1596 - Search Open Technical Databases**), support resource development (e.g., **T1585 - Establish Accounts**, **T1586 - Compromise Accounts**), and enable initial access via **T1133 - External Remote Services** and **T1566 - Phishing**.

***

## The Open Web as an Intelligence Source

The open web represents the largest and most diverse reconnaissance surface available to adversaries. Unlike technical database queries that target structured infrastructure data, open website reconnaissance exploits the full breadth of human-generated organisational content published across the internet. Every press release, job posting, conference presentation, news article, employee LinkedIn profile, GitHub commit, and corporate blog post contributes to an adversary's picture of the target organisation's personnel, technology stack, business relationships, operational processes, and security posture. The challenge for defenders is that the vast majority of this content is published for entirely legitimate business or personal reasons, making restriction operationally and culturally difficult.

***

## Procedure Examples

### Contagious Interview
**Contagious Interview** -- a Lazarus Group sub-cluster -- used open-source indicator of compromise (IOC) repositories including [VirusTotal](https://www.virustotal.com/) and [MalTrail](https://github.com/stamparm/maltrail) to actively monitor for detections of its own malware and infrastructure. This represents a sophisticated operational security use of open website reconnaissance, in which the adversary searches public threat intelligence repositories to assess the degree to which its tools have been detected and attributed, enabling it to rotate burned infrastructure and modify malware before widespread detection blocks operational effectiveness.

### Kimsuky
**Kimsuky** has used Large Language Models (LLMs) to search open websites and identify think tanks, government organisations, and other entities containing intelligence relevant to its targeting priorities. This AI-augmented approach enables the group to process and synthesise vastly larger volumes of open web content than manual research would allow, significantly accelerating the target identification and profiling phases of its reconnaissance operations.

### Mustang Panda
**Mustang Panda** conducted structured open-source research to identify specific information about victim organisations and individuals, using the gathered intelligence to construct weaponised phishing lures and attachments precisely tailored to each target's specific context, responsibilities, and interests. The group's use of open web intelligence to craft contextually convincing lures directly illustrates the link between T1593 reconnaissance and T1566 phishing operations.

### Sandworm Team
**Sandworm Team** conducted specific open website research in preparation for the **NotPetya** attack, including running queries on the Ukrainian government's EDRPOU legal entity identifier registry website to research Ukraine's corporate registration system. The group also researched third-party websites to gather intelligence supporting the construction of credible spearphishing emails, demonstrating the direct operational connection between open website research and initial access campaign development.

### Star Blizzard
**Star Blizzard** (SEABORGIUM / Callisto Group) has systematically used open-source research to identify and profile target individuals, gathering sufficient personal and professional context from open websites to construct the extended rapport-building email conversations it uses before delivering credential harvesting links. Star Blizzard's operational model specifically requires detailed prior knowledge of each target's professional background, research interests, and network of contacts -- all of which are obtainable through structured open website reconnaissance.

### Volt Typhoon
**Volt Typhoon** has conducted pre-compromise web searches for victim information as part of its extensive reconnaissance operations against critical infrastructure targets, identifying specific personnel and technical details relevant to its network pre-positioning objectives.

***

## Mitigations

### Application Developer Guidance (MITRE M1013)
Application developers publishing code to public repositories must be trained to rigorously avoid committing sensitive information including credentials, API keys, private keys, and internal configuration data. Specific guidance should include:

- Use environment variables and secrets management platforms such as [HashiCorp Vault](https://www.vaultproject.io/) and [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) rather than hardcoded credential values in code.
- Add sensitive file patterns (`*.env`, `config.json`, `secrets.yaml`, `*.pem`, `*.key`) to `.gitignore` before the first commit to a repository.
- Review all files staged for commit before pushing to a public repository, treating every commit to a public repository as a permanent public disclosure.
- Rotate any credential or key immediately if it is discovered to have been committed to a public repository, regardless of how briefly it was exposed -- automated credential scanning tools are known to harvest newly committed secrets within seconds of publication.

### Audit (MITRE M1047)
Implement automated continuous scanning of all public code repositories associated with the organisation using tools such as [GitGuardian](https://www.gitguardian.com/), [truffleHog](https://github.com/trufflesecurity/trufflehog), and [Gitleaks](https://github.com/gitleaks/gitleaks) to detect and alert on exposed secrets before they are discovered and operationalised by adversaries. When exposed credentials are discovered:

- **Immediately rotate** the exposed credential or key, not merely remove it from the current file.
- **Rewrite the git commit history** using `git filter-branch` or the [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) to permanently remove the sensitive data from all historical commits, rather than simply committing a deletion that leaves the credential retrievable in commit history.
- **Investigate for compromise:** Treat any discovered exposed credential as potentially already collected and exploited, reviewing authentication logs for the relevant service for evidence of unauthorised access using the exposed credential.

### Additional Organisational Controls
Beyond code repository hygiene, organisations should implement broader controls to reduce open web intelligence exposure:

- **Employee social media guidance:** Publish clear guidance on the level of organisational and technical detail appropriate for public professional profiles, specifically discouraging disclosure of access levels, privileged role details, internal system names, and technology stack specifics.
- **Job posting content review:** Review all externally published job postings before publication to minimise disclosure of specific internal technology names, security tool vendors, and network architecture details that provide adversaries with actionable infrastructure intelligence.
- **Press release and public content review:** Implement an information security review step in the corporate communications approval process for press releases, blog posts, and partnership announcements that may inadvertently disclose details useful for social engineering or technical targeting.

***

## Detection Strategy

### Complete Passive Collection Opacity
Open website and domain reconnaissance is conducted entirely through publicly accessible platforms and generates no artefacts within the target organisation's IT infrastructure. Direct detection of this activity is entirely infeasible.

### Proactive Exposure Monitoring and Downstream Attack Detection

- **Continuous public repository scanning:** Integrate automated repository secret scanning into the CI/CD pipeline using [GitHub Advanced Security Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) and [GitGuardian](https://www.gitguardian.com/), enabling detection and alerting on sensitive data exposures at the point of push rather than after adversary discovery and exploitation.
- **Brand and personnel monitoring:** Deploy social media and web monitoring services to detect adversary-created profiles impersonating the organisation or its key personnel, enabling rapid takedown of fake accounts before they are used to conduct social engineering operations informed by open website reconnaissance.
- **Detection pivot to Initial Access:** Given the direct operational link between open website reconnaissance and targeted phishing campaigns, prioritise detection coverage at the Initial Access stage -- specifically monitoring for spearphishing delivery patterns, credential harvesting page access, and anomalous authentication events -- recognising that successful T1593 reconnaissance significantly increases the precision and effectiveness of subsequent phishing operations.
- **Exposed credential response monitoring:** Following any confirmed code repository credential exposure, implement enhanced monitoring for the affected service's authentication logs, treating any access attempt using the exposed credential as a confirmed compromise indicator requiring immediate incident response engagement.

***

## Sub-Techniques

| Sub-Technique | Primary Platforms | Intelligence Gathered | Key Tools and Resources | Adversarial Use Cases |
|---|---|---|---|---|
| **Social Media** | LinkedIn, Twitter/X, Facebook, Instagram, YouTube | Employee roles, responsibilities, technology certifications, project history, direct contact details, organisational structures and reporting relationships, business relationships, technology platforms in use, operational patterns and working schedules | LinkedIn People Search, [LinkedIn Sales Navigator](https://business.linkedin.com/sales-solutions/sales-navigator), [Maltego](https://www.maltego.com/), [SpiderFoot](https://www.spiderfoot.net/), [theHarvester](https://github.com/laramies/theHarvester) | Building precision targeting profiles for spearphishing and vishing; identifying high-value personnel by access level and role (T1591.004); enumerating technology platforms through employee certifications; mapping organisational hierarchies and team structures (T1591.004); crafting contextually convincing social engineering lures |
| **Search Engines** | Google, Bing, DuckDuckGo, specialised search engines, AI-powered LLM search tools | Accidentally published configuration files, exposed documents containing sensitive data, login portals, API endpoint documentation, corporate news, job postings, contract awards, partner disclosures | Google advanced operators (`site:`, `filetype:`, `inurl:`, `intitle:`), [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database), [Shodan](https://www.shodan.io/), LLMs (as used by Kimsuky), [Bing Webmaster Tools](https://www.bing.com/webmasters/) | Google Dorking for sensitive indexed files; using LLMs to aggregate and synthesise open web intelligence at scale; identifying target organisations and key personnel by sector and role; discovering unintentionally indexed sensitive content |
| **Code Repositories** | [GitHub](https://github.com/), [GitLab](https://about.gitlab.com/), [Bitbucket](https://bitbucket.org/), [SourceForge](https://sourceforge.net/) | Hardcoded credentials, API keys and access tokens, cloud provider secrets (AWS, Azure, GCP), infrastructure configuration data (Terraform, Ansible, Kubernetes), internal hostnames and endpoints, SSH and TLS private keys, historical commit data containing previously exposed secrets | [truffleHog](https://github.com/trufflesecurity/trufflehog), [Gitleaks](https://github.com/gitleaks/gitleaks), [GitGuardian](https://www.gitguardian.com/), [gitrob](https://github.com/michenriksen/gitrob), [Semgrep](https://semgrep.dev/) | Harvesting active API keys and credentials from public repositories for immediate exploitation via T1078 - Valid Accounts; extracting internal infrastructure details from configuration files; analysing historical commit history for credentials removed from current code but still present in git log; scanning for cloud provider credentials enabling direct cloud environment compromise |
