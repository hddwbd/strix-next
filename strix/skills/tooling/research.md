---
name: research
description: Advanced web research techniques for security testing - when to search for exploits, bypasses, and new attack techniques
---

# Security Research Skill

## When to Use Web Search

Use the `web_search` tool as a supplemental research capability after you have already tried the local PoC path.

If you have strong component or version evidence, try `poc_shortlist` first.
Only if local PoC shortlisting does not produce usable candidates should you use `web_search`.

### Critical Scenarios Requiring Research

**1. Unknown or Unfamiliar Technologies**
- Encountered a service, framework, or technology you're not deeply familiar with
- Need to understand attack surface and common vulnerabilities
- Example: "Found Grafana 9.5.2 running - what are the latest authentication bypass vulnerabilities?"

**2. Stuck on Exploitation**
- Attempted multiple exploitation techniques without success
- Need alternative approaches or bypass methods
- Example: "WAF is blocking all my SQLi payloads - what are the latest WAF bypass techniques for 2025?"

**3. Version-Specific Vulnerabilities**
- Discovered specific software versions during reconnaissance
- First try to match local PoCs for the exact product or version
- Use web search only when local PoCs are missing, blocked, or insufficient
- Example: "Target running Apache Tomcat 9.0.65 - are there any RCE exploits for this version?"

**4. Bypass Techniques**
- Security controls are blocking your attacks (WAF, IPS, EDR, rate limiting)
- Need modern evasion and bypass methods
- Example: "Cloudflare WAF is blocking my requests - what are current bypass techniques?"

**5. New Attack Vectors**
- Discovered interesting functionality that might be vulnerable
- Need to research attack patterns for specific features
- Example: "Found GraphQL endpoint with introspection enabled - what are the latest GraphQL security testing techniques?"

**6. Tool Selection**
- Need to find the best tool for a specific security testing task
- Looking for alternatives when primary tools fail
- Example: "What's the best tool for testing JWT vulnerabilities in 2025?"

**7. Privilege Escalation**
- Gained initial access but stuck on privilege escalation
- Need OS/kernel-specific exploits
- Example: "Have shell on Ubuntu 22.04 with kernel 5.15.0-89 - what are the latest privilege escalation exploits?"

**8. Zero-Day Research**
- Found potentially novel vulnerability patterns
- Need to verify if it's a known issue or new discovery
- Example: "Found IDOR in API endpoint /api/v2/users/{id}/settings - is this a known vulnerability pattern for this framework?"

## Research Best Practices

### Be Specific in Queries

**Bad Query:**
```
"How to hack WordPress?"
```

**Good Query:**
```
"WordPress 6.4.2 with WooCommerce 8.5.1 - what are the current authenticated RCE exploits or privilege escalation vulnerabilities?"
```

### Include Context

Always provide:
- Exact versions when known
- Current stage of attack (recon, exploitation, post-exploitation)
- What you've already tried
- Specific error messages or behaviors observed

### Research Early and Often

Do not treat research as the first automatic move once version information appears.
Use research proactively only after checking whether local PoC shortlisting already covers the identified target.

Research is especially useful:
- When local PoC shortlisting does not match the fingerprinted target
- When all matched candidates are `manual_only`
- When the available evidence is too weak to support reliable PoC matching
- When a working local PoC still needs current bypass or exploitation context

### Validate Research Results

After getting search results:
1. Verify the information applies to your specific target version
2. Test techniques in a controlled manner first
3. Adapt generic exploits to your specific context
4. Document what works and what doesn't

## Example Research Workflows

### Workflow 1: New Technology Discovery
```
1. Reconnaissance finds: "Jenkins 2.426.1"
2. Try `poc_shortlist` first with Jenkins product/version evidence
3. If local PoC shortlisting does not produce usable candidates, research: "Jenkins 2.426.1 security vulnerabilities CVE 2024"
4. Follow-up: "Jenkins authentication bypass techniques"
5. Tool research: "Best tools for Jenkins security testing"
```

### Workflow 2: Stuck on Exploitation
```
1. Attempted: local PoC discovery and safe execution for the fingerprinted component
2. Result: no usable candidate or execution blocked by defenses
3. Research: "Cloudflare WAF SQL injection bypass 2025"
4. Research: "Alternative SQL injection techniques for WAF bypass"
5. Research: "Time-based blind SQLi WAF evasion"
```

### Workflow 3: Privilege Escalation
```
1. Gained: Low-privilege shell access
2. Enumeration: Ubuntu 20.04, kernel 5.4.0-150-generic
3. Research: "Ubuntu 20.04 kernel 5.4.0-150 privilege escalation exploits"
4. Research: "Linux privilege escalation techniques 2025"
5. Research: "Sudo vulnerabilities Ubuntu 20.04"
```

## Integration with Other Skills

Combine research with other skills:
- **After reconnaissance**: build `recon_summary`, try `poc_shortlist`, then research missing gaps
- **During exploitation**: Research bypass techniques
- **With business_logic skill**: Research framework-specific logic flaws
- **With authentication_jwt skill**: Research latest JWT attack techniques

## Remember

- Local PoC matching comes before broad external research when fingerprint evidence is available
- When component evidence is strong, try `poc_shortlist` first
- Research is a fallback and enrichment path, not the default first move
- Research AFTER attempting local PoC shortlisting for fingerprinted targets
- Stay current with latest techniques and bypasses
- Document useful findings in notes for future reference
- Share relevant research with other agents via notes tool
