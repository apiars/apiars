# Security Policy

## 🔒 Security Overview

apiars is a security testing tool designed to identify vulnerabilities in APIs.
This document outlines our security practices and vulnerability disclosure process.

---

## ⚠️ Responsible Use Policy

### Authorized Use Only

This tool is designed for **authorized security testing only**. By using this software, you agree to:

1. **Only test systems you own** or have explicit written authorization to test
2. **Comply with all applicable laws** in your jurisdiction
3. **Not use this tool for malicious purposes** or unauthorized access
4. **Respect data privacy** and confidentiality

### Legal Considerations

Unauthorized use of this tool may violate:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act 1990 - United Kingdom
- GDPR Article 32 (Security of Processing) - European Union
- Similar laws in other jurisdictions

**You are responsible for compliance** with all applicable laws and regulations.

---

## 🛡️ Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 24.1.x  | ✅ Yes            | Current stable release |
| 24.0.x  | ⚠️ Limited        | Critical fixes only (EOL: 2026-06-01) |
| < 24.0  | ❌ No             | No longer supported |

---

## 🐛 Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow this process:

### How to Report

**Email:** apiars.dev@gmail.com

**PGP Key:** [Optional: Include PGP fingerprint for encrypted communications]

### What to Include

Please provide the following information:

1. **Description** - Clear description of the vulnerability
2. **Impact** - What can an attacker do? (e.g., RCE, data exposure, DoS)
3. **Affected Versions** - Which versions are vulnerable?
4. **Steps to Reproduce** - Detailed steps to reproduce the issue
5. **Proof of Concept** - Code/screenshots (if safe to share)
6. **Suggested Fix** - (Optional) How to fix the vulnerability
7. **Disclosure Timeline** - When do you plan to publicly disclose?

### Example Report

```
Subject: [SECURITY] Vulnerability in apiars v24.1.0

Description: [Clear description of the issue]
Impact: [What an attacker could do]
Affected Versions: 24.0.0 - 24.1.2
Steps to Reproduce:
  1. [Step 1]
  2. [Step 2]
  3. [Observed behavior]
Suggested Fix: [Optional recommendation]
Disclosure: Will publish in 90 days (2026-04-27)
```

---

## ⏱️ Response Timeline

We commit to the following timeline:

| Phase | Timeline | Action |
|-------|----------|--------|
| **Initial Response** | 48 hours | Acknowledge receipt of report |
| **Triage** | 5 business days | Confirm or reject vulnerability |
| **Fix Development** | 30 days (critical)<br>90 days (medium) | Develop and test fix |
| **Disclosure** | Coordinated with reporter | Public disclosure after fix |

### Severity Levels

- **Critical** (CVSS 9.0-10.0): RCE, data breach, auth bypass
  - Fix: 30 days
  - Immediate patch release
  
- **High** (CVSS 7.0-8.9): Privilege escalation, DoS
  - Fix: 60 days
  - Next minor release
  
- **Medium** (CVSS 4.0-6.9): Information disclosure, logic errors
  - Fix: 90 days
  - Next patch release
  
- **Low** (CVSS 0.1-3.9): Minor issues
  - Fix: Best effort
  - Next scheduled release

---

## 🏆 Security Researcher Recognition

We appreciate responsible disclosure. With your permission, we will:

1. **Credit you** in the CHANGELOG and release notes
2. **List you** in our Hall of Fame (security researchers page)
3. **Provide recognition** for significant findings

---

## 🔐 Security Features

### Current Protections

apiars v24.1 includes the following security features:

1. **Sensitive Data Masking**
   - Automatically masks tokens, passwords, API keys in logs
   - Configurable via `SECURITY_CONFIG.maskInLogs`
   - Prevents accidental credential exposure

2. **Rate Limiting**
   - Prevents DoS attacks via `createRateLimiter()`
   - Configurable delay: `CONFIG.delayMs` (default: 1000ms)
   - Protects target APIs from abuse

3. **Memory Bounds**
   - Prevents OOM crashes via `MEMORY_LIMITS`
   - Max node collection: 5000 (Postman), 3000 (Newman)
   - Max depth: 50 levels (prevents infinite loops)

4. **Request Timeouts**
   - Single request: 60 seconds (`requestTimeoutMs`)
   - Global execution: 30 minutes (`globalTimeoutMs`)
   - Prevents hanging processes

5. **Input Validation**
   - Type checking for configuration
   - Path validation (prevents traversal in file operations)
   - Payload size limits (10 MB max)

6. **Explicit Security Test Opt-In**
   - Requires `ENABLE_SECURITY_TESTS=true` environment variable
   - Prevents accidental execution of attack payloads
   - 5-second abort window before execution

### Known Limitations

1. **No Encryption at Rest** - Results are stored in plain text
2. **No HTTPS Enforcement** - Users must configure HTTPS manually
3. **Limited Authentication** - No built-in auth mechanism
4. **Postman Dependency** - Inherits Postman security model

---

## 🚨 Security Advisories

Published security advisories will be listed here:

**Current Status:** No published CVEs

When vulnerabilities are discovered and fixed, they will be documented here with:
- CVE identifier (if assigned)
- Affected versions
- Fixed version
- Severity rating
- Mitigation steps

---

## 🔍 Security Audit History

| Date | Auditor | Scope | Findings | Status |
|------|---------|-------|----------|--------|
| 2026-01-27 | Internal OSPO | Full codebase | 15 issues | ✅ Resolved |
| 2026-01-27 | Legal Framework | Licensing & IP | 3 critical | ✅ Resolved |

---

## 📚 Security Best Practices

### For Users

1. **Use Latest Version** - Always run the most recent stable release
2. **Enable Security Features** - Don't disable `SECURITY_CONFIG.maskInLogs`
3. **Review Logs** - Check for sensitive data before sharing
4. **Limit Scope** - Test only what's necessary
5. **Rotate Credentials** - Change test credentials regularly
6. **Use HTTPS** - Always test over encrypted connections
7. **Isolate Testing** - Run tests in isolated environments when possible

### For Developers

1. **Review PRs** - All code changes require security review
2. **Static Analysis** - Run ESLint + npm audit before commits
3. **Dependency Updates** - Update dependencies monthly
4. **Secrets Management** - Never commit secrets to Git
5. **Least Privilege** - Run with minimal permissions
6. **Code Signing** - Sign releases for authenticity

---

## 📞 Contact Information

### Security Team
- **Email:** apiars.dev@gmail.com
- **Response Time:** 48 hours
- **Preferred Method:** Email (encrypted with PGP if sensitive)

### General Support
- **GitHub Issues:** For non-security bugs and features
- **Discussions:** For questions and community support
- **Documentation:** See README.md and docs/

---

## 📖 Additional Resources

**Security Standards:**
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

**Reporting Formats:**
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0) (our output format)
- [CVE Numbering Authority](https://www.cve.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

**Secure Development:**
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

---

## 📝 Security Changelog

All security-related changes are documented in [CHANGELOG.md](CHANGELOG.md) with:
- 🔒 Prefix for security fixes
- CVE identifiers (if applicable)
- Upgrade instructions
- Impact assessment

---

## ⚖️ Legal

This security policy is subject to our [LICENSE](LICENSE) terms.

**Disclaimer:** 

While we strive to address all security issues promptly, we cannot guarantee:
- Zero vulnerabilities in the software
- Specific fix timelines beyond stated commitments
- Bounty payments (we do not currently offer a bug bounty program)

**Privacy:** 

We will not share reporter information without explicit consent.
Security reports are handled confidentially.

**Coordinated Disclosure:**

We follow responsible disclosure practices:
- Work with reporters to understand and fix issues
- Coordinate public disclosure timing
- Credit researchers (with permission)
- Notify affected users before public disclosure

---

## 🎯 Scope

### In Scope

Security issues in:
- Core fuzzing engine
- Request generation logic
- Response analysis
- Data handling and storage
- Configuration parsing
- Dependency vulnerabilities

### Out of Scope

- Issues in third-party dependencies (report to upstream)
- Postman/Newman platform issues (report to Postman)
- Social engineering attacks
- Physical security
- Denial of service via intentional API rate limiting

---

## 🔄 Policy Updates

This security policy is reviewed and updated every 6 months or after significant security events.

**Last Updated:** January 27, 2026  
**Version:** 1.0  
**Next Review:** July 27, 2026

---

## 📧 Emergency Contact

For critical security issues requiring immediate attention:

**Email:** apiars.dev@gmail.com  
**Subject Line:** [URGENT SECURITY] apiars vulnerability

Expected response time: **4 hours** for critical issues

---

**Questions about this policy?**

Contact: apiars.dev@gmail.com

---

*This document is provided for informational purposes and may be updated without notice.*
