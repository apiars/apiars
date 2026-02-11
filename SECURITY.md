# Responsible Use Policy

> **Note on File Name**: This file is named `SECURITY.md` per GitHub convention for security/responsible use policies, even though this tool is NOT a security testing tool.

---

## ⚠️ Important Notice

**apiars is a QA-oriented exploratory API fuzzing tool, NOT a security testing tool.**

### What This Tool IS

✅ Exploratory API fuzzing engine for QA  
✅ Robustness testing framework  
✅ Contract deviation detector  
✅ Edge case discovery tool

### What This Tool Is NOT

❌ Security scanner  
❌ Penetration testing tool  
❌ Vulnerability scanner  
❌ Hacking or exploitation framework  
❌ CI/CD automation system  
❌ Load/stress testing tool

---

## 🎯 Authorized Use Only

This tool is designed for **authorized API testing only**. By using this software, you agree to:

1. **Only test systems you own** or have explicit written authorization to test
2. **Comply with all applicable laws** in your jurisdiction
3. **Not use this tool for malicious purposes** or unauthorized access
4. **Respect data privacy** and confidentiality
5. **Use for QA purposes only**, not for security/penetration testing

---

## ⚖️ Legal Considerations

Unauthorized use of this tool may violate:

- **Computer Fraud and Abuse Act (CFAA)** - United States
- **Computer Misuse Act 1990** - United Kingdom
- **GDPR Article 32 (Security of Processing)** - European Union
- Similar laws in other jurisdictions

**You are responsible for compliance** with all applicable laws and regulations.

---

## 🛡️ Supported Versions

We provide updates for the following versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 27.14.x | ✅ Yes             | Current stable release |
| 27.0.x  | ⚠️ Limited         | Security fixes only (EOL: 2026-03-11) |
| 24.1.x  | ❌ No              | Deprecated (security features removed) |
| < 24.0  | ❌ No              | No longer supported |

---

## 🐛 Reporting Issues

### For Security/Legal Concerns

If you discover a security vulnerability or have concerns about misuse:

**Email:** apiars.dev@gmail.com  
**Subject:** [SECURITY] Brief description

**What to Include:**
1. Description of the issue
2. Impact assessment
3. Steps to reproduce (if applicable)
4. Suggested mitigation

### For Bugs and Features

- **GitHub Issues:** For non-security bugs and feature requests
- **Discussions:** For questions and community support

---

## ⏱️ Response Timeline

| Phase | Timeline | Action |
|-------|----------|--------|
| **Initial Response** | 48 hours | Acknowledge receipt |
| **Triage** | 5 business days | Assess and categorize |
| **Resolution** | 30 days (critical)<br>90 days (medium) | Develop and release fix |

---

## 📜 Scope Limitations

### Execution Environment

- **Runtime:** Postman sandbox and Newman CLI only
- **Network:** Standard API requests (HTTP/HTTPS)
- **System Access:** No filesystem, OS, or system-level interaction
- **Privileges:** No privilege escalation or bypass logic

### Supported Formats

- **JSON:** Full support with path filtering and nested objects
- **FormData:** Flat fields only (no nested structures)
- **URL-encoded:** Flat key-value pairs only
- **Query Parameters:** Flat parameters only (no nested objects)
- **NOT supported:** GraphQL, XML, Binary, Multipart File uploads

### Permitted Mutations

✅ Type confusion (null, boolean, string, number, array, object)  
✅ Boundary values (0, -1, Int32.MAX, Number.MAX_SAFE_INTEGER)  
✅ Empty values (empty string, array, object)  
✅ Format validation (invalid dates, emails, UUIDs)  
✅ String edge cases (whitespace, newlines, UTF-8)  
✅ Length boundaries (VARCHAR(255), medium strings)  
✅ Structural mutations (field deletion, object/array replacement)

### Prohibited Mutations (Removed in v27.0.4)

❌ SQL injection patterns  
❌ XSS payloads  
❌ Command injection  
❌ Path traversal  
❌ LDAP injection  
❌ XXE payloads  
❌ SSRF payloads  
❌ Template injection (SSTI)  
❌ Any attack signatures or exploit payloads

---

## 🔒 Built-in Safety Features

1. **Rate Limiting** - Prevents API overload (default: 1000ms delay)
2. **Resource Limits** - Maximum requests: 5000, execution time: 60 minutes
3. **Memory Bounds** - Maximum depth: 50 levels, prevents infinite loops
4. **Explicit Enablement** - Engine disabled by default (`ENGINE_ENABLED = false`)

---

## 📚 Best Practices

### For Users

1. **Use Latest Version** - Always run the most recent stable release
2. **Test in Isolation** - Use dedicated test environments
3. **Review Logs** - Check for sensitive data before sharing
4. **Limit Scope** - Test only what's necessary
5. **Rotate Credentials** - Change test credentials regularly
6. **Use HTTPS** - Always test over encrypted connections

### For Developers

1. **Review PRs** - All code changes require review
2. **Static Analysis** - Run ESLint + npm audit before commits
3. **Update Dependencies** - Update dependencies monthly
4. **Secrets Management** - Never commit secrets to Git

---

## 📞 Contact Information

### Security Team
- **Email:** apiars.dev@gmail.com
- **Response Time:** 48 hours
- **Preferred Method:** Email

### General Support
- **GitHub Issues:** For non-security bugs and features
- **Discussions:** For questions and community support

---

## 📖 Additional Resources

**Security Standards:**
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

**Related Documents:**
- [CHANGELOG.md](CHANGELOG.md) - Version history and migration guide
- [FAQ.md](FAQ.md) - Frequently asked questions
- [README.md](README.md) - Project overview
- [LICENSE](LICENSE) - AGPL-3.0 license

---

## ⚖️ Legal

This security policy is subject to our [LICENSE](LICENSE) terms.

**Disclaimer:** 

While we strive to address all issues promptly, we cannot guarantee:
- Zero vulnerabilities in the software
- Specific fix timelines beyond stated commitments

**Privacy:** 

We will not share reporter information without explicit consent.
Reports are handled confidentially.

---

## 📄 Policy Updates

This policy is reviewed every 6 months or after significant events.

**Last Updated:** February 11, 2026  
**Version:** 2.1  
**Next Review:** August 11, 2026

---

**Questions about this policy?**

Contact: apiars.dev@gmail.com

---

*This document is provided for informational purposes and may be updated without notice.*
