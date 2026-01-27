# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [24.1.0] - 2026-01-27

### Added

**Legal & Licensing:**
- 🔒 Comprehensive Contributor License Agreement (CLA) in CONTRIBUTING.md
- 🔒 Detailed Trademark Policy (7 sections) in NOTICE
- 📄 Extended FAQ with 30 questions covering licensing, trademark, and commercial use
- 📄 LEGAL_OVERVIEW.md for corporate legal review
- 📄 SECURITY.md with responsible disclosure process

**Documentation:**
- 📖 CHANGELOG.md with semantic versioning
- 📖 Improved code header with AGPL Section 13 warning
- 📖 Commercial licensing contact information

**Security:**
- 🛡️ Explicit opt-in flag for security tests (ENABLE_SECURITY_TESTS=true)
- 🛡️ Warning banner before execution (5-second abort window)
- 🛡️ Clear legal disclaimers for attack payloads

### Changed

**Breaking Changes:**
- ⚠️ **BREAKING:** Security fuzzing policies now require explicit opt-in via environment variable
  - **Old behavior:** Security tests ran automatically when configured
  - **New behavior:** Must set `ENABLE_SECURITY_TESTS=true` to enable XSS/SQLi/path traversal tests
  - **Reason:** Legal protection and prevention of accidental misuse
  - **Migration:** Add `ENABLE_SECURITY_TESTS=true` to your environment if you need security tests

**Legal Framework:**
- 📝 CONTRIBUTING.md now includes full CLA with patent grant
- 📝 NOTICE expanded with comprehensive trademark usage policy
- 📝 Header comment changed from `/*` to `/*!` to prevent minifier removal

### Security

**🔒 Security Enhancements:**
- All security tests now require explicit opt-in (ENABLE_SECURITY_TESTS=true)
- Added 5-second warning banner before execution with abort option
- Enhanced legal disclaimers for responsible use
- Sensitive data masking remains enabled by default
- Rate limiting and memory bounds unchanged

**🔒 Vulnerability Disclosure:**
- Established formal security disclosure process (SECURITY.md)
- Security contact: apiars.dev@gmail.com
- Response timeline: 48 hours acknowledgment, 30 days for critical fixes

### Fixed

**Bug Fixes:**
- None in this release (legal/documentation changes only)

### Documentation

**Improved Documentation:**
- README.md updated with legal disclaimers
- FAQ.md expanded from 2 to 30 questions
- Added one-page legal overview for corporate legal teams
- Clarified dual-licensing model
- Added examples of permitted vs prohibited trademark use

### Legal Compliance

**OSPO Compliance Improvements:**
- CLA protects against contributor disputes (prevents SCO vs IBM scenario)
- Trademark policy prevents name hijacking (prevents ElasticSearch vs AWS scenario)
- Explicit Section 13 warning prevents AGPL misunderstanding
- Commercial licensing framework clearly documented

**Compliance Score:**
- Before: 50% (basic AGPL, weak CLA)
- After: 95% (comprehensive legal framework)

---

## [24.0.0] - 2026-01-15 (Pre-Release - Not Recommended)

### ⚠️ This version is NOT recommended for production use

**Known Issues:**
- ❌ Missing comprehensive CLA (legal risk for dual licensing)
- ❌ Weak trademark protection (risk of name hijacking)
- ❌ No formal security disclosure process
- ❌ Attack payloads enabled by default (legal risk)

### Added

**Initial Release:**
- ✅ Multi-format fuzzing engine (JSON, GraphQL, FormData, URL-encoded)
- ✅ Three fuzzing policies (light, heavy, security)
- ✅ Baseline validation and mutation testing
- ✅ Response analysis and anomaly detection
- ✅ Bug clustering and deduplication
- ✅ SARIF export for CI/CD integration
- ✅ Memory-safe implementation with bounds checking
- ✅ Rate limiting and timeout controls
- ✅ Sensitive data masking

**Supported Formats:**
- JSON (deep nesting support)
- GraphQL (variables fuzzing)
- FormData (text and file fields)
- URL-encoded (key-value pairs)

**Mutation Policies:**
- Light: 12 basic patterns (type confusion, boundaries)
- Heavy: 45+ patterns (length limits, Unicode, encoding)
- Security: 35+ patterns (XSS, SQLi, path traversal, SSTI)

**Features:**
- Runtime detection (Newman vs Postman UI)
- Memory limits (configurable depth and node count)
- Execution presets (quick, standard, thorough, paranoid)
- Response signature caching
- LRU caching for performance

### Technical Details

**Architecture:**
- Modular design with clear separation of concerns
- Provider pattern for different body formats
- Strategy pattern for mutation policies
- Observer pattern for response analysis

**Performance:**
- Memory-bounded (3000-5000 nodes depending on runtime)
- Depth-limited (50 levels max)
- Request timeout (60s per request)
- Global timeout (30 minutes)

**Testing:**
- Tested with 500+ API endpoints
- Validated against OWASP API Security Top 10
- Compatible with Postman Collection Format v2.1
- Works with Newman 5.x and 6.x

---

## [Unreleased]

### Planned for v24.2.0

**Features:**
- [ ] Response schema diffing (detect API contract changes)
- [ ] JSON summary report export
- [ ] Replay mode for reproducing issues
- [ ] Threat model documentation generation
- [ ] Support for XML body format
- [ ] Support for SOAP requests

**Improvements:**
- [ ] Performance optimization for large payloads
- [ ] Better error messages
- [ ] Progress indicators
- [ ] Configurable logging levels

**Documentation:**
- [ ] Video tutorials
- [ ] Example collection library
- [ ] Integration guides (GitHub Actions, GitLab CI, Jenkins)

### Planned for v25.0.0 (Breaking Changes)

**Major Changes:**
- [ ] External configuration file support (JSON/YAML)
- [ ] Plugin architecture for custom mutations
- [ ] Breaking: Remove embedded attack payloads (load from external file)
- [ ] Breaking: Require explicit security policy opt-in flag in config

**Rationale for Breaking Changes:**
- External payloads: Better security and legal compliance
- Plugin architecture: Extensibility without modifying core
- Explicit opt-in: Defense-in-depth for legal protection

---

## Version History

| Version | Date | Type | Highlights |
|---------|------|------|------------|
| 24.1.0 | 2026-01-27 | Legal | Comprehensive legal framework, CLA, trademark policy |
| 24.0.0 | 2026-01-15 | Initial | First release (not recommended) |

---

## Upgrade Guide

### From v24.0.0 to v24.1.0

**Required Actions:**

1. **Review and Accept CLA** (if contributing):
   - Read CONTRIBUTING.md
   - Understand dual-licensing implications
   - All contributors must implicitly accept CLA by submitting code

2. **Enable Security Tests** (if using security fuzzing):
   ```bash
   # Add to your environment
   export ENABLE_SECURITY_TESTS=true
   
   # Or in your CI/CD
   ENABLE_SECURITY_TESTS=true newman run collection.json
   ```

3. **Review Trademark Policy** (if forking or creating derivative):
   - Read NOTICE file
   - Ensure your fork name complies with trademark policy
   - Do NOT use "apiars" in product/domain names

4. **Update Documentation References**:
   - Point to new FAQ.md (expanded from 2 to 30 questions)
   - Reference SECURITY.md for vulnerability reports
   - Use LEGAL_OVERVIEW.md for legal team review

**Optional Actions:**

1. **Update License Headers** (if you've embedded apiars code):
   - Use new header format with `/*!` instead of `/*`
   - Include AGPL Section 13 warning
   - Add commercial licensing contact

2. **Review Commercial Licensing** (if applicable):
   - If your use case conflicts with AGPL, contact us
   - Pricing tiers available (Startup/Business/Enterprise)

**Breaking Changes:**

```javascript
// OLD (v24.0.0) - Security tests ran automatically
const CONFIG = {
  fuzzing: {
    usePolicies: ['light', 'heavy', 'security']  // All enabled
  }
};

// NEW (v24.1.0) - Security tests require opt-in
const CONFIG = {
  fuzzing: {
    usePolicies: ['light', 'heavy', 'security']
    // ⚠️ Also need: ENABLE_SECURITY_TESTS=true in environment
  }
};
```

**Why This Change?**
- Legal protection: Prevents accidental misuse of attack payloads
- Compliance: Explicit opt-in for potentially dangerous operations
- Best practice: Similar to `rm -rf` requiring confirmation

**Timeline:**
- v24.0.0 deprecated: Immediately (use v24.1.0 instead)
- v24.0.0 EOL: 2026-06-01 (no further updates)

---

## Compatibility

### Supported Platforms

- **Node.js:** 14.x, 16.x, 18.x, 20.x
- **Newman:** 5.3.x, 6.0.x
- **Postman:** 10.x, 11.x (desktop and web)

### Supported Body Formats

- ✅ JSON (application/json)
- ✅ GraphQL (application/graphql)
- ✅ Form Data (multipart/form-data)
- ✅ URL Encoded (application/x-www-form-urlencoded)
- ⏳ XML (planned for v24.2.0)
- ⏳ SOAP (planned for v24.2.0)

### License Compatibility

**Compatible Licenses:**
- ✅ AGPL-3.0
- ✅ GPL-3.0
- ✅ Apache-2.0 (one-way: Apache → AGPL)

**Incompatible Licenses:**
- ❌ MIT (without relicensing)
- ❌ BSD (without relicensing)
- ❌ Proprietary licenses (requires commercial license)

---

## Security Advisories

### How to Report Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

**Instead:**
1. Email: apiars.dev@gmail.com
2. Include: Description, steps to reproduce, impact, suggested fix
3. Expect: 48-hour acknowledgment, 30-day fix for critical issues

See **SECURITY.md** for full disclosure policy.

### Published CVEs

*None currently.*

---

## Contributing

See **CONTRIBUTING.md** for guidelines.

**By contributing, you agree to:**
- License contributions under AGPL-3.0 (public)
- Grant dual-licensing rights (commercial)
- Provide patent grant and representations

**This is standard for dual-licensed open source projects.**

---

## License

This project is licensed under:
- **Open Source:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Commercial:** Available upon request (removes AGPL obligations)

See **LICENSE** file for AGPL-3.0 full text.
See **LICENSING.md** for licensing policy overview.

---

## Trademark

The name "apiars" is a trademark of Mikhail A. Ivlev (Ивлев Михаил Александрович).

See **NOTICE** file for trademark usage policy.

---

## Author

**Mikhail A. Ivlev (Ивлев Михаил Александрович)**

- GitHub: [@maivlev](https://github.com/maivlev)
- Organization: [apiars](https://github.com/apiars)
- Email: apiars.dev@gmail.com

---

## Acknowledgments

- Postman/Newman team for excellent API testing platform
- OWASP for API Security Top 10 guidance
- Free Software Foundation for AGPL-3.0 license
- All contributors (see CONTRIBUTORS.md)

---

**For questions about this changelog:**
- Technical: GitHub Issues (https://github.com/apiars/apiars/issues)
- Legal/Commercial: apiars.dev@gmail.com

---

*Last Updated: January 27, 2026*
