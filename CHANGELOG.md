# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [27.14.6] - 2026-02-11

### 🎯 Overview

This is a **minor update** focused on improving bug clustering, CURL generation, and fuzzing control.

**Key improvements:**
- 🆕 Configurable bug clustering (CLUSTER_CONFIG)
- 🆕 CURL command generation for bug reproduction
- 🆕 Fuzzing limits for large APIs (maxObjectsToFuzz, maxArraysToFuzz)
- ✅ Backward compatible with v27.0.4

**Migration:** No breaking changes. Simply replace engine.js and optionally configure new features.

---

### Added

**🆕 Bug Clustering Configuration (CLUSTER_CONFIG):**

New configuration object for controlling bug cluster output:

\`\`\`javascript
const CLUSTER_CONFIG = Object.freeze({
    includeCodes: [400, 422],           // HTTP codes to cluster
    excludeSuccessCodes: true,          // Exclude 2xx from clusters
    maxClustersToShow: 40,              // Max clusters in output
    minOccurrencesToShow: 1,            // Min occurrences to display
    detailedCurlOutput: true,           // Generate CURL for each example
    maxCurlsPerCluster: 3,              // Max CURL commands per cluster
    showMutationDetails: true           // Show mutation path/type
});
\`\`\`

**Benefits:**
- Customizable cluster filtering by HTTP codes
- Control output verbosity
- Detailed reproduction commands for each bug
- Better organization of test results

---

**🆕 CURL Generation (CURL_CONFIG + buildCurl()):**

New configuration and function for generating CURL commands:

\`\`\`javascript
const CURL_CONFIG = Object.freeze({
    enabled: true,                      // Enable/disable CURL generation
    maxBodyLength: 5000                 // Max body size in CURL (bytes)
});
\`\`\`

**New function:** \`buildCurl(requestSnapshot)\`
- Automatically generates CURL commands from request snapshots
- Handles JSON, FormData, URLEncoded, Query Parameters
- Safe shell escaping (escapeForShell() helper)
- Truncates large bodies (controlled by maxBodyLength)

**Example output:**
\`\`\`bash
curl -X POST 'https://api.example.com/users' \\
  -H 'Content-Type: application/json' \\
  -H 'Authorization: Bearer token123' \\
  -d '{"email":null,"name":"test"}'
\`\`\`

**Benefits:**
- Easy bug reproduction
- Quick testing in terminal
- Share reproducible test cases
- Integration with external tools

---

**🆕 Fuzzing Limits (STAGE_CONFIG.fuzzing):**

New parameters to control fuzzing scope for large APIs:

\`\`\`javascript
fuzzing: Object.freeze({
    enabled: true,
    usePolicies: ['light'],
    typeAwareness: true,
    fuzzObjects: true,
    fuzzArrays: true,
    maxObjectsToFuzz: 20,               // ✅ NEW: Limit objects
    maxArraysToFuzz: 20,                // ✅ NEW: Limit arrays
    maxMutationsPerParam: 10            // ✅ NEW: Limit query param mutations
})
\`\`\`

**Benefits:**
- Prevent excessively long test runs
- Focus on critical fields
- Optimize for time-constrained testing
- Better control for CI/CD integration

**Default values:**
- \`maxObjectsToFuzz: 20\` (0 = unlimited)
- \`maxArraysToFuzz: 20\` (0 = unlimited)
- \`maxMutationsPerParam: 10\` (0 = unlimited)

---

**🆕 Parametrized Minimal Payload Threshold (STAGE_CONFIG.progressiveDelete):**

Previously hardcoded 1000-byte threshold is now configurable:

\`\`\`javascript
progressiveDelete: Object.freeze({
    enabled: true,
    continueOnError: true,
    logMinimalPayload: true,
    minimalPayloadSizeThreshold: 1000   // ✅ NEW: Configurable threshold
})
\`\`\`

**Benefits:**
- Adjust logging verbosity
- Control console output size
- Customize for different API sizes

---

**🆕 Additional Mutation in MUTATION_POLICIES.heavy:**

Added \`[null]\` mutation for VALUE fuzzing when \`fuzzArrays=false\`:

\`\`\`javascript
heavy: Object.freeze([
    // ... existing mutations ...
    [null]          // 🔥🔥 Array with null: needed for VALUE mutation
])
\`\`\`

**Use case:** Tests how APIs handle arrays containing null values when array structure fuzzing is disabled.

---

### Changed

**📝 Improved Logging Semantics:**

Replaced 98 instances of \`console.log()\` with \`console.info()\` for informational messages:

| Method | v27.0.4 | v27.14.6 | Change |
|--------|---------|----------|--------|
| \`console.log()\` | 98 | 0 | -98 |
| \`console.info()\` | 0 | 114 | +114 |
| \`console.warn()\` | 37 | 37 | no change |
| \`console.error()\` | 56 | 56 | no change |

**Benefits:**
- Semantically correct logging levels
- Better filtering in Postman console
- Clearer distinction between info/warning/error
- Follows industry best practices

---

### Migration Guide

#### From v27.0.4 to v27.14.6

**✅ Fully backward compatible - no breaking changes.**

**Required Actions:**

1. **Replace engine.js file**
   \`\`\`bash
   # Backup old version (optional)
   cp engine.js engine_v27.0.4.backup.js
   
   # Download new version
   wget https://github.com/apiars/apiars/raw/main/engine.js
   \`\`\`

2. **Verify version**
   \`\`\`javascript
   // Check first line of engine.js
   const ENGINE_VERSION = '27.14.6';  // ✅ Should be 27.14.6
   \`\`\`

**That's it!** No other changes required. All new configurations are optional.

---

### Compatibility

**Platforms:**
- ✅ Postman 10.x, 11.x (no changes)
- ✅ Newman 5.3.x, 6.0.x (no changes)
- ✅ Node.js 14.x, 16.x, 18.x, 20.x (no changes)

**Configuration:**
- ✅ All v27.0.4 configurations work without modification
- ✅ New configurations are optional
- ✅ Defaults match v27.0.4 behavior (when new configs omitted)

---

### Technical Details

**Code Changes:**
- Added: 600 lines
- Removed: 227 lines
- Net change: +373 lines (+295 functional code, -78 license header)

**New Functions:**
- \`buildCurl(requestSnapshot)\` - ~51 lines
- \`escapeForShell(str)\` - ~5 lines

**New Configurations:**
- \`CLUSTER_CONFIG\` - 7 parameters
- \`CURL_CONFIG\` - 2 parameters
- \`STAGE_CONFIG.fuzzing\` - 3 new parameters
- \`STAGE_CONFIG.progressiveDelete\` - 1 new parameter

---
## [27.0.4] - 2026-02-08

### ⚠️ BREAKING CHANGES

**This is a major breaking release that removes all security testing features.**

---

### Removed

**🔴 Security Testing Features (Complete Removal):**
- ❌ Security fuzzing policies (`'security'` option removed from `usePolicies`)
- ❌ XSS attack payloads (all variants)
- ❌ SQL injection patterns (all variants)
- ❌ Path traversal payloads (`../`, `..\`, etc.)
- ❌ Command injection patterns
- ❌ LDAP injection patterns
- ❌ XXE payloads
- ❌ SSRF payloads
- ❌ SSTI (Server-Side Template Injection) patterns
- ❌ All other attack signatures and exploit payloads

**🔴 Format Support:**
- ❌ GraphQL format support (use JSON instead)

**🔴 CI/CD Integration:**
- ❌ SARIF export functionality
- ❌ ExecutionPresets (`quick`, `standard`, `thorough`, `paranoid`)
- ❌ `ENABLE_SECURITY_TESTS` environment variable (no longer needed)
- ❌ Security test opt-in mechanism

**🔴 Reporting Modules:**
- ❌ SARIF report generation
- ❌ Security findings export
- ❌ Vulnerability clustering

---

### Added

**✅ New Features:**

1. **JSON Path Filtering** (`TARGET_PATHS_KEYS`)
   - Target specific fields for focused testing
   - Syntax: `"user.email"`, `"order.items[].price"`
   - Reduces noise, improves efficiency
   - JSON format only

2. **Combinatorial Delete Stage**
   - Test pairs and triplets of field deletions
   - Configurable: `maxCombinations`, `maxFieldsPerCombo`
   - Finds inter-field dependencies
   - Example: `{maxCombinations: 50, maxFieldsPerCombo: 3}`

3. **Progressive Delete Stage**
   - Binary search for minimal viable payload
   - Finds minimum required fields
   - Configurable: `continueOnError`, `logMinimalPayload`
   - Useful for understanding API contracts

4. **Format Validation Policy**
   - New policy: `'format_validation'`
   - Replaces security-focused mutations
   - Focus: Data format correctness
   - 6 validation patterns (dates, emails, UUIDs, format confusion)

5. **Enhanced Logging**
   - JSON structure map visualization
   - Detailed mutation logging (`ENABLE_MUTATION_LOGGING`)
   - Better debugging capabilities

6. **Query Parameter Support**
   - Fuzzing for URL query parameters (flat parameters only)
   - Pairs with existing JSON/FormData/URLEncoded support

---

### Changed

**📝 Mutation Policies:**

**Before v27.0.4:**
```javascript
usePolicies: ['light', 'heavy', 'security']
```

**After v27.0.4:**
```javascript
usePolicies: ['light', 'heavy', 'format_validation']
```

**🔧 Configuration:**

**Before v27.0.4:**
```javascript
const ENGINE_ENABLED = true;
const ENABLE_SECURITY_TESTS = true;  // Required for security fuzzing
```

**After v27.0.4:**
```javascript
const ENGINE_ENABLED = true;
// ENABLE_SECURITY_TESTS removed - no longer exists
```

**📋 Stage Configuration:**

**Before v27.0.4:**
```javascript
const STAGE_CONFIG = {
    baseline: { enabled: true },
    fuzzing: { enabled: true, usePolicies: ['light', 'heavy', 'security'] },
    singleDelete: { enabled: true }
};
```

**After v27.0.4:**
```javascript
const STAGE_CONFIG = {
    baseline: { enabled: true },
    fuzzing: { enabled: true, usePolicies: ['light', 'heavy', 'format_validation'] },
    singleDelete: { enabled: true },
    combinatorialDelete: { enabled: true, maxCombinations: 50 },
    progressiveDelete: { enabled: true, continueOnError: true }
};
```

---

### Migration Guide

#### Step 1: Update Configuration

**Remove:**
```javascript
// ❌ REMOVE these lines
const ENABLE_SECURITY_TESTS = true;
```

**Update:**
```javascript
// ✅ UPDATE this
const STAGE_CONFIG = {
    fuzzing: {
        usePolicies: ['light', 'heavy']  // Remove 'security', optionally add 'format_validation'
    }
};
```

#### Step 2: Add New Features (Optional)

**Path Filtering:**
```javascript
const TARGET_PATHS_KEYS = [
    "user.email",
    "metadata.settings"
];
```

**Combinatorial Delete:**
```javascript
combinatorialDelete: {
    enabled: true,
    maxCombinations: 50,
    maxFieldsPerCombo: 3
}
```

**Progressive Delete:**
```javascript
progressiveDelete: {
    enabled: true,
    continueOnError: true,
    logMinimalPayload: true
}
```

#### Step 3: Format Changes

**If using GraphQL:**
- GraphQL format is NO LONGER supported
- Convert your request to JSON format
- Update request body type in Postman

**FormData/URLEncoded/QueryParams:**
- Now support only flat fields (no nested structures)
- If you have nested data, use JSON format instead

#### Step 4: Remove CI/CD Integration

**If using SARIF export:**
- SARIF export is NO LONGER available
- Use response logs for debugging
- Consider dedicated API testing tools for CI/CD

#### Step 5: Alternative for Security Testing

**If you need security testing:**

apiars v27.0.4+ is **NOT** designed for security testing.

**Recommended alternatives:**
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Burp Suite](https://portswigger.net/burp) - Security testing toolkit
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer

**Migration path:**
1. Export your API collection from Postman
2. Convert to OpenAPI/Swagger format (use `postman-to-openapi`)
3. Import into security testing tool of choice
4. Continue security testing there

---

### Rationale

**Why remove security features?**

1. **LLM Provider Policy Compliance**
   - LLM providers (OpenAI, Anthropic, etc.) restrict assistance with offensive security tools
   - Security features classify the tool as "penetration testing" or "vulnerability scanner"
   - Removal enables LLM-assisted development and support

2. **Scope Clarification**
   - apiars is better positioned as a QA tool
   - Security testing requires different approach (exploit chains, attack surfaces)
   - Clear separation: QA tools vs Security tools

3. **Legal Protection**
   - Security features create liability concerns
   - Clearer "authorized use only" enforcement
   - Reduces risk of tool misuse

4. **Better Tools for the Job**
   - Security testing is better served by dedicated tools (ZAP, Burp, Nuclei)
   - QA fuzzing is a distinct use case with different requirements
   - Specialization leads to better outcomes

5. **Development Focus**
   - Focus resources on QA-specific features
   - Deeper investment in robustness testing
   - Better contract deviation detection

6. **Maintenance Simplification**
   - Removal of GraphQL support simplifies codebase
   - Focus on well-supported formats (JSON, FormData, URLEncoded, QueryParams)
   - Better testing and validation coverage

**Why remove GraphQL support?**

- GraphQL fuzzing requires different approach than REST
- JSON format can be used for GraphQL variables
- Simplifies codebase and maintenance
- Dedicated GraphQL fuzzers exist (e.g., InQL, GraphQL Cop)

---

### Documentation

**📝 Updated Files:**
- [README.md](README.md) - Complete rewrite with new features
- [SECURITY.md](SECURITY.md) - Renamed focus to "Responsible Use Policy"
- [FAQ.md](FAQ.md) - Added migration and rationale questions (Q31-Q36)
- [NOTICE](NOTICE) - Updated project description
- [LICENSING.md](LICENSING.md) - Updated project type
- [LEGAL_OVERVIEW.md](LEGAL_OVERVIEW.md) - Updated project type

---

### Technical Details

**Engine Version:** 27.0.4  
**Release Date:** February 8, 2026  
**Breaking Changes:** Yes (major)  
**Migration Required:** Yes  
**Backward Compatible:** No

**Supported Formats:**
- ✅ JSON (with path filtering and nested object support)
- ✅ FormData (flat fields only)
- ✅ URL-encoded (flat key-value pairs)
- ✅ Query Parameters (flat parameters only)
- ❌ GraphQL - NOT supported (removed, use JSON instead)

**Mutation Policies:**
- ✅ `light` - 14 basic patterns
- ✅ `heavy` - 20 boundary patterns
- ✅ `format_validation` - 6 format patterns
- ❌ `security` - REMOVED (no longer available)

**Deletion Stages:**
- ✅ Single field deletion (finds required fields)
- ✅ Combinatorial deletion (tests pairs/triplets)
- ✅ Progressive deletion (binary search for minimal payload)

**Execution Limits:**
- Max requests: 5000
- Request timeout: 60 seconds
- Global timeout: 60 minutes
- Rate limiting: 1000ms delay (default)
- Memory depth limit: 50 levels

---

## [24.1.0] - 2026-01-27 (DEPRECATED)

### ⚠️ This version is DEPRECATED

**Deprecation Notice:**
- v24.1.0 is no longer supported
- EOL: January 25, 2026
- Migrate to v27.0.4 immediately

**Known Issues:**
- Security features present legal and compliance risks
- Attack payloads require opt-in (legal complexity)
- GraphQL support causes maintenance overhead
- SARIF export adds unnecessary complexity

### Added

**Legal & Licensing:**
- 📜 Comprehensive Contributor License Agreement (CLA) in CONTRIBUTING.md
- 📜 Detailed Trademark Policy (7 sections) in NOTICE
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

## Version History

| Version | Date | Type | Highlights |
|---------|------|------|------------|
| 27.0.4 | 2026-02-08 | Major | QA-focused rewrite, security features removed, new delete stages |
| 24.1.0 | 2026-01-27 | Legal | Comprehensive legal framework (DEPRECATED) |
| 24.0.0 | 2026-01-15 | Initial | First release (not recommended) |

---

## Upgrade Guide

### From v24.x to v27.0.4

See **Migration Guide** in the v27.0.4 release notes above.

### From v24.0.0 to v24.1.0 (DEPRECATED PATH)

**⚠️ This upgrade path is deprecated. Upgrade directly to v27.0.4 instead.**

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

**Timeline:**
- v24.0.0 deprecated: Immediately (use v27.0.4 instead)
- v24.0.0 EOL: 2026-01-25 (no further updates)
- v24.1.0 deprecated: Immediately (use v27.0.4 instead)
- v24.1.0 EOL: 2026-01-25 (no further updates)

---

## Compatibility

### Supported Platforms

- **Node.js:** 14.x, 16.x, 18.x, 20.x
- **Newman:** 5.3.x, 6.0.x
- **Postman:** 10.x, 11.x (desktop and web)

### Supported Body Formats (v27.0.4)

- ✅ JSON (application/json) - Full support with path filtering and nested objects
- ✅ FormData (multipart/form-data) - Flat fields only
- ✅ URL Encoded (application/x-www-form-urlencoded) - Flat key-value pairs only
- ✅ Query Parameters - Flat parameters only
- ❌ GraphQL - NOT supported (removed in v27.0.4, use JSON instead)

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
- Open-source testing community for inspiration
- Free Software Foundation for AGPL-3.0 license
- All contributors (see CONTRIBUTORS.md)

---

**For questions about this changelog:**
- Technical: GitHub Issues (https://github.com/apiars/apiars/issues)
- Legal/Commercial: apiars.dev@gmail.com

---

*Last Updated: February 8, 2026*
