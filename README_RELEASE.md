# apiars v27.14.6 - Release Package

**Release Date:** February 11, 2026  
**Package Type:** Complete documentation and engine files  
**Previous Version:** v27.0.4

---

## 📦 Contents of This Package

This ZIP archive contains all files for apiars v27.14.6 release:

### Core Files

| File | Status | Description |
|------|--------|-------------|
| **engine.js** | ✅ UPDATED | Main fuzzing engine (v27.14.6) |
| **README.md** | ✅ UPDATED | Project overview and configuration examples |
| **CHANGELOG.md** | ✅ UPDATED | Complete version history with v27.14.6 section |
| **FAQ.md** | ✅ UPDATED | FAQ with 40 questions (Q37-Q40 are new) |
| **SECURITY.md** | ✅ UPDATED | Responsible use policy with updated version table |

### Legal & Licensing (No Changes)

| File | Status | Description |
|------|--------|-------------|
| **NOTICE** | ⚪ UNCHANGED | Trademark and copyright notices |
| **CONTRIBUTING.md** | ⚪ UNCHANGED | Contributor License Agreement (CLA) |
| **LEGAL_OVERVIEW.md** | ⚪ UNCHANGED | Legal summary for compliance teams |
| **LICENSING.md** | ⚪ UNCHANGED | Dual licensing policy (AGPL-3.0 + Commercial) |

### This File

| File | Description |
|------|-------------|
| **README_RELEASE.md** | This file - installation and deployment instructions |

---

## 🚀 Quick Start

### Option 1: Update Existing Repository

```bash
# 1. Backup your current files
mkdir backup-v27.0.4
cp engine.js README.md CHANGELOG.md FAQ.md SECURITY.md backup-v27.0.4/

# 2. Extract this ZIP and copy files
unzip apiars-v27.14.6-release.zip
cd apiars-v27.14.6-release
cp * /path/to/your/apiars/repo/

# 3. Verify engine version
head -n 1 /path/to/your/apiars/repo/engine.js
# Should show: const ENGINE_VERSION = '27.14.6';

# 4. Commit changes
cd /path/to/your/apiars/repo
git add .
git commit -m "Update to v27.14.6"
git tag -a v27.14.6 -m "Release v27.14.6 - Bug clustering, CURL generation, fuzzing limits"
git push origin main
git push origin v27.14.6
```

### Option 2: Fresh Installation

```bash
# 1. Create new repository directory
mkdir apiars
cd apiars

# 2. Extract ZIP contents
unzip /path/to/apiars-v27.14.6-release.zip
mv apiars-v27.14.6-release/* .
rmdir apiars-v27.14.6-release

# 3. Initialize git (if needed)
git init
git add .
git commit -m "Initial commit - apiars v27.14.6"

# 4. Add LICENSE file (create separate AGPL-3.0 license file)
wget https://www.gnu.org/licenses/agpl-3.0.txt -O LICENSE
git add LICENSE
git commit -m "Add AGPL-3.0 license"
```

### Option 3: Use in Postman/Newman Directly

```bash
# Just extract and use engine.js
unzip apiars-v27.14.6-release.zip
# Copy engine.js to your Postman collection's Pre-request Script
# Configure and enable: ENGINE_ENABLED = true
```

---

## 📋 What's New in v27.14.6

### Major Features

✅ **Bug Clustering Configuration (CLUSTER_CONFIG)**
- Customize HTTP codes for clustering
- Control output verbosity
- Generate CURL for each bug

✅ **CURL Command Generation (CURL_CONFIG + buildCurl())**
- Automatic CURL generation for bug reproduction
- Shell-safe escaping
- Configurable body size limits

✅ **Fuzzing Limits**
- `maxObjectsToFuzz: 20` - limit objects
- `maxArraysToFuzz: 20` - limit arrays  
- `maxMutationsPerParam: 10` - limit query params

✅ **Improved Logging**
- 98 instances of `console.log()` → `console.info()`
- Better semantic logging

### Minor Improvements

- Parametrized `minimalPayloadSizeThreshold` (progressive delete)
- Added `[null]` mutation in heavy policy
- Enhanced documentation comments
- License header moved from engine.js to LICENSE file

---

## 🔄 Migration from v27.0.4

**✅ Fully backward compatible - no breaking changes!**

### Required Steps

1. **Replace engine.js**
   - Backup old version
   - Copy new engine.js from this package

2. **Verify version**
   ```javascript
   const ENGINE_VERSION = '27.14.6';  // First line of engine.js
   ```

### Optional Steps

3. **Configure new features** (see Configuration Examples below)

4. **Update documentation links** (if you reference specific line numbers)

5. **Test in your environment**
   - Run existing tests
   - Verify new configurations work as expected

**That's it!** All new features are optional. Your existing configuration will work without modification.

---

## ⚙️ Configuration Examples

### Enable Bug Clustering

Add to engine.js (after other constants):

```javascript
const CLUSTER_CONFIG = Object.freeze({
    includeCodes: [400, 422, 404, 409],  // Your relevant error codes
    excludeSuccessCodes: true,
    maxClustersToShow: 40,
    minOccurrencesToShow: 1,
    detailedCurlOutput: true,
    maxCurlsPerCluster: 3,
    showMutationDetails: true
});
```

### Enable CURL Generation

```javascript
const CURL_CONFIG = Object.freeze({
    enabled: true,
    maxBodyLength: 5000  // Adjust for your API payload sizes
});
```

### Set Fuzzing Limits (for large APIs)

```javascript
const STAGE_CONFIG = {
    // ... existing config ...
    fuzzing: {
        enabled: true,
        usePolicies: ['light'],
        typeAwareness: true,
        fuzzObjects: true,
        fuzzArrays: true,
        maxObjectsToFuzz: 20,      // Limit to 20 objects
        maxArraysToFuzz: 20,       // Limit to 20 arrays
        maxMutationsPerParam: 10   // Limit query param mutations
    }
};
```

### Adjust Minimal Payload Logging

```javascript
const STAGE_CONFIG = {
    // ... existing config ...
    progressiveDelete: {
        enabled: true,
        continueOnError: true,
        logMinimalPayload: true,
        minimalPayloadSizeThreshold: 2000  // Increase from 1000 to 2000 bytes
    }
};
```

---

## 📊 File Comparison

### Updated Files

| File | v27.0.4 Size | v27.14.6 Size | Change | Key Changes |
|------|--------------|---------------|--------|-------------|
| engine.js | 3464 lines | 3759 lines | +295 | New configs, functions, logging |
| CHANGELOG.md | ~600 lines | ~650 lines | +50 | v27.14.6 section added |
| README.md | ~350 lines | ~400 lines | +50 | Version, config examples |
| FAQ.md | ~866 lines | ~986 lines | +120 | Q37-Q40 added |
| SECURITY.md | ~280 lines | ~280 lines | ±0 | Version table updated |

### Unchanged Files

- NOTICE
- CONTRIBUTING.md  
- LEGAL_OVERVIEW.md
- LICENSING.md

---

## ✅ Verification Checklist

Before deploying to production:

- [ ] engine.js version is 27.14.6 (check first line)
- [ ] CHANGELOG.md includes v27.14.6 section
- [ ] README.md version is 27.14.6
- [ ] FAQ.md includes Q37-Q40
- [ ] SECURITY.md shows 27.14.x as current
- [ ] All files extracted successfully
- [ ] LICENSE file exists (AGPL-3.0)
- [ ] Existing tests pass
- [ ] New configurations work (if enabled)

---

## 🐛 Troubleshooting

### "Version still shows 27.0.4"

**Solution:** Ensure you copied the correct engine.js from this package.

```bash
head -n 1 engine.js
# Should output: const ENGINE_VERSION = '27.14.6';
```

### "CLUSTER_CONFIG is not defined"

**Solution:** This is normal if you haven't added CLUSTER_CONFIG to engine.js. It's optional. Add the configuration block if you want to use clustering features.

### "Tests are running slower"

**Solution:** You may have set fuzzing limits too low. Increase `maxObjectsToFuzz` and `maxArraysToFuzz` or set to 0 for unlimited.

### "CURL commands not showing"

**Solution:** Check that:
1. `CURL_CONFIG.enabled = true`
2. `CLUSTER_CONFIG.detailedCurlOutput = true`
3. Bug clusters exist (errors occurred during testing)

---

## 📞 Support

### Documentation

- **Full Changelog:** See CHANGELOG.md for complete details
- **FAQ:** See FAQ.md for common questions (Q37-Q40 for v27.14.6)
- **Configuration:** See README.md for all config options

### Getting Help

- **GitHub Issues:** https://github.com/apiars/apiars/issues
- **Email:** apiars.dev@gmail.com
- **Discussions:** https://github.com/apiars/apiars/discussions

### Reporting Bugs

1. Check FAQ.md first (40 questions)
2. Search existing GitHub issues
3. Create new issue with:
   - Version (27.14.6)
   - Steps to reproduce
   - Expected vs actual behavior
   - Configuration (if relevant)

---

## 📜 License

**apiars** is dual-licensed:

- **Open Source:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Commercial:** Available upon request

See LICENSE file for AGPL-3.0 full text.  
See LICENSING.md for licensing policy.

**Trademark:** "apiars" is a trademark - see NOTICE file.

---

## 🙏 Acknowledgments

**Special thanks to:**
- Community members who requested CURL generation
- Users who provided feedback on bug clustering
- Testers who validated this release

---

## 📚 Additional Resources

### Official Links

- **Repository:** https://github.com/apiars/apiars
- **Releases:** https://github.com/apiars/apiars/releases
- **Documentation:** https://github.com/apiars/apiars#readme

### Related Tools

- **Postman:** https://www.postman.com
- **Newman:** https://github.com/postmanlabs/newman

### Previous Versions

- **v27.0.4:** https://github.com/apiars/apiars/releases/tag/v27.0.4
- **v24.1.0:** Deprecated (do not use)

---

## 🔐 Security

To report security issues:

- **DO NOT** open public GitHub issues
- **Email:** apiars.dev@gmail.com with [SECURITY] in subject
- **Response time:** 48 hours acknowledgment

See SECURITY.md for full disclosure policy.

---

**Release Package Version:** 1.0  
**Generated:** February 11, 2026  
**Package Maintainer:** Mikhail A. Ivlev (Ивлев Михаил Александрович)

---

*For questions about this release package, contact apiars.dev@gmail.com*
