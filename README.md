# apiars

**apiars** is an Exploratory API Fuzzing Engine for Postman and Newman,
designed for robustness testing, contract deviation detection, and edge case discovery in APIs.

🎯 **Focus**: QA-oriented exploratory testing, NOT security/penetration testing.

---

## 🚀 Features

- **Multi-format Support:** JSON (nested), FormData (flat), URL-encoded (flat), Query Parameters (flat)
- **Configurable Fuzzing:** Light, Heavy, and Format Validation policies
- **Advanced Field Deletion:**
  - Single field deletion (find required fields)
  - Combinatorial delete (test pairs/triplets of fields)
  - Progressive delete (find minimal viable payload)
- **JSON Path Filtering:** Target specific fields for focused testing
- **Memory-Safe:** Built-in bounds checking and rate limiting
- **Response Analysis:** Anomaly detection and bug clustering

### ⚠️ What This Is NOT

❌ NOT a security scanner  
❌ NOT a penetration testing tool  
❌ NOT a vulnerability scanner  
❌ NOT a CI/CD automation system  
❌ NOT a load/stress testing tool

✅ IS an exploratory API fuzzing engine for QA  
✅ IS focused on contract robustness testing  
✅ IS designed for edge case discovery

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/apiars/apiars.git
cd apiars

# Install dependencies (if any)
npm install
```

---

## 🔧 Usage

### Basic Usage

```bash
# Import the collection into Postman
# Add the engine script to your request's "Pre-request Script" tab
# Configure ENGINE_ENABLED = true at the top of the script
# Run the request

# Or use Newman
newman run your-collection.json
```

### Configuration

Configure fuzzing behavior at the top of the script:

```javascript
const ENGINE_ENABLED = true;  // Enable/disable the engine
const STAGE_CONFIG = {
    fuzzing: {
        enabled: true,
        usePolicies: ['light']  // Options: 'light', 'heavy', 'format_validation'
    }
};
```

### Advanced Features

**Path Filtering** (JSON format only):
```javascript
// Target specific fields for focused testing
const TARGET_PATHS_KEYS = [
    "user.email",
    "order.items[].price",
    "metadata.settings"
];
```

**Combinatorial Delete**:
```javascript
combinatorialDelete: {
    enabled: true,
    maxCombinations: 50,     // Maximum total combinations to test
    maxFieldsPerCombo: 3,    // Test pairs and triplets
    startWithPairs: true     // Start with 2-field combinations
}
```

**Progressive Delete**:
```javascript
progressiveDelete: {
    enabled: true,
    continueOnError: true,   // Continue after finding first required field
    logMinimalPayload: true   // Log minimal viable payload
}
```


---

## 🔧 Advanced Configuration (v27.14.6+)

### Bug Clustering

Control how bugs are grouped and displayed:

\`\`\`javascript
const CLUSTER_CONFIG = Object.freeze({
    includeCodes: [400, 422],           // HTTP codes to include in clusters
    excludeSuccessCodes: true,          // Exclude 2xx codes
    maxClustersToShow: 40,              // Maximum clusters in summary
    minOccurrencesToShow: 1,            // Minimum occurrences to show
    detailedCurlOutput: true,           // Generate CURL for each bug
    maxCurlsPerCluster: 3,              // Max CURL commands per cluster
    showMutationDetails: true           // Show mutation details
});
\`\`\`

### CURL Generation

Automatically generate curl commands for bug reproduction:

\`\`\`javascript
const CURL_CONFIG = Object.freeze({
    enabled: true,                      // Enable CURL generation
    maxBodyLength: 5000                 // Max body size in CURL (bytes)
});
\`\`\`

### Fuzzing Limits

Control test scope for large APIs:

\`\`\`javascript
const STAGE_CONFIG = {
    fuzzing: {
        enabled: true,
        usePolicies: ['light'],
        maxObjectsToFuzz: 20,           // Limit objects (0 = unlimited)
        maxArraysToFuzz: 20,            // Limit arrays (0 = unlimited)
        maxMutationsPerParam: 10        // Limit query param mutations (0 = unlimited)
    }
};
\`\`\`

These features help control test scope and improve bug reporting for large APIs.


---

## ⚠️ Responsible Use

This tool is designed for **authorized API testing only**.

- Test only systems you own or have written permission to test
- Comply with all applicable laws in your jurisdiction
- This is a QA tool, NOT a security/pentesting tool
- Do not use for unauthorized testing or malicious purposes

See [SECURITY.md](SECURITY.md) for full responsible use policy.

---

## 📄 Licensing

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

### What This Means

- ✅ **Free to use** for open-source projects
- ✅ **Free to modify** under AGPL-3.0 terms
- ⚠️ **Network use requires source disclosure** (AGPL Section 13)
- ❌ **Proprietary use requires commercial license**

### Trademark Notice

The name **"apiars"** is a trademark and not granted under this license.

### Commercial Licensing

Commercial or proprietary licensing is available for:
- Embedding in proprietary products
- SaaS deployment without source disclosure
- Custom licensing terms

**Contact:** apiars.dev@gmail.com

For detailed licensing information, see [LICENSING.md](LICENSING.md).

---

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history and migration guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [FAQ.md](FAQ.md) - Frequently asked questions
- [SECURITY.md](SECURITY.md) - Responsible use policy
- [LICENSE](LICENSE) - Full AGPL-3.0 text

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Contributor License Agreement (CLA)
- Development guidelines
- Pull request process

---

## 🔒 Security

To report security vulnerabilities or responsible use concerns:

- **Email:** apiars.dev@gmail.com
- **DO NOT** open public GitHub issues for security matters
- See [SECURITY.md](SECURITY.md) for full disclosure policy

---

## 💤 Author

**Mikhail A. Ivlev (Ивлев Михаил Александрович)**

- GitHub: [@maivlev](https://github.com/maivlev)
- Organization: [apiars](https://github.com/apiars)
- Email: apiars.dev@gmail.com

---

## 📋 Version

**Current Version:** 27.14.6  
**Release Date:** February 11, 2026  
**Previous Version:** 24.1.0 (deprecated)

⚠️ **Breaking Changes**: v27.14.6 removes all security testing features.  
See [CHANGELOG.md](CHANGELOG.md) for migration guide.

---

## ⚖️ License Summary

- **Open Source:** AGPL-3.0
- **Commercial:** Available upon request
- **Trademark:** "apiars" is reserved

For detailed licensing information, see [LICENSING.md](LICENSING.md).

---

*Last Updated: February 11, 2026*  
*Documentation Version: 2.1*
