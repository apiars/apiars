# apiars

**apiars** is an API Fuzzing & Security Engine for Postman / Newman,
designed for advanced API testing, security validation, and CI/CD integration.

---

## 🚀 Features

- **Multi-format Support:** JSON, GraphQL, FormData, URL-encoded
- **Comprehensive Fuzzing:** Light, Heavy, and Security policies
- **Memory-Safe:** Built-in bounds checking and rate limiting
- **CI/CD Ready:** SARIF export for seamless integration
- **Security Testing:** XSS, SQLi, path traversal, SSTI patterns
- **Response Analysis:** Anomaly detection and bug clustering

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/apiars/apiars.git
cd apiars

# Install dependencies
npm install
```

---

## 🔧 Usage

### Basic Usage

```bash
# Run with Newman
newman run your-collection.json

# Enable security tests (required for security fuzzing)
ENABLE_SECURITY_TESTS=true newman run your-collection.json
```

### Configuration

Configure fuzzing behavior in your collection:

```javascript
const CONFIG = {
  fuzzing: {
    usePolicies: ['light', 'heavy', 'security'],
    preset: 'standard'  // quick, standard, thorough, paranoid
  }
};
```

---

## ⚠️ Legal Notice

### Authorized Use Only

This tool is designed for **authorized security testing only**.

- Only test systems you own or have written permission to test
- Comply with all applicable laws in your jurisdiction
- Not for malicious purposes or unauthorized access

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

---

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [FAQ.md](FAQ.md) - Frequently asked questions
- [SECURITY.md](SECURITY.md) - Security policy
- [LICENSE](LICENSE) - Full AGPL-3.0 text

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Contributor License Agreement (CLA)
- Development guidelines
- Pull request process

---

## 🔒 Security

To report security vulnerabilities:

- **Email:** apiars.dev@gmail.com
- **DO NOT** open public GitHub issues for security bugs
- See [SECURITY.md](SECURITY.md) for full disclosure policy

---

## 👤 Author

**Mikhail A. Ivlev (Ивлев Михаил Александрович)**

- GitHub: [@maivlev](https://github.com/maivlev)
- Organization: [apiars](https://github.com/apiars)
- Email: apiars.dev@gmail.com

---

## 📋 Version

**Current Version:** 24.1.0  
**Release Date:** January 27, 2026

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## ⚖️ License Summary

- **Open Source:** AGPL-3.0
- **Commercial:** Available upon request
- **Trademark:** "apiars" is reserved

For detailed licensing information, see [LICENSING.md](LICENSING.md).

---

*Last Updated: January 27, 2026*
