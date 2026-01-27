# Frequently Asked Questions (FAQ)

## 📋 Licensing & General Usage

### Q1: Can I use apiars for free?

**Yes!** apiars is open-source software licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

You can use, modify, and distribute apiars without paying any fees, as long as you comply with the AGPL-3.0 terms.

---

### Q2: Can I use apiars in my company?

**Yes.** Internal use within your company is permitted under AGPL-3.0.

**Internal use means:**
- Testing your own APIs
- Security validation for your products
- CI/CD integration for your projects
- Employee training and development

**Important:** If you modify apiars and provide it to users over a network (e.g., as a hosted service), AGPL-3.0 source disclosure requirements apply. See Q4 below.

---

### Q3: Can I modify apiars?

**Yes!** You have complete freedom to modify apiars for your needs.

**You can:**
- Customize fuzzing policies
- Add new mutation patterns
- Integrate with your testing infrastructure
- Fix bugs or add features

**But remember:** Modified versions must also be licensed under AGPL-3.0 when distributed.

---

### Q4: Can I use apiars in a SaaS or hosted service?

**Yes, but with conditions.**

AGPL-3.0 Section 13 states:

> "If you modify this software and provide it to users over a network,
> you must make the complete corresponding source code available to those users."

**This means:**
- ✅ You CAN offer apiars-based services
- ⚠️ You MUST provide your modified source code to your service users
- ⚠️ You MUST license your modifications under AGPL-3.0

**Example:**
If you create "FuzzingAsAService.io" using modified apiars, your users must be able to download your full source code, including:
- Your web frontend
- Your backend API
- Your apiars modifications
- Your integration code

**Alternative:** Get a commercial license (see Q12).

---

### Q5: Can I embed apiars into a proprietary product?

**No, not under AGPL-3.0.**

Embedding apiars into closed-source or proprietary software requires a **commercial license**.

**Examples that require commercial licensing:**
- ❌ Shipping apiars as part of a proprietary security suite
- ❌ Including apiars in a closed-source testing platform
- ❌ Bundling apiars with commercial software

**Why?** AGPL-3.0 is a "copyleft" license that requires derivative works to also be open-source.

**Solution:** Contact us for commercial licensing options.

---

### Q6: Can I redistribute apiars?

**Yes, under AGPL-3.0 terms.**

**You can:**
- ✅ Include apiars in open-source distributions
- ✅ Package apiars for Linux distributions (apt, yum, brew)
- ✅ Bundle apiars with other AGPL/GPL software

**You cannot:**
- ❌ Redistribute under different license terms
- ❌ Remove or modify copyright notices
- ❌ Add additional restrictions beyond AGPL-3.0

**For non-AGPL redistribution:** Contact us for commercial licensing.

---

### Q7: What if I don't want to publish my modifications?

**Get a commercial license.**

Commercial licenses remove AGPL-3.0 obligations, allowing you to:
- Keep your modifications private
- Offer SaaS without source disclosure
- Embed in proprietary products
- Redistribute under custom terms

See Q12 for commercial licensing details.

---

## 🏢 Corporate & Enterprise Use

### Q8: Can AWS/Google Cloud/Microsoft Azure use apiars?

**Yes, but with important caveats.**

**Scenario A: They modify and offer as a service**
→ MUST disclose all modifications to service users (AGPL Section 13)
→ Unlikely for competitive reasons
→ They will probably purchase a commercial license

**Scenario B: They use unmodified version internally**
→ No source disclosure required
→ Perfectly fine under AGPL-3.0

**Scenario C: They purchase a commercial license**
→ Can modify and offer as a service without disclosure
→ This is the typical path for cloud providers

**Historical example:** MongoDB (AGPL) → AWS created DocumentDB (compatible API) → MongoDB changed to SSPL → AWS eventually licensed MongoDB

---

### Q9: Does my company's legal team need to review this?

**Yes, we encourage legal review!**

We've prepared documentation specifically for legal teams:
- **LEGAL_OVERVIEW.md** - One-page summary for lawyers
- **LICENSING.md** - Licensing policy overview
- This **FAQ.md** - Common questions

**Key points for legal review:**
- AGPL-3.0 is OSI-approved (widely recognized)
- Similar to GPL but with network use provisions
- Dual-licensing model is industry-standard
- Used by MongoDB, GitLab, Qt, and others

**If your legal team has questions:** Contact apiars.dev@gmail.com

---

### Q10: Can we get an exception to AGPL-3.0 terms?

**Not to AGPL-3.0 itself** (the license is standard and cannot be modified).

**However:** We offer **commercial licenses** with different terms.

**Commercial licenses can provide:**
- Proprietary use rights
- No source disclosure obligations
- Custom licensing terms
- Different warranty terms

Contact us to discuss your specific needs.

---

### Q11: Is AGPL-3.0 compatible with our existing licenses?

**It depends on your existing licenses.**

**Compatible with:**
- ✅ GPL-3.0 (can be combined)
- ✅ Apache-2.0 (one-way compatible: Apache → AGPL)
- ✅ Other AGPL-3.0 code
- ✅ Public domain code

**NOT directly compatible with:**
- ❌ MIT (without relicensing)
- ❌ BSD (without relicensing)
- ❌ Proprietary licenses
- ⚠️ GPL-2.0 (only GPL-2.0-or-later is compatible)

**Recommendation:** Consult with your legal team or contact us for clarification.

---

## 🏷️ Trademark & Naming

### Q12: Can I fork apiars?

**Yes!** Forking is explicitly permitted under AGPL-3.0.

**However:**
- ✅ You CAN create forks
- ✅ You CAN modify the code
- ✅ You CAN distribute your fork
- ❌ You CANNOT use the "apiars" name

**Naming requirements for forks:**
```
✅ GOOD:  "API Fuzzer (based on apiars)"
✅ GOOD:  "FuzzEngine (forked from apiars)"
✅ GOOD:  "SecurityTester (derived from apiars)"

❌ BAD:   "apiars-fork"
❌ BAD:   "apiars community edition"
❌ BAD:   "unofficial apiars"
```

**Why?** The name "apiars" is a trademark, separate from the software license.

See **NOTICE** file for complete trademark policy.

---

### Q13: Can I create "apiars-pro" or "apiars-enterprise"?

**No.** This violates trademark policy.

**The name "apiars" (and variations) cannot be used in:**
- Product names
- Service names
- Company names
- Domain names
- Package names (npm, PyPI, etc.)

**Alternatives:**
- "Pro API Fuzzer (based on apiars)"
- "Enterprise Security Testing Engine (powered by apiars)"

---

### Q14: Can I use "apiars" in my documentation?

**Yes, for factual references.**

**Permitted uses:**
- ✅ "Our tool integrates with apiars"
- ✅ "Compatible with apiars 24.x"
- ✅ "Alternative to apiars"
- ✅ "Based on apiars"

**NOT permitted:**
- ❌ "apiars Pro Edition" (implies product name)
- ❌ "Official apiars partner" (implies endorsement)
- ❌ "Certified by apiars" (false claim)

---

### Q15: Can I register a domain like "apiars-tools.com"?

**No, without permission.**

**Domain restrictions:**
- ❌ apiars.* (any TLD)
- ❌ *-apiars.* (prefix-apiars)
- ❌ apiars-*.* (apiars-suffix)

**Permitted alternatives:**
- ✅ api-fuzzing-tools.com
- ✅ security-testing-platform.com
- ✅ fuzzer-engine.com

**Why?** Trademark rights extend to domain names to prevent user confusion.

---

## 💰 Commercial Licensing

### Q16: How much does a commercial license cost?

**It depends on several factors:**

**Typical pricing tiers:**

**🏢 STARTUP** (~$5,000/year)
- Companies with <50 employees
- Internal use only
- Email support
- Annual renewal

**🏭 BUSINESS** (~$25,000/year)
- Companies with <500 employees
- SaaS deployment allowed
- Priority support
- Custom terms negotiable

**🌐 ENTERPRISE** (Custom quote)
- Unlimited employees
- White-label option
- Dedicated support
- On-premises deployment
- Custom SLA
- Multi-year contracts

**Factors affecting price:**
- Company size (revenue, employees)
- Use case (internal vs SaaS vs redistribution)
- Support requirements
- Trademark usage (if needed)

**Contact apiars.dev@gmail.com for a quote.**

---

### Q17: What does a commercial license include?

**Standard commercial license includes:**

**✅ Core Rights:**
- Proprietary use (closed-source modifications)
- No AGPL source disclosure obligation
- SaaS deployment without code sharing
- Redistribution under custom terms

**⚠️ Optional Add-ons (negotiable):**
- Technical support (SLA-based)
- Custom feature development
- Trademark usage rights
- Training and consulting
- Priority bug fixes

**NOT included by default:**
- Ownership transfer (copyright remains with author)
- Exclusivity (license is non-exclusive)
- Warranty (provided "AS IS")

---

### Q18: Can we negotiate license terms?

**Yes!** Commercial licenses are fully customizable.

**Common negotiation points:**
- Payment terms (annual vs perpetual)
- Territory restrictions
- Field-of-use limitations
- Sublicensing rights
- Support SLA
- Indemnification clauses
- Warranty terms

**Process:**
1. Contact us with your requirements
2. We'll send a proposal
3. Negotiate terms
4. Execute agreement

---

### Q19: Do you offer discounts?

**Yes, for:**

**🎓 Education & Research:**
- Universities and research institutions
- Non-profit organizations
- Open-source projects

**🚀 Startups:**
- Early-stage companies (<2 years old)
- Venture-backed startups
- Incubators/accelerators

**🌍 Geographic:**
- Emerging markets
- Developing countries

**📄 Multi-year:**
- 2-year contracts: 10% discount
- 3-year contracts: 20% discount

**Contact us to discuss eligibility.**

---

### Q20: What happens if we stop paying?

**Commercial licenses typically include:**

**During active subscription:**
- ✅ You can use the software under commercial terms
- ✅ You receive updates and support (if included)

**After subscription ends:**
- ⚠️ You revert to AGPL-3.0 terms
- ⚠️ You must comply with AGPL source disclosure
- ⚠️ Support and updates stop

**Perpetual licenses:**
- Some commercial licenses are "perpetual" (pay once, use forever)
- But support/updates typically require active subscription

**Grace periods:**
- Typically 30-day grace period for payment
- Notification before license termination

---

## 🔧 Technical Questions

### Q21: Is apiars production-ready?

**Current status: v24.1**

**✅ Production-ready features:**
- Multi-format support (JSON, GraphQL, FormData, URL-encoded)
- Comprehensive fuzzing policies
- Memory-safe implementation
- Rate limiting and timeout controls
- SARIF export for CI/CD
- Bug clustering and deduplication

**⚠️ Enterprise features (may require setup):**
- Custom integration with your CI/CD
- Advanced reporting customization
- Performance tuning for large-scale tests

**Maturity:**
- Core engine: Stable (v24.1)
- Documentation: Good
- Community: Growing

**For enterprise deployments:** Consider commercial license with support.

---

### Q22: Can I contribute code to apiars?

**Yes! We welcome contributions.**

**Process:**
1. Read **CONTRIBUTING.md**
2. Accept the Contributor License Agreement (CLA)
3. Fork the repository
4. Make your changes
5. Submit a pull request

**Important:** By contributing, you agree to:
- License your contribution under AGPL-3.0 (public)
- Grant us rights for commercial licensing (dual licensing)
- Provide representations about your code

**Why CLA?** It allows us to offer commercial licenses while keeping the project open-source.

---

### Q23: Who owns the code I contribute?

**You retain copyright ownership.**

**However:**
- Your code is licensed to the public under AGPL-3.0
- You grant us rights to use your code in commercial licenses
- You do NOT gain rights to the "apiars" trademark

**This is standard for dual-licensed projects** (similar to Apache Foundation, Google, Microsoft).

---

### Q24: Can I report security vulnerabilities?

**Yes, please do!**

**Process:**
1. **DO NOT** open a public GitHub issue for security bugs
2. Email: apiars.dev@gmail.com
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

**Our commitment:**
- Acknowledge within 48 hours
- Triage within 5 business days
- Fix critical issues within 30 days
- Credit you in release notes (with permission)

See **SECURITY.md** for full disclosure policy.

---

### Q25: Where can I get help?

**Community Support (Free):**
- 💬 GitHub Discussions: General questions, ideas
- 🐛 GitHub Issues: Bug reports, feature requests
- 📖 Documentation: README.md, docs/ folder

**Commercial Support (Paid):**
- 📧 Email support (SLA-based)
- 📞 Phone/video support
- 🎓 Training and workshops
- 🛠️ Custom development

**Self-Help Resources:**
- Examples: examples/ directory
- Test cases: test/ directory
- Documentation: https://github.com/apiars/apiars

---

## ⚖️ Legal Questions

### Q26: What law governs AGPL-3.0?

**AGPL-3.0 itself:**
- No specific jurisdiction (international license)
- Interpreted according to local copyright law
- Widely recognized globally

**Commercial licenses:**
- Typically governed by:
  - Delaware law (USA), or
  - Mutually agreed jurisdiction (EU, etc.)
- Specified in each agreement

---

### Q27: Can we use apiars if we're a competitor?

**Yes.** AGPL-3.0 does not discriminate.

**However:**
- ✅ You can use apiars under AGPL terms
- ✅ You can fork and modify (under AGPL)
- ❌ You cannot use "apiars" branding
- ⚠️ If you offer similar services, commercial license terms may vary

**We believe in open source** even for competitors.

**But:** Trademark protection prevents unfair competition through name confusion.

---

### Q28: What if AGPL-3.0 changes in the future?

**It won't.**

AGPL-3.0 is version 3 (2007) and is stable.

**License versioning:**
- apiars is licensed under "AGPL-3.0" (not "AGPL-3.0-or-later")
- This locks the license to version 3
- Future AGPL versions do NOT automatically apply

**If FSF releases AGPL-4.0:**
- We may choose to upgrade
- Existing users remain under AGPL-3.0
- Would be announced clearly

---

### Q29: Can we get an indemnification clause?

**Not in the AGPL-3.0 license** (which provides "AS IS" with no warranty).

**However:**
- Commercial licenses can include indemnification
- Typically limited to copyright infringement claims
- Subject to caps and exclusions
- Additional cost

**Example clause (commercial):**
```
Licensor shall defend and indemnify Licensee against third-party
claims alleging that the Software infringes copyright,
subject to a cap of [license fees paid] and standard exclusions.
```

---

### Q30: What if my question isn't answered here?

**Contact us:**

**General inquiries:**
- GitHub Discussions
- Email: apiars.dev@gmail.com

**Legal/licensing:**
- Email: apiars.dev@gmail.com
- Include: Company name, use case, specific question

**Commercial licensing:**
- Email: apiars.dev@gmail.com
- Include: Company size, intended use, budget (if any)

**Typical response time:** 2-5 business days

---

## 📚 Additional Resources

**Official Documentation:**
- LICENSE - Full AGPL-3.0 text
- NOTICE - Trademark and copyright notices
- LEGAL_OVERVIEW.md - One-page legal summary
- LICENSING.md - Licensing policy
- CONTRIBUTING.md - Contribution guidelines
- SECURITY.md - Security disclosure policy

**External Resources:**
- [AGPL-3.0 FAQ](https://www.gnu.org/licenses/gpl-faq.html)
- [OSI License Review](https://opensource.org/licenses/AGPL-3.0)
- [Dual Licensing Guide](https://en.wikipedia.org/wiki/Multi-licensing)

**Need clarification on AGPL-3.0?**
- Free Software Foundation: https://www.fsf.org
- Software Freedom Law Center: https://softwarefreedom.org

---

**Last Updated:** January 27, 2026  
**Version:** 1.0  
**Maintainer:** Mikhail A. Ivlev (Ивлев Михаил Александрович)

---

*This FAQ is provided for informational purposes and does not constitute legal advice.*
