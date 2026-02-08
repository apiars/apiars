/*!
 * apiars - Exploratory API Fuzzing Engine
 * Version: 27.0.4
 * Release Date: February 8, 2026
 * 
 * Copyright (c) 2026 Mikhail A. Ivlev (Ивлев Михаил Александрович)
 * 
 * This file is part of apiars.
 * 
 * apiars is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * apiars is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with apiars. If not, see <https://www.gnu.org/licenses/>.
 * 
 * ============================================================================
 * IMPORTANT: AGPL-3.0 Section 13 - Network Use
 * ============================================================================
 * 
 * If you run a modified version of this software as a service over a network,
 * you MUST offer users of that service access to the Corresponding Source
 * of your modified version.
 * 
 * This includes:
 * - Providing complete source code to service users
 * - Making your modifications available under AGPL-3.0
 * - Including installation and build instructions
 * 
 * For commercial licensing that removes AGPL obligations:
 * Contact: apiars.dev@gmail.com
 * 
 * ============================================================================
 * Trademark Notice
 * ============================================================================
 * 
 * The name "apiars" is a trademark of Mikhail A. Ivlev.
 * Trademark rights are NOT granted under the AGPL-3.0 license.
 * 
 * See NOTICE file for complete trademark policy.
 * 
 * ============================================================================
 * Project Information
 * ============================================================================
 * 
 * Repository: https://github.com/apiars/apiars
 * Documentation: https://github.com/apiars/apiars#readme
 * Issues: https://github.com/apiars/apiars/issues
 * License: AGPL-3.0 (see LICENSE file)
 * 
 * ============================================================================
 * What This Tool IS and IS NOT
 * ============================================================================
 * 
 * ✅ IS:
 * - Exploratory API Fuzzing Engine for QA
 * - Robustness testing framework
 * - Contract deviation detector
 * - Edge case discovery tool
 * 
 * ❌ IS NOT:
 * - Security scanner
 * - Penetration testing tool
 * - Vulnerability scanner
 * - Hacking or exploitation framework
 * - CI/CD automation system
 * - Load/stress testing tool
 * 
 * For responsible use policy, see SECURITY.md
 * 
 * ============================================================================
 */
const ENGINE_VERSION = '27.0.4';
const ENGINE_ENABLED = false;
const SHOW_BANNER = true;  // Show startup banner with instructions and config (true/false)
const ENABLE_MUTATION_LOGGING = true;  // ENHANCED: Show JSON structure map and detailed mutation logging
const REQUEST_DELAY_MS = 1000;
const REQUEST_TIMEOUT_MS = 60000;  // 60 seconds
const GLOBAL_TIMEOUT_MS = 3600000;  // 60 minutes
const MAX_TOTAL_REQUESTS = 5000;
const TARGET_PATHS_KEYS = []; // JSON FUZZING ONLY SUPPORTED - targetPathsKeys: ["STEP_1.0.nested_1"]
const ENABLE_JSON_COMMENTS = true;  // Parse and strip JSON comments (// and /* */) from request body

const STAGE_CONFIG = Object.freeze({
    baseline: Object.freeze({
        enabled: true,
        repeatCount: 3  // Number of identical requests to verify stability
    }),

    fuzzing: Object.freeze({
        enabled: true,
        usePolicies: ['light'],  // Which mutation policies to use - ['light', 'heavy', 'format_validation']
        typeAwareness: true,     // Respect field types when fuzzing
        fuzzObjects: true,       // Mutate object fields
        fuzzArrays: true         // Mutate array fields
    }),

    singleDelete: Object.freeze({
        enabled: true
    }),

    combinatorialDelete: Object.freeze({
        enabled: true,
        maxCombinations: 50,     // Maximum total combinations to test
        maxFieldsPerCombo: 3,    // Maximum fields per combination
        startWithPairs: true     // Start with 2-field combinations
    }),

    progressiveDelete: Object.freeze({
        enabled: true,
        continueOnError: true,   // Stop at first required field? false = stop, true = continue
        logMinimalPayload: true   // Log minimal payload to console (only if < 1000 bytes)
    })
});

const MUTATION_POLICIES = Object.freeze({
    // ========================================================================
    // 🟢 LIGHT - Basic Contract Testing (14 values)
    // ========================================================================
    // USE CASE: Always enabled by default (usePolicies: ['light'])
    // EXECUTION TIME: ~1-5 minutes for typical API
    // COVERAGE: 95% of "rookie mistakes" in contracts
    // ========================================================================
    light: Object.freeze([
        // --- Type Confusion ---
        null,           // 🔥🔥🔥 Nullable field handling, null coercion, missing null checks (→ 400/500)
                        // ALSO COVERS: undefined→null, NaN→null, Infinity→null in JSON
        true,           // 🔥🔥🔥 Type coercion: boolean→number (true==1), boolean→string ("true")
        false,          // 🔥🔥🔥 Falsy value handling: false vs 0 vs "" vs null distinction
        
        // --- Numeric Boundaries ---
        0,              // 🔥🔥🔥 Zero boundary: division by zero, falsy value, ID=0 edge case
        1,              // 🔥🔥 Minimum positive value, true coercion (1==true), off-by-one baseline
        -1,             // 🔥🔥🔥 Negative index, error code convention (-1 = "not found"), enum sentinel
        
        // --- String Edges ---
        "",             // 🔥🔥🔥 Empty string ≠ null: required field with "" value, minLength bypass
        " ",            // 🔥🔥🔥 Whitespace-only string: missing trim(), minLength after trim check
        "\n",           // 🔥🔥 Newline character: multiline field validation, JSON escaping check
        "\t",           // 🔥 Tab character: whitespace edge case, trim() implementation check
        
        // --- Structural Confusion ---
        [],             // 🔥🔥🔥 Empty array vs scalar: type mismatch, array when primitive expected
        {},             // 🔥🔥🔥 Empty object vs primitive: type mismatch, object when scalar expected
        
        // --- Critical Number Boundaries ---
        2147483647,     // 🔥🔥🔥 Int32.MAX: SQL INTEGER limit, Java int overflow, ID boundary
        9007199254740991 // 🔥🔥🔥 Number.MAX_SAFE_INTEGER: JavaScript precision limit, use string for larger IDs
    ]),

    // ========================================================================
    // 🟡 HEAVY - Boundary Testing + Encoding (20 values)
    // ========================================================================
    // USE CASE: Enable manually for deep testing
    // EXECUTION TIME: +10-20 minutes beyond LIGHT
    // COVERAGE: Overflows, boundaries, encoding issues
    // ========================================================================
    heavy: Object.freeze([
        // --- Length Boundaries (safe for Postman UI) ---
        "A".repeat(255),    // 🔥🔥🔥 VARCHAR(255) boundary: most common DB string limit
        "A".repeat(256),    // 🔥🔥🔥 Off-by-one: VARCHAR(255) overflow check
        "A".repeat(1000),   // 🔥🔥 Medium length: HTTP header limit (~8KB), JSON parser stress
        "A".repeat(2000),   // 🔥 Long string: large payload handling (2KB, safe for UI)
        
        // --- Numeric Extremes ---
        -2147483648,        // 🔥🔥🔥 Int32.MIN: SQL INTEGER lower boundary, negative ID edge case
        2147483648,         // 🔥🔥 Int32.MAX + 1: overflow detection, should fail validation
        
        // --- String Masquerading (strings pretending to be types) ---
        "null",         // 🔥🔥🔥 String "null" vs null: parsing ambiguity, type coercion check
        "undefined",    // 🔥🔥 String "undefined" vs undefined: JavaScript API confusion, query param handling
        "true",         // 🔥🔥 String "true" vs boolean true: query param parsing, type conversion
        "false",        // 🔥🔥 String "false" vs boolean false: falsy string handling, bool coercion
        "0",            // 🔥🔥🔥 String "0" vs number 0: loose equality (==) vs strict (===)
        "NaN",          // 🔥🔥 String "NaN" vs NaN: parsing check, Number("NaN") = NaN
        "Infinity",     // 🔥 String "Infinity" vs Infinity: edge case in number parsing
        "1e10",         // 🔥 Scientific notation string: parseFloat() vs parseInt(), number format handling
        "-0",           // 🔥 Negative zero string: edge case for number parsing, sign handling
        
        // --- Real UTF-8 Characters (visible in Postman console) ---
        "测试",         // 🔥🔥 Multibyte chars: 3-byte UTF-8, database encoding (UTF8 vs UTF8MB4)
        "مرحبا",        // 🔥🔥 RTL script: Right-to-Left rendering, combining characters, bidi handling
        "🔥💩",          // 🔥🔥 Emoji: 4-byte UTF-8, JavaScript surrogate pairs, string length calculation
        
        // --- Special Characters ---
        "\r\n",         // 🔥 Windows line ending (CRLF): multiline field handling, line break normalization
        
        // --- Structural Mutations (CRITICAL for VALUE fuzzing!) ---
        [null]          // 🔥🔥 Array with null: needed when fuzzArrays=false for VALUE mutation
    ]),

    // ========================================================================
    // 🟣 FORMAT_VALIDATION - Format & Data Quality Checks (6 values)
    // ========================================================================
    // USE CASE: Optional validation-focused testing
    // PURPOSE: Check format validation (dates, emails, UUIDs, etc.)
    // COVERAGE: Format validators, data quality checks
    // ========================================================================
    format_validation: Object.freeze([
        // --- Date/Time Format Validation ---
        "2025-13-45",           // 🔥🔥🔥 Invalid date: month=13, day=45 (tests date parser)
        "0000-01-01",           // 🔥🔥 Zero date: edge case for date validators
        
        // --- Email Format Validation ---
        "not-an-email@",        // 🔥🔥🔥 Malformed email: missing domain part
        "user@",                // 🔥🔥 Incomplete email: no domain
        
        // --- UUID Format Validation ---
        "00000000-0000-0000-0000-000000000000", // 🔥🔥🔥 Nil UUID: valid format, semantically empty
        
        // --- IP Address Confusion ---
        "1.2.3.4"               // 🔥🔥 Looks like IP: tests if validator accepts non-IP field
    ]),

    // ========================================================================
    // 🔵 OBJECT MUTATIONS (for fuzzObjects: true)
    // ========================================================================
    // Applied when mutating object-type fields during VALUE fuzzing stage
    // Tests object type validation, nullable objects, schema compliance
    // ========================================================================
    objectMutations: Object.freeze([
        {},             // 🔥🔥🔥 Empty object: tests nullable object, required property check, schema validation with no properties
        null,           // 🔥🔥🔥 Object replaced with null: tests nullable object fields, type validation (object vs null)
        {"key": "value"}, // 🔥 Unexpected structure: tests schema validation, unknown property handling, additionalProperties check
        {"a": null}    // 🔥🔥 Object with null property: tests nested null handling, required nested field validation
    ]),

    // ========================================================================
    // 🔵 ARRAY MUTATIONS (for fuzzArrays: true)
    // ========================================================================
    // Applied when mutating array-type fields during VALUE fuzzing stage
    // Tests array type validation, nullable arrays, element validation
    // ========================================================================
    arrayMutations: Object.freeze([
        [],             // 🔥🔥🔥 Empty array: tests minItems validation, array vs null distinction, empty collection handling
        null,           // 🔥🔥🔥 Array replaced with null: tests nullable array fields, type validation (array vs null)
        [null],         // 🔥🔥 Array with null element: tests null item handling, array element validation, nullable array items
        [{}],           // 🔥 Array with empty object: tests array of objects validation, empty object in array, schema validation of array items
        [""],           // 🔥 Array with empty string: tests string array validation, empty string element, minLength on array items
        [0]            // 🔥 Array with zero: tests numeric array validation, zero vs null distinction, minimum value in arrays
    ]),

    // ========================================================================
    // 🌐 TEST VALUES - Query Params / URL Encoded (24 values) - COMPLETE COMMENTS
    // ========================================================================
    // ⚠️  AUTO-USED for queryparams and urlencoded formats (see line ~2158)
    // USE CASE: Specialized values for GET parameters (dates, formats, etc.)
    // COVERAGE: Query-string specific edge cases
    // NOTE: Engine automatically switches to these values for URL-encoded contexts
    // ========================================================================
    testValues: Object.freeze([
        // --- Numeric Boundaries ---
        0,                   // 🔥🔥🔥 Zero in query param: tests division by zero, falsy value, ID=0 edge case, ?page=0
        -1,                  // 🔥🔥🔥 Negative one: tests negative ID, error code (-1 sentinel), negative pagination offset ?offset=-1
        -100,                // 🔥🔥 Negative number: tests negative filter values, negative limit ?limit=-100, signed integer handling
        2147483647,          // 🔥🔥🔥 Int32.MAX: SQL INTEGER limit, Java int overflow, ID boundary in query string
        -2147483648,         // 🔥🔥🔥 Int32.MIN: SQL INTEGER lower boundary, negative ID edge case, minimum signed 32-bit value
        9007199254740991,    // 🔥🔥🔥 Number.MAX_SAFE_INTEGER: JavaScript precision limit, use string for larger IDs in URLs
        
        // --- String Masquerading (strings pretending to be types) ---
        "null",              // 🔥🔥🔥 String 'null' in query param: tests parsing of ?field=null vs actual null, type coercion
        "undefined",         // 🔥🔥 String 'undefined' in query param: tests ?field=undefined handling, JavaScript undefined confusion
        "NaN",               // 🔥🔥 String 'NaN' in query param: tests parsing, Number('NaN')=NaN confusion, invalid number handling
        "Infinity",          // 🔥 String 'Infinity': tests Number('Infinity')=Infinity in query params, infinite value parsing
        "-Infinity",         // 🔥 String '-Infinity': tests negative infinity parsing in query parameters, unbounded values
        "true",              // 🔥🔥 String 'true': tests boolean parsing in query params (?enabled=true), string vs boolean true
        "false",             // 🔥🔥 String 'false': tests boolean false parsing (note: 'false' is truthy!), ?active=false
        "0",                 // 🔥🔥🔥 String '0': tests zero string vs number 0 in query parameters, ?count=0 vs ?count="0"
        "''",                // 🔥 Two single quotes: tests empty string literal in query params (?field=''), quote handling
        '""',                // 🔥 Two double quotes: tests empty string literal (?field=""), double quote in URL encoding
        "0x0",               // 🔥 Hexadecimal notation: tests hex parsing parseInt('0x0')=0, alternative number format
        "1e10",              // 🔥 Scientific notation string: tests parseFloat('1e10')=10000000000, E-notation in query params
        
        // --- Date/Time Edges (critical for query params!) ---
        "1970-01-01T00:00:00Z", // 🔥🔥🔥 Unix epoch: timestamp=0, minimum date boundary, ?since=1970-01-01T00:00:00Z
        "2038-01-19T03:14:07Z", // 🔥🔥 Y2K38 problem: 32-bit timestamp overflow (2147483647 seconds), ?until=2038-01-19T03:14:07Z
        "9999-12-31",           // 🔥 Max date boundary: maximum reasonable date, far future date, ?expiry=9999-12-31
        "0000-01-01",           // 🔥 Zero date: year 0 edge case, minimum date, ?birthdate=0000-01-01
        
        // --- Format Confusion ---
        "1.2.3.4",       // 🔥 Looks like IP address: tests IP format confusion, ?server=1.2.3.4 for non-IP field
        "not-a-number"   // 🔥 Text instead of number: tests type validation, ?limit=not-a-number, string in numeric field
    ])
});

const FEATURES = Object.freeze({
    postmanTest: true,
});
const MEMORY_LIMITS = Object.freeze({
    maxCollectNodesSize: 5000,
    maxCollectDepth: 50,
    maxWarningsSize: 100,
    maxBugClustersSize: 500,
    maxResultsPerStage: 1000,
    maxTotalResults: 4000
});
const ADVANCED_CONFIG = Object.freeze({
    debug: Object.freeze({
        enabled: false
    }),
    logDetailedSteps: false,
    failFast: Object.freeze({
        enabled: true,
        maxServiceErrors: 10,      // Threshold: 5xx errors in last 20 requests
        maxRateLimitErrors: 5      // Threshold: 429 errors in last 20 requests
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
    strictVariables: true,
    
    targetPathsKeys: TARGET_PATHS_KEYS,
    
    targetPathsPrefixMatch: false
});

// ============================================================================
// 📋 STAGE METADATA - Single Source of Truth
// ============================================================================
// Ensures stage names in banner, console output, and code are always synchronized
// Prevents issues like "VALUE MUTATION" in banner but "fuzzing" in code
// Lazy initialization: getDynamicInfo functions are called only when banner is generated
// This is safe because they're called after all configs are initialized
// ============================================================================

const STAGE_METADATA = Object.freeze({
    baseline: Object.freeze({
        emoji: '1️⃣',
        name: 'BASELINE',
        shortDesc: 'API stability check',
        details: Object.freeze([
            'Verifies API returns consistent responses',
            'Stops only on: network errors (0), auth errors (401/403)',
            'Continues on: unstable APIs, validation errors, 5xx (v26.0.0)'
        ]),
        getDynamicInfo: function() {
            // Lazy access to STAGE_CONFIG - safe because called after initialization
            return `(${STAGE_CONFIG.baseline.repeatCount} identical requests)`;
        }
    }),
    
    fuzzing: Object.freeze({
        emoji: '2️⃣',
        name: 'FUZZING',
        shortDesc: 'Field value substitution',
        details: Object.freeze([
            'Each field replaced with mutation values',
            'Responses analyzed for errors'
        ])
    }),
    
    singleDelete: Object.freeze({
        emoji: '3️⃣',
        name: 'SINGLE DELETE',
        shortDesc: 'Field deletion one by one',
        details: Object.freeze([
            'Each field deleted individually',
            'Identifies required fields'
        ])
    }),
    
    combinatorialDelete: Object.freeze({
        emoji: '4️⃣',
        name: 'COMBINATORIAL DELETE',
        shortDesc: 'Combined field deletion',
        details: Object.freeze([
            'Tests field interactions (pairwise testing)'
        ]),
        getDynamicInfo: function() {
            // Lazy access to STAGE_CONFIG - safe because called after initialization
            const cfg = STAGE_CONFIG.combinatorialDelete;
            const start = cfg.startWithPairs ? 2 : 1;
            return `(up to ${cfg.maxCombinations} combos, ${start}-${cfg.maxFieldsPerCombo} fields each)`;
        }
    }),
    
    progressiveDelete: Object.freeze({
        emoji: '5️⃣',
        name: 'PROGRESSIVE DELETE',
        shortDesc: 'Cumulative field removal',
        details: Object.freeze([
            'Deletes fields ONE-BY-ONE, accumulating deletions',
            'Finds minimal working payload'
        ])
    })
});

// ============================================================================
// VALIDATION - Check all stages have metadata
// ============================================================================
(() => {
    const missingMeta = Object.keys(STAGE_CONFIG).filter(key => !STAGE_METADATA[key]);
    if (missingMeta.length > 0) {
        console.warn(`⚠️  STAGE_METADATA missing for: ${missingMeta.join(', ')}`);
    }
})();

// ============================================================================
// CUSTOM ERROR CLASS FOR STAGE ABORTION  
// ============================================================================

class StageAbortError extends Error {
    constructor(message) {
        super(message);
        this.name = 'StageAbortError';
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const Helpers = {
    shouldAbort: function(stats) {
        return stats && stats.abortReasons && stats.abortReasons.length > 0;
    },

    secureLog: function(message, level) {
        level = level || 'info';
        const logFn = console[level] || console.log;
        logFn(message);
    }
};


// ============================================================================
// PATH FILTER UTILITY - Filter nodes by targetPathsKeys
// ============================================================================

const PathFilter = {
    isAllowed: function(nodePath, config) {
        const targetPaths = config.targetPathsKeys;
        const prefixMatch = config.targetPathsPrefixMatch;
        
        // If target paths are not specified - allow all nodes
        if (!targetPaths || targetPaths.length === 0) {
            return true;
        }
        
        // Convert path to dot-separated string
        const pathStr = nodePath.join('.');
        
        // Prefix or exact match
        if (prefixMatch) {
            return targetPaths.some(target => pathStr.startsWith(target));
        } else {
            return targetPaths.includes(pathStr);
        }
    },

    filterNodes: function(nodes, config) {
        const targetPaths = config.targetPathsKeys;
        
        // Fast path: if filtering is not needed
        if (!targetPaths || targetPaths.length === 0) {
            return nodes;
        }
        
        // Optimization: use Set for large arrays
        let pathSet = null;
        if (!config.targetPathsPrefixMatch && targetPaths.length > 100) {
            pathSet = new Set(targetPaths);
        }
        
        return nodes.filter(node => {
            if (pathSet) {
                // Fast check via Set
                return pathSet.has(node.path.join('.'));
            } else {
                // Standard check
                return this.isAllowed(node.path, config);
            }
        });
    },

    logFilterStats: function(totalNodes, filteredNodes, config) {
        if (!config.debug || !config.debug.enabled) {
            return;
        }
        
        const targetPaths = config.targetPathsKeys || [];
        const difference = totalNodes - filteredNodes;
        
        console.log(`[PathFilter] Total nodes collected: ${totalNodes}`);
        console.log(`[PathFilter] After filtering: ${filteredNodes}`);
        console.log(`[PathFilter] Excluded: ${difference} nodes`);
        
        if (config.debug.verbosity === 'high' && targetPaths.length > 0) {
            console.log(`[PathFilter] Target paths (${targetPaths.length}):`);
            targetPaths.slice(0, 10).forEach(p => console.log(`  - ${p}`));
            if (targetPaths.length > 10) {
                console.log(`  ... and ${targetPaths.length - 10} more`);
            }
        }
        
        if (filteredNodes === 0 && targetPaths.length > 0) {
            console.warn(`⚠️  [PathFilter] No nodes matched target paths! Check your configuration.`);
        }
    },

    validateConfig: function(config) {
        const result = { valid: true, warnings: [] };
        const targetPaths = config.targetPathsKeys;
        
        if (!targetPaths) {
            return result;
        }
        
        if (!Array.isArray(targetPaths)) {
            result.valid = false;
            result.warnings.push('targetPathsKeys must be an array');
            return result;
        }
        
        for (let i = 0; i < targetPaths.length; i++) {
            const path = targetPaths[i];
            
            if (typeof path !== 'string') {
                result.warnings.push(`Path at index ${i} is not a string: ${path}`);
                continue;
            }
            
            if (path.trim() === '') {
                result.warnings.push(`Path at index ${i} is empty`);
                continue;
            }
            
            if (path.includes('..')) {
                result.warnings.push(`Path '${path}' contains suspicious pattern '..'`);
            }
            
            if (path.startsWith('.') || path.endsWith('.')) {
                result.warnings.push(`Path '${path}' has leading or trailing dot`);
            }
        }
        
        return result;
    }
};

// ============================================================================
// UNIFIED STAGE EXECUTOR
// ============================================================================

const executeStageWithHandler = async function(stageName, stageFunction, args, context, config, stats, BugClustering, PostmanAdapter) {
    const hasErrorHandler = typeof ErrorHandler !== 'undefined';

    try {
        let result;

        if (hasErrorHandler) {
            const wrapped = await ErrorHandler.executeStage(
                stageName,
                async () => await stageFunction.apply(MutationStages, args),  // Fixed: use MutationStages as context
                context,
                config
            );
            result = wrapped && wrapped.success ? wrapped.result : null;
        } else {
            result = await stageFunction.apply(MutationStages, args);  // Fixed: use MutationStages as context
        }

        if (Helpers.shouldAbort(stats)) {
            throw new StageAbortError(`Stage ${stageName} aborted`);
        }

        return result;

    } catch (error) {
        if (error instanceof StageAbortError) {
            throw error;
        }
        Helpers.secureLog(`Stage ${stageName} failed: ${error.message}`, 'error');
        throw error;
    }
};

const CONFIG = Object.freeze({
    delayMs: REQUEST_DELAY_MS,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
    globalTimeoutMs: GLOBAL_TIMEOUT_MS,
    maxTotalRequests: MAX_TOTAL_REQUESTS,
    mutationPolicies: MUTATION_POLICIES,
    memoryLimits: MEMORY_LIMITS,
    fuzzing: STAGE_CONFIG.fuzzing,
    stages: Object.freeze({
        baseline: STAGE_CONFIG.baseline.enabled,
        fuzz: STAGE_CONFIG.fuzzing.enabled,
        singleDelete: STAGE_CONFIG.singleDelete.enabled,
        combinatorialDelete: STAGE_CONFIG.combinatorialDelete.enabled,
        progressiveDelete: STAGE_CONFIG.progressiveDelete.enabled
    }),
    stage3Config: Object.freeze({
        maxCombinations: STAGE_CONFIG.combinatorialDelete.maxCombinations,
        maxFieldsPerCombo: STAGE_CONFIG.combinatorialDelete.maxFieldsPerCombo,
        startWithPairs: STAGE_CONFIG.combinatorialDelete.startWithPairs
    }),
    progressiveConfig: STAGE_CONFIG.progressiveDelete,
    features: FEATURES,
    debug: ADVANCED_CONFIG.debug,
    logDetailedSteps: ADVANCED_CONFIG.logDetailedSteps,
    failFast: ADVANCED_CONFIG.failFast,
    networkRetry: ADVANCED_CONFIG.networkRetry,
    rateLimit: ADVANCED_CONFIG.rateLimit,
    strictVariables: ADVANCED_CONFIG.strictVariables,
    targetPathsKeys: ADVANCED_CONFIG.targetPathsKeys,
    targetPathsPrefixMatch: ADVANCED_CONFIG.targetPathsPrefixMatch
});

if (ENABLE_MUTATION_LOGGING) {
        console.log(`✅ Config v${ENGINE_VERSION} - Configuration assembled successfully`);
    }
if (!ENGINE_ENABLED) {
    if (SHOW_BANNER) {
        console.log(`
╔════════════════════════════════════════════════════════════════════════════
║                   EXPLORATORY API FUZZING TOOL
║                           ENGINE v${ENGINE_VERSION}
╠════════════════════════════════════════════════════════════════════════════
║  📌 STATUS: DISABLED
║  Script loaded successfully, but ENGINE is not activated.
║  Your request will proceed NORMALLY without any modifications.
╠════════════════════════════════════════════════════════════════════════════
║  ⚙️ HOW TO ENABLE ENGINE:
║  1. Open "Pre-request Script" tab
║  2. Find line: const ENGINE_ENABLED = false;
║  3. Change to:  const ENGINE_ENABLED = true;
║  4. Ensure your request has a body (JSON/FormData/URLEncoded) or Query Parameters
║  5. Click "Send"
╠════════════════════════════════════════════════════════════════════════════
║  🎯 WHAT ENGINE DOES WHEN ENABLED:
║  Automatically detects request body format and runs ${Object.keys(STAGE_CONFIG).length} stages:
${(() => {
    const stageOrder = ['baseline', 'fuzzing', 'singleDelete', 'combinatorialDelete', 'progressiveDelete'];
    return stageOrder.map(stageKey => {
        const meta = STAGE_METADATA[stageKey];
        if (!meta) return '';
        
        const dynamicInfo = meta.getDynamicInfo ? ` ${meta.getDynamicInfo()}` : '';
        const header = `║  ${meta.emoji} ${meta.name} - ${meta.shortDesc}${dynamicInfo}`;
        const details = meta.details.map(d => `║     • ${d}`).join('\n');
        
        return `${header}\n${details}`;
    }).join('\n');
})()}
╠════════════════════════════════════════════════════════════════════════════
║  📋 SUPPORTED FORMATS:
║  ✅ FULL SUPPORT:
║     • JSON - complete testing, nested objects, arrays
║  ⚠️  LIMITED SUPPORT:
║     • FormData - flat fields only
║     • URLEncoded - flat fields only
║     • QueryParams (GET) - flat parameters only
║     (no nesting, templates, or files)
║  ❌ NOT SUPPORTED:
║     • XML, Text, Binary, GraphQL, Multipart (File)
╚════════════════════════════════════════════════════════════════════════════
`);
    }
    return;
}
const ENGINE_START_TIME = Date.now();
const ENGINE_START_HIRES = typeof performance !== 'undefined' && performance.now ?
    performance.now() : 0;
if (SHOW_BANNER) {
    console.log(`
╔════════════════════════════════════════════════════════════════════════════
║                   EXPLORATORY API FUZZING TOOL
║                           ENGINE v${ENGINE_VERSION}
╠════════════════════════════════════════════════════════════════════════════
║  ✅ STATUS: ENABLED
║  ENGINE is active and will execute fuzzing stages on this request.
╠════════════════════════════════════════════════════════════════════════════
║  ⚙️  ACTIVE CONFIGURATION:
║  📊 Mutation Policies:
${(() => {
    const lines = [];
    for (const p of CONFIG.fuzzing.usePolicies) {
        const emoji = p === 'light' ? '🟢' : p === 'heavy' ? '🟡' : p === 'format_validation' ? '🟣' : '⚪';
        const count = MUTATION_POLICIES[p] ? MUTATION_POLICIES[p].length : 0;
        lines.push(`║     ✅ ${emoji} ${p.toUpperCase()}: ${count} values`);
    }
    if (CONFIG.fuzzing.fuzzObjects) {
        const count = MUTATION_POLICIES.objectMutations ? MUTATION_POLICIES.objectMutations.length : 0;
        lines.push(`║     ✅ 🔵 OBJECT MUTATIONS: ${count} values`);
    }
    if (CONFIG.fuzzing.fuzzArrays) {
        const count = MUTATION_POLICIES.arrayMutations ? MUTATION_POLICIES.arrayMutations.length : 0;
        lines.push(`║     ✅ 🔵 ARRAY MUTATIONS: ${count} values`);
    }
    // Show testValues info
    if (MUTATION_POLICIES.testValues) {
        const count = MUTATION_POLICIES.testValues.length;
        lines.push(`║     🌐 TEST VALUES (queryparams/urlencoded): ${count} values`);
    }
    return lines.join('\n');
})()}
║  🎯 Enabled Stages:
${Object.entries(CONFIG.stages).map(([stage, enabled]) =>
    `║     ${enabled ? '✅' : '❌'} ${stage}`
).join('\n')}
║  ⏱️  Timing:
║     • Request delay: ${CONFIG.delayMs}ms
║     • Request timeout: ${Math.round(CONFIG.requestTimeoutMs/1000)}s
║     • Global timeout: ${Math.round(CONFIG.globalTimeoutMs/60000)}min
╠════════════════════════════════════════════════════════════════════════════
║  🔍 What ENGINE will do:
║  1. Parse your request body (JSON/FormData/URLEncoded/QueryParams)
║  2. Run baseline check (verify API stability)
║  3. Execute enabled fuzzing stages
║  4. Analyze responses for errors and bugs
║  5. Generate summary report
╚════════════════════════════════════════════════════════════════════════════
`);
}
const HARD_COMBINATION_CAP = 500;
const HARD_RESULTS_CAP = 4000;
const getTzSafeTimestamp = function() {
    if (typeof performance !== 'undefined' && performance.now) {
        return ENGINE_START_TIME + (performance.now() - ENGINE_START_HIRES);
    }
    return Date.now();
};
const createEngineContext = function(MEMORY_LIMITS) {
    return {
        bugClusters: {
            clusters: new Map(),
            maxClusters: MEMORY_LIMITS.maxBugClustersSize || 500,
            clear: function() {
                this.clusters.clear();
            }
        },
        stats: null,
        createdAt: getTzSafeTimestamp(),
        executionId: `exec_${getTzSafeTimestamp()}_${Math.random().toString(36).substr(2, 9)}`
    };
};
const cleanupEngineContext = function(context) {
    if (!context) return;
    if (context.bugClusters) context.bugClusters.clear();
    context.stats = null;
    try {
        if (typeof pm !== 'undefined' && pm.collectionVariables) {
            pm.collectionVariables.unset('engine_running');
        }
    } catch (e) {
    }
};
const safeAddResult = function(collection, result, maxSize) {
    if (!collection || !result) return;
    if (collection.length >= maxSize) {
        collection.shift();
        if (collection.length === maxSize) {
            console.log(`⚠️ Results array reached limit (${maxSize}), oldest results being evicted`);
        }
    }
    collection.push(result);
};
const safeAddTest = function(name, fn, activeConfig) {
    if (typeof pm !== 'undefined' && pm.test) {
        pm.test(name, fn);
        return name;
    }
    return null;
};
const ErrorHandler = {
    executeStage: async function(stageName, stageFunc, context, activeConfig) {
        const startTime = getTzSafeTimestamp();
        try {
            const result = await stageFunc();
            const duration = getTzSafeTimestamp() - startTime;
            return {
                success: true,
                result: result,
                duration: duration,
                stageName: stageName
            };
        } catch (error) {
            const duration = getTzSafeTimestamp() - startTime;
            console.error(`\n❌ STAGE FAILED: ${stageName}`);
            console.error(`   Error: ${error.message}`);
            console.error(`   Duration before fail: ${duration}ms`);
            if (activeConfig && activeConfig.logDetailedSteps && error.stack) {
                console.error(`   Stack trace:\n${error.stack}`);
            }
            if (context && context.stats) {
                context.stats.abortReasons.push(
                    `${stageName} failed: ${error.message}`
                );
            }
            this.generateEmergencyReport(context, stageName, error, activeConfig);
            return {
                success: false,
                error: error,
                duration: duration,
                stageName: stageName
            };
        }
    },
    generateEmergencyReport: function(context, stageName, error, activeConfig) {
        console.log('\n');
        console.log('╔════════════════════════════════════════════════════════╗');
        console.log('║       🚨 EMERGENCY REPORT (Partial Results)          ║');
        console.log('╚════════════════════════════════════════════════════════╝');
        console.log(`\nFailed at stage: ${stageName}`);
        console.log(`Error: ${error.message}`);
        if (!context || !context.stats) {
            console.log('\n⚠️  No stats available (early failure)\n');
            return;
        }
        const stats = context.stats;
        console.log('\n📊 PARTIAL STATISTICS:');
        console.log('─'.repeat(60));
        console.log(`Total requests sent: ${stats.total || 0}`);
        console.log(`Success: ${stats.success || 0}`);
        console.log(`Errors: ${stats.errors || 0}`);
        console.log(`Bugs found: ${stats.bugs || 0}`);
        if (context.bugClusters && context.bugClusters.clusters.size > 0) {
            console.log(`Unique bug patterns: ${context.bugClusters.clusters.size}`);
        }
        console.log('─'.repeat(60));
        console.log('\n💡 TIP: Enable CONFIG.logDetailedSteps for more debug info\n');
    },
    };

const getEnabledHeaders = function() {
    if (!pm || !pm.request) return {};
    const enabledHeaders = {};
    if (pm.request.headers) {
        pm.request.headers.all().forEach(header => {
            if (!header.disabled) {
                enabledHeaders[header.key] = header.value;
            }
        });
    }
    if (pm.request.auth && pm.request.auth.type) {
        const authType = pm.request.auth.type;
        if (authType === 'bearer' && pm.request.auth.bearer) {
            const token = pm.request.auth.bearer.find(i => i.key === 'token');
            if (token && token.value) {
                enabledHeaders['Authorization'] = `Bearer ${token.value}`;
            }
        } else if (authType === 'basic' && pm.request.auth.basic) {
            const username = pm.request.auth.basic.find(i => i.key === 'username');
            const password = pm.request.auth.basic.find(i => i.key === 'password');
            if (username && password) {
                const creds = btoa(`${username.value}:${password.value}`);
                enabledHeaders['Authorization'] = `Basic ${creds}`;
            }
        } else if (authType === 'oauth2' && pm.request.auth.oauth2) {
            const token = pm.request.auth.oauth2.find(i => i.key === 'accessToken');
            if (token && token.value) {
                enabledHeaders['Authorization'] = `Bearer ${token.value}`;
            }
        } else if (authType === 'apikey' && pm.request.auth.apikey) {
            const key = pm.request.auth.apikey.find(i => i.key === 'key');
            const value = pm.request.auth.apikey.find(i => i.key === 'value');
            const addTo = pm.request.auth.apikey.find(i => i.key === 'in');
            if (key && value && addTo && addTo.value === 'header') {
                enabledHeaders[key.value] = value.value;
            }
        }
    }
    return enabledHeaders;
};
const REQUEST_SCOPED_DYNAMIC_VARS = [
    '$timestamp',
    '$isoTimestamp'
];
const ALWAYS_DYNAMIC_VARS = [
    '$guid', '$randomUUID', '$randomInt', '$randomBoolean',
    '$randomIP', '$randomIPV6', '$randomMACAddress', '$randomPassword',
    '$randomLocale', '$randomUserAgent', '$randomProtocol', '$randomSemver',
    '$randomFirstName', '$randomLastName', '$randomFullName',
    '$randomNamePrefix', '$randomNameSuffix',
    '$randomJobArea', '$randomJobDescriptor', '$randomJobTitle', '$randomJobType',
    '$randomPhoneNumber', '$randomPhoneNumberExt',
    '$randomCity', '$randomStreetName', '$randomStreetAddress',
    '$randomCountry', '$randomCountryCode', '$randomLatitude', '$randomLongitude',
    '$randomColor', '$randomHexColor', '$randomAbbreviation',
    '$randomAlphaNumeric', '$randomBankAccount', '$randomBankAccountBic',
    '$randomBankAccountIban', '$randomBitcoin', '$randomCreditCardMask',
    '$randomCurrencyCode', '$randomCurrencyName', '$randomCurrencySymbol',
    '$randomDatabaseCollation', '$randomDatabaseColumn',
    '$randomDatabaseEngine', '$randomDatabaseType',
    '$randomDateFuture', '$randomDatePast', '$randomDateRecent',
    '$randomFileName', '$randomFileType', '$randomFileExt',
    '$randomCommonFileName', '$randomCommonFileType', '$randomCommonFileExt',
    '$randomFilePath', '$randomDirectoryPath', '$randomMimeType',
    '$randomPrice',
    '$randomProduct', '$randomProductAdjective', '$randomProductMaterial',
    '$randomProductName', '$randomDepartment',
    '$randomCompanyName', '$randomCompanySuffix', '$randomBs',
    '$randomBsAdjective', '$randomBsBuzz', '$randomBsNoun',
    '$randomCatchPhrase', '$randomCatchPhraseAdjective',
    '$randomCatchPhraseDescriptor', '$randomCatchPhraseNoun',
    '$randomCompanyCatchPhrase', '$randomDomainName', '$randomDomainSuffix',
    '$randomDomainWord', '$randomEmail', '$randomExampleEmail',
    '$randomUserName', '$randomUrl', '$randomAvatarImage', '$randomImageUrl',
    '$randomAbstractImage', '$randomAnimalsImage', '$randomBusinessImage',
    '$randomCatsImage', '$randomCityImage', '$randomFoodImage',
    '$randomNightlifeImage', '$randomFashionImage', '$randomPeopleImage',
    '$randomNatureImage', '$randomSportsImage', '$randomTransportImage',
    '$randomImageDataUri', '$randomBankAccountName', '$randomTransactionType',
    '$randomCreditCardNumber', '$randomAmount', '$randomArrayElement',
    '$randomWeekday', '$randomMonth', '$randomImage'
];
const DYNAMIC_VARIABLES = [
    ...REQUEST_SCOPED_DYNAMIC_VARS,
    ...ALWAYS_DYNAMIC_VARS
];
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
        if (char === '/' && next === '*') {
            let j = i + 2;
            while (j < raw.length - 1 && !(raw[j] === '*' && raw[j + 1] === '/')) {
                j++;
            }
            i = j + 1;
            continue;
        }
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
    result = result.replace(/[ \t]+(\r?\n)/g, '$1');
    result = result.replace(/^\s*[\r\n]+/gm, '');
    result = result.trim();
    return result;
};
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
const deepCopy = function(obj, visited, depth, maxDepth) {
    visited = visited || new WeakMap();
    depth = depth || 0;
    if (typeof maxDepth !== 'number' || maxDepth < 1) {
        maxDepth = typeof MEMORY_LIMITS !== 'undefined' && MEMORY_LIMITS.maxCollectDepth
            ? MEMORY_LIMITS.maxCollectDepth
            : 100;
    }
    if (depth > maxDepth) {
        console.warn(`⚠️ Max recursion depth (${maxDepth}) reached in deepCopy`);
        return null;
    }
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
            copy[i] = deepCopy(obj[i], visited, depth + 1, maxDepth);
        }
        return copy;
    }
    if (obj instanceof Object) {
        visited.set(obj, true);
        const copy = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                copy[key] = deepCopy(obj[key], visited, depth + 1, maxDepth);
            }
        }
        return copy;
    }
    return obj;
};
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
    sortBottomUp: function(nodes) {
        return [...nodes].sort((a, b) => {
            if (a.path.length !== b.path.length) {
                return b.path.length - a.path.length;
            }
            return a.pathStr.localeCompare(b.pathStr);
        });
    },
    
    // ============================================================================
    // SORT TOP-DOWN: For Progressive Delete (Greedy Algorithm)
    // ============================================================================
    sortTopDown: function(nodes) {
        return [...nodes].sort((a, b) => {
            if (a.path.length !== b.path.length) {
                return a.path.length - b.path.length;  // ASC: 0, 1, 2, 3...
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
};
Utils.addResultSafe = function(stageArray, allResults, result, stats) {
    if (!result) return false;
    if (stageArray && stageArray.length >= MEMORY_LIMITS.maxResultsPerStage) {
        console.warn(`⚠️ Stage result limit reached (${MEMORY_LIMITS.maxResultsPerStage}), discarding oldest`);
        stageArray.shift();
        if (stats) {
            stats.warnings = stats.warnings || [];
            if (stats.warnings.length < MEMORY_LIMITS.maxWarningsSize) {
                stats.warnings.push('Stage result limit reached, oldest results discarded');
            }
        }
    }
    if (allResults && allResults.length >= MEMORY_LIMITS.maxTotalResults) {
        console.warn(`⚠️ Total results limit reached (${MEMORY_LIMITS.maxTotalResults}), cannot add more`);
        if (stats) {
            stats.skipped = (stats.skipped || 0) + 1;
            stats.warnings = stats.warnings || [];
            if (stats.warnings.length < MEMORY_LIMITS.maxWarningsSize) {
                stats.warnings.push('Total results limit reached, new results skipped');
            }
        }
        return false;
    }
    if (stageArray) stageArray.push(result);
    if (allResults) allResults.push(result);
    return true;
};
const checkGlobalTimeout = function(stats, activeConfig) {
    if (typeof stats === 'undefined' || !stats || !stats.startTime) return false;
    const elapsed = getTzSafeTimestamp() - stats.startTime;
    if (elapsed > activeConfig.globalTimeoutMs) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(`Global timeout (${activeConfig.globalTimeoutMs}ms)`);
        if (typeof AbortController !== 'undefined') {
        }
        return true;
    }
    return false;
};
const getAllRecentResults = function(stats, count) {
    if (!stats || !stats.stageResults) return [];
    const allResults = [];
    if (stats.stageResults.baseline) allResults.push(...stats.stageResults.baseline);
    if (stats.stageResults.fuzz) allResults.push(...stats.stageResults.fuzz);
    if (stats.stageResults.singleDelete) allResults.push(...stats.stageResults.singleDelete);
    if (stats.stageResults.combinatorialDelete) allResults.push(...stats.stageResults.combinatorialDelete);
    if (stats.stageResults.progressiveDelete) allResults.push(...stats.stageResults.progressiveDelete);
    return allResults.slice(-count);
};
const MutationLogger = {
    formatValue: function(value, maxLength = 50) {
        if (value === null) return 'null';
        if (value === undefined) return 'undefined';
        let str;
        if (typeof value === 'string') {
            str = `"${value}"`;
        } else if (typeof value === 'object') {
            try {
                str = JSON.stringify(value);
            } catch (e) {
                str = '[object]';
            }
        } else {
            str = String(value);
        }
        if (str.length > maxLength) {
            return str.substring(0, maxLength) + '...';
        }
        return str;
    },
    getTypeLabel: function(value) {
        if (value === null) return 'null';
        if (value === undefined) return 'undefined';
        if (Array.isArray(value)) return 'array';
        if (typeof value === 'object') return 'object';
        if (typeof value === 'string') return 'string';
        if (typeof value === 'number') return 'number';
        if (typeof value === 'boolean') return 'boolean';
        return 'unknown';
    },
    logReplace: function(pathStr, oldValue, newValue, isEnabled) {
        if (!isEnabled || typeof ENABLE_MUTATION_LOGGING === 'undefined' || !ENABLE_MUTATION_LOGGING) {
            return;
        }
        const oldStr = this.formatValue(oldValue);
        const newStr = this.formatValue(newValue);
        console.log(`  [REPLACE] ${pathStr}: ${oldStr} → ${newStr}`);
    },
    logDelete: function(pathStr, deletedValue, isEnabled) {
        if (!isEnabled || typeof ENABLE_MUTATION_LOGGING === 'undefined' || !ENABLE_MUTATION_LOGGING) {
            return;
        }
        const typeLabel = this.getTypeLabel(deletedValue);
        const valuePreview = this.formatValue(deletedValue, 30);
        if (typeLabel === 'object' || typeLabel === 'array') {
            console.log(`  [DELETE]  ${pathStr} [${typeLabel}]`);
        } else {
            console.log(`  [DELETE]  ${pathStr}: ${valuePreview} [${typeLabel}]`);
        }
    },
    extractOldValue: function(template, path, provider) {
        if (!template || !path || !provider) return undefined;
        try {
            if (provider.name === 'JSON') {
                let current = template;
                for (const segment of path) {
                    if (current === null || current === undefined) return undefined;
                    current = current[segment];
                }
                return current;
            }
            if (provider.name === 'FormData' || provider.name === 'URLEncoded' || provider.name === 'QueryParams') {
                if (!Array.isArray(template)) return undefined;
                const index = path[0];
                if (typeof index === 'number' && index >= 0 && index < template.length) {
                    return template[index].value;
                }
                return undefined;
            }
            return undefined;
        } catch (e) {
            return undefined;
        }
    }
};
const JSONStructureMap = {
    printMap: function(template, provider, allNodes, bodyFormat, TemplateProcessor, Utils) {
        if (!template || !allNodes || allNodes.length === 0) return;
        console.log('\n📦 JSON STRUCTURE MAP:\n');
        let resolvedTemplate;
        if (bodyFormat === 'json' && TemplateProcessor) {
            resolvedTemplate = TemplateProcessor.processTemplates(Utils.deepCopy(template), {});
        } else {
            resolvedTemplate = template;
        }
        const primitiveNodes = allNodes.filter(node =>
            node.valueType === 'primitive'
        );
        for (const node of primitiveNodes) {
            if (!node.pathStr) continue;
            const value = MutationLogger.extractOldValue(resolvedTemplate, node.path, provider);
            const formattedValue = MutationLogger.formatValue(value, 100);
            console.log(`${node.pathStr} = ${formattedValue}`);
        }
        console.log('');
    }
};
const checkFailFast = function(stats, activeConfig) {
    if (!stats || !activeConfig?.failFast?.enabled) {
        return false;
    }
    
    const recentResults = getAllRecentResults(stats, 20);
    if (recentResults.length === 0) return false;
    
    // Count service errors (5xx) - v27.0.1: ALL 5xx codes, not just 502/503/504
    const serviceErrors = recentResults.filter(r => 
        r && r.code >= 500 && r.code < 600
    ).length;
    
    // Count rate limit errors (429)
    const rateLimitErrors = recentResults.filter(r => 
        r && r.code === 429
    ).length;
    
    // Check service errors threshold
    if (serviceErrors >= activeConfig.failFast.maxServiceErrors) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(
            `Fail-fast triggered: ${serviceErrors} service errors (5xx) in last 20 requests`
        );
        return true;
    }
    
    // Check rate limit threshold
    if (rateLimitErrors >= activeConfig.failFast.maxRateLimitErrors) {
        stats.abortReasons = stats.abortReasons || [];
        stats.abortReasons.push(
            `Fail-fast triggered: ${rateLimitErrors} rate limit errors (429) in last 20 requests`
        );
        return true;
    }
    
    return false;
};
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
            if (depth > MEMORY_LIMITS.maxCollectDepth) {
                console.warn(`⚠️ Max depth ${MEMORY_LIMITS.maxCollectDepth} reached at: ${pathStr || '(root)'}`);
                return nodes;
            }
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
            if (visited.has(obj)) {
                console.warn(`⚠️ Circular reference detected at: ${pathStr || '(root)'}`);
                return nodes;
            }
            visited.add(obj);
            if (Array.isArray(obj)) {
                if (path.length > 0) {
                    nodes.push({
                        path: path.slice(),
                        pathStr: pathStr,
                        value: obj,
                        valueType: 'array',
                        depth: depth
                    });
                }
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
                if (path.length > 0) {
                    nodes.push({
                        path: path.slice(),
                        pathStr: pathStr,
                        value: obj,
                        valueType: 'object',
                        depth: depth
                    });
                }
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
        cleanupEmpty: function(obj, depth, maxDepth) {
            depth = depth || 0;
            maxDepth = maxDepth || 50;
            if (depth > maxDepth) {
                console.warn(`⚠️ cleanupEmpty: max depth ${maxDepth} reached`);
                return obj;
            }
            if (obj === null || typeof obj !== 'object') {
                return obj;
            }
            if (Array.isArray(obj)) {
                const cleaned = obj.map(item => this.cleanupEmpty(item, depth + 1, maxDepth));
                const filtered = cleaned.filter(item => {
                    if (item === null || typeof item !== 'object') {
                        return true;
                    }
                    if (!Array.isArray(item) && Object.keys(item).length === 0) {
                        return false;
                    }
                    if (Array.isArray(item) && item.length === 0) {
                        return false;
                    }
                    return true;
                });
                return filtered;
            }
            else {
                const cleaned = {};
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        const value = this.cleanupEmpty(obj[key], depth + 1, maxDepth);
                        if (value === null || typeof value !== 'object') {
                            cleaned[key] = value;
                            continue;
                        }
                        if (!Array.isArray(value) && Object.keys(value).length === 0) {
                            continue;
                        }
                        if (Array.isArray(value) && value.length === 0) {
                            continue;
                        }
                        cleaned[key] = value;
                    }
                }
                return cleaned;
            }
        }
    };
};
const createFormDataProvider = function() {
    return {
        name: 'FormData',
        collectNodes: function(formDataObj) {
            const nodes = [];
            let formDataArray;
            if (Array.isArray(formDataObj)) {
                formDataArray = formDataObj;
            } else if (formDataObj && typeof formDataObj === 'object') {
                if (formDataObj.members && Array.isArray(formDataObj.members)) {
                    formDataArray = formDataObj.members;
                } else if (typeof formDataObj.toJSON === 'function') {
                    const jsonData = formDataObj.toJSON();
                    if (Array.isArray(jsonData)) {
                        formDataArray = jsonData;
                    } else if (jsonData && jsonData.members && Array.isArray(jsonData.members)) {
                        formDataArray = jsonData.members;
                    } else {
                        console.warn('⚠️ FormData: toJSON() did not return expected structure');
                        return nodes;
                    }
                } else if (typeof formDataObj.all === 'function') {
                    try {
                        formDataArray = formDataObj.all();
                    } catch (e) {
                        console.warn('⚠️ FormData: error calling all():', e.message);
                        return nodes;
                    }
                } else {
                    console.warn('⚠️ FormData expected array, got:', typeof formDataObj);
                    return nodes;
                }
            } else {
                console.warn('⚠️ FormData: invalid structure', typeof formDataObj);
                return nodes;
            }
            for (let i = 0; i < formDataArray.length; i++) {
                const item = formDataArray[i];
                if (!item || !item.key || item.disabled === true) continue;
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
        }
    };
};
const createURLEncodedProvider = function() {
    return {
        name: 'URLEncoded',
        collectNodes: function(urlencodedObj) {
            const nodes = [];
            let urlencodedArray;
            if (Array.isArray(urlencodedObj)) {
                urlencodedArray = urlencodedObj;
            } else if (urlencodedObj && typeof urlencodedObj === 'object') {
                if (urlencodedObj.members && Array.isArray(urlencodedObj.members)) {
                    urlencodedArray = urlencodedObj.members;
                } else if (typeof urlencodedObj.toJSON === 'function') {
                    const jsonData = urlencodedObj.toJSON();
                    if (Array.isArray(jsonData)) {
                        urlencodedArray = jsonData;
                    } else if (jsonData && jsonData.members && Array.isArray(jsonData.members)) {
                        urlencodedArray = jsonData.members;
                    } else {
                        console.warn('⚠️ URLEncoded: toJSON() did not return expected structure');
                        return nodes;
                    }
                } else if (typeof urlencodedObj.all === 'function') {
                    try {
                        urlencodedArray = urlencodedObj.all();
                    } catch (e) {
                        console.warn('⚠️ URLEncoded: error calling all():', e.message);
                        return nodes;
                    }
                } else {
                    console.warn('⚠️ URLEncoded expected array, got:', typeof urlencodedObj);
                    return nodes;
                }
            } else {
                console.warn('⚠️ URLEncoded: invalid structure', typeof urlencodedObj);
                return nodes;
            }
            for (let i = 0; i < urlencodedArray.length; i++) {
                const item = urlencodedArray[i];
                if (!item || !item.key || item.disabled === true) continue;
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
        }
    };
};
const createQueryParamsProvider = function() {
    return {
        name: 'QueryParams',
        collectNodes: function(queryObj) {
            const nodes = [];
            let queryArray;
            if (Array.isArray(queryObj)) {
                queryArray = queryObj;
            } else if (queryObj && typeof queryObj === 'object') {
                if (queryObj.members && Array.isArray(queryObj.members)) {
                    queryArray = queryObj.members;
                } else if (typeof queryObj.toJSON === 'function') {
                    const jsonData = queryObj.toJSON();
                    if (Array.isArray(jsonData)) {
                        queryArray = jsonData;
                    } else if (jsonData && jsonData.members && Array.isArray(jsonData.members)) {
                        queryArray = jsonData.members;
                    } else {
                        console.warn('⚠️ QueryParams: toJSON() did not return expected structure');
                        return nodes;
                    }
                } else if (typeof queryObj.all === 'function') {
                    try {
                        queryArray = queryObj.all();
                    } catch (e) {
                        console.warn('⚠️ QueryParams: error calling all():', e.message);
                        return nodes;
                    }
                } else {
                    console.warn('⚠️ QueryParams expected array, got:', typeof queryObj);
                    return nodes;
                }
            } else {
                console.warn('⚠️ QueryParams: invalid structure', typeof queryObj);
                return nodes;
            }
            for (let i = 0; i < queryArray.length; i++) {
                const item = queryArray[i];
                if (!item || !item.key || item.disabled === true) continue;
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
        deleteByPath: function(queryArray, path) {
            if (!Array.isArray(queryArray) || !path || path.length === 0) return false;
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < queryArray.length) {
                queryArray.splice(index, 1);
                return true;
            }
            return false;
        },
        setByPath: function(queryArray, path, value) {
            if (!Array.isArray(queryArray) || !path || path.length === 0) return false;
            const index = path[0];
            if (typeof index === 'number' && index >= 0 && index < queryArray.length) {
                queryArray[index].value = value;
                return true;
            }
            return false;
        }
    };
};
const DataProviderFactory = {
    create: function(type) {
        switch (type) {
            case 'json':
                return createJSONProvider();
            case 'formdata':
                return createFormDataProvider();
            case 'urlencoded':
                return createURLEncodedProvider();
            case 'queryparams':
                return createQueryParamsProvider();
            default:
                console.error(`❌ Unsupported request body format: "${type}"`);
                console.error('   Supported formats: json, formdata, urlencoded, queryparams');
                console.error('   XML, Text, Binary and GraphQL formats are NOT supported');
                throw new Error(`Unsupported body format: ${type}. Supported formats: json, formdata, urlencoded, queryparams`);
        }
    }
};
const createRateLimiter = function(CONFIG) {
    const queue = [];
    let lastRequest = 0;
    return {
        wait: async function() {
            if (!CONFIG.rateLimit.enabled) return;
            const now = getTzSafeTimestamp();
            const filtered = queue.filter(t => now - t < CONFIG.rateLimit.burstWindowMs);
            queue.length = 0;
            queue.push(...filtered);
            if (queue.length >= CONFIG.rateLimit.burstLimit) {
                const delay = CONFIG.rateLimit.burstWindowMs - (now - queue[0]);
                await new Promise(r => setTimeout(r, Math.max(0, delay)));
            }
            const timeSinceLast = getTzSafeTimestamp() - lastRequest;
            if (timeSinceLast < CONFIG.rateLimit.delayMs) {
                await new Promise(r => setTimeout(r, CONFIG.rateLimit.delayMs - timeSinceLast));
            }
            lastRequest = getTzSafeTimestamp();
            queue.push(lastRequest);
        },
        reset: function() {
            queue.length = 0;
            lastRequest = 0;
        }
    };
};
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
        // Check for timeout errors
        if (errorMsg.includes('timeout') || errorMsg.includes('Timeout')) {
            return true;
        }
        // Check for configured retryable errors
        return CONFIG.networkRetry.retryErrors.some(err => errorMsg.includes(err));
    };
    return {
        send: async function(method, url, bodyData, label, bodyFormat, rateLimiter) {
            await rateLimiter.wait();
            if (!pm) {
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
                        header: getEnabledHeaders()
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
                            case 'queryparams':
                                if (Array.isArray(bodyData) && bodyData.length > 0) {
                                    const baseUrl = url.split('?')[0];
                                    const queryParts = [];
                                    for (const param of bodyData) {
                                        if (param && param.key && param.disabled !== true) {
                                            const key = encodeURIComponent(param.key);
                                            const value = encodeURIComponent(param.value || '');
                                            queryParts.push(`${key}=${value}`);
                                        }
                                    }
                                    if (queryParts.length > 0) {
                                        requestConfig.url = `${baseUrl}?${queryParts.join('&')}`;
                                    } else {
                                        requestConfig.url = baseUrl;
                                    }
                                }
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
                    const startTime = getTzSafeTimestamp();
                    
                    return await new Promise((resolve, reject) => {
                        let isCompleted = false;  // Flag to prevent race conditions
                        let timeoutId = null;
                        
                        // Timeout Promise
                        const timeoutPromise = new Promise((_, timeoutReject) => {
                            timeoutId = setTimeout(() => {
                                if (!isCompleted) {
                                    isCompleted = true;
                                    timeoutReject(new Error(`Request timeout after ${CONFIG.requestTimeoutMs}ms`));
                                }
                            }, CONFIG.requestTimeoutMs);
                        });
                        
                        // Request Promise
                        const requestPromise = new Promise((requestResolve, requestReject) => {
                            pm.sendRequest(requestConfig, (err, res) => {
                                // Check if already completed (timeout fired)
                                if (isCompleted) {
                                    if (CONFIG.debug && CONFIG.debug.enabled) {
                                        console.warn(`⚠️ Late response received after timeout (ignored) - URL: ${requestConfig.url}`);
                                    }
                                    return;  // Ignore late response
                                }
                                
                                isCompleted = true;  // Block timeout
                                if (timeoutId !== null) {
                                    clearTimeout(timeoutId);  // Clean up timeout
                                }
                                
                                // Handle error
                                if (err) {
                                    requestReject(err);
                                    return;
                                }
                                
                                // Handle successful response
                                const code = res?.code || 0;
                                let responseBody = null;
                                try {
                                    responseBody = res ? res.json() : null;
                                } catch (e) {
                                    responseBody = res ? res.text() : null;
                                }
                                
                                requestResolve({
                                    label,
                                    code,
                                    response: res,
                                    responseBody,
                                    responseTime: res?.responseTime || (getTzSafeTimestamp() - startTime),
                                    timestamp: getTzSafeTimestamp()
                                });
                            });
                        });
                        
                        // Promise.race: first Promise to complete wins
                        Promise.race([requestPromise, timeoutPromise])
                            .then(resolve)
                            .catch(reject)
                            .finally(() => {
                                // Ensure timeout is always cleared
                                if (timeoutId !== null) {
                                    clearTimeout(timeoutId);
                                }
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
                timestamp: getTzSafeTimestamp()
            };
        }
    };
};
const PostmanAdapter = {
    extractMethodAndUrl: function() {
        if (!pm || !pm.request) {
            throw new Error('pm.request not available');
        }
        return {
            method: pm.request.method,
            url: pm.request.url.toString()
        };
    },
    extractQueryParams: function() {
        if (!pm || !pm.request || !pm.request.url) {
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
    setTest: function(name, fn, activeConfig) {
        if (!activeConfig.features.postmanTest) return;
        try {
            safeAddTest(name, fn, activeConfig);
        } catch (err) {
            console.error(`Test error: ${err.message}`);
        }
    },
    setRequestBody: function(payload, bodyFormat) {
        if (!pm || !pm.request) {
            return;
        }
        try {
            if (bodyFormat === 'json' && pm.request.body) {
                pm.request.body.raw = JSON.stringify(payload, null, 2);
            } else if (bodyFormat === 'formdata' && pm.request.body && Array.isArray(payload)) {
                pm.request.body.formdata.clear();
                payload.forEach(field => {
                    if (field.key && !field.disabled) {
                        pm.request.body.formdata.add({
                            key: field.key,
                            value: field.value || '',
                            type: field.type || 'text',
                            disabled: false
                        });
                    }
                });
            } else if (bodyFormat === 'urlencoded' && pm.request.body && Array.isArray(payload)) {
                pm.request.body.urlencoded.clear();
                payload.forEach(field => {
                    if (field.key && !field.disabled) {
                        pm.request.body.urlencoded.add({
                            key: field.key,
                            value: field.value || '',
                            disabled: false
                        });
                    }
                });
            } else if (bodyFormat === 'queryparams' && pm.request.url && pm.request.url.query && Array.isArray(payload)) {
                pm.request.url.query.clear();
                payload.forEach(param => {
                    if (param.key && !param.disabled) {
                        pm.request.url.query.add({
                            key: param.key,
                            value: param.value || '',
                            disabled: false
                        });
                    }
                });
            }
        } catch (error) {
            console.warn(`⚠️ Failed to update pm.request: ${error.message}`);
        }
    }
};

// ============================================================================
// BODY PARSING UTILITIES
// ============================================================================

const parseBodyData = function(bodyData) {
    if (typeof bodyData.toJSON === 'function') return bodyData.toJSON();
    if (typeof bodyData.all === 'function') return bodyData.all();
    if (bodyData.members && Array.isArray(bodyData.members)) return bodyData.members;
    if (Array.isArray(bodyData)) return bodyData;
    return bodyData;
};

const detectBodyFormat = function(Utils) {
    if (!pm || !pm.request) {
        return { format: 'none', data: null };
    }
    
    const body = pm.request.body;
    if (body && body.mode === 'formdata' && body.formdata) {
        return { format: 'formdata', data: body.formdata };
    }
    if (body && body.mode === 'urlencoded' && body.urlencoded) {
        return { format: 'urlencoded', data: body.urlencoded };
    }
    if (body && body.mode === 'raw' && body.raw) {
        let rawContent = body.raw.trim();
        rawContent = rawContent.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        let parsed = null;
        let lastError = null;
        let processedContent = null;
        try {
            parsed = JSON.parse(rawContent);
            return { format: 'json', data: parsed };
        } catch (e1) {
            lastError = e1;
        }
        try {
            // Apply comment removal and template escaping based on configuration
            if (ENABLE_JSON_COMMENTS) {
                // ENABLED: Remove comments from JSON before parsing
                processedContent = Utils.removeComments(rawContent);
                processedContent = Utils.escapeUnquotedTemplates(processedContent);
                
                // Optional: Log comment removal activity (if mutation logging is enabled)
                if (ENABLE_MUTATION_LOGGING && processedContent !== rawContent) {
                    const charDiff = rawContent.length - processedContent.length;
                    console.log(`ℹ️  JSON comments processed: ${charDiff} characters stripped`);
                }
            } else {
                // DISABLED: Skip comment removal, only escape Postman variables
                processedContent = Utils.escapeUnquotedTemplates(rawContent);
            }
            
            parsed = JSON.parse(processedContent);
            return { format: 'json', data: parsed };
        } catch (e2) {
            lastError = e2;
            console.error('❌ XML/Text formats are NOT supported');
            console.error(`   JSON parsing error: ${lastError.message}`);
            const originalPreview = rawContent.substring(0, 150);
            console.error(`   Original content preview: ${originalPreview.replace(/\n/g, '\\n')}`);
            if (processedContent) {
                const processedPreview = processedContent.substring(0, 150);
                console.error(`   Processed content preview: ${processedPreview.replace(/\n/g, '\\n')}`);
            }
            console.error('   Convert request to JSON format for testing');
            console.error('   Ensure body contains valid JSON (not XML, not text)');
            throw new Error(`XML/Text formats are not supported. Use JSON format. Parse error: ${lastError.message}`);
        }
    }
    if (body && body.mode === 'file') {
        console.error('❌ File format is NOT supported');
        console.error('   Convert request to JSON, FormData or URLEncoded format');
        throw new Error('File format is not supported. Use JSON, FormData, or URLEncoded.');
    }
    if (body && body.mode === 'binary') {
        console.error('❌ Binary format is NOT supported');
        console.error('   Convert request to JSON, FormData or URLEncoded format');
        throw new Error('Binary format is not supported. Use JSON, FormData, or URLEncoded.');
    }
    if (body && body.mode === 'graphql') {
        console.error('❌ GraphQL format is NOT supported');
        console.error('   Convert request to JSON format for testing');
        throw new Error('GraphQL format is not supported. Use JSON format.');
    }
    if (body && body.mode && body.mode !== 'none') {
        console.error(`❌ Unsupported body format: ${body.mode}`);
        console.error('   Supported formats: json, formdata, urlencoded');
        throw new Error(`Unsupported body format: ${body.mode}. Supported formats: json, formdata, urlencoded`);
    }
    if (pm.request.url && pm.request.url.query) {
        const queryParams = pm.request.url.query;
        let hasEnabledParams = false;
        if (typeof queryParams.all === 'function') {
            const allParams = queryParams.all();
            hasEnabledParams = allParams.some(p => p && p.key && p.disabled !== true);
        } else if (Array.isArray(queryParams)) {
            hasEnabledParams = queryParams.some(p => p && p.key && p.disabled !== true);
        } else if (queryParams.members && Array.isArray(queryParams.members)) {
            hasEnabledParams = queryParams.members.some(p => p && p.key && p.disabled !== true);
        }
        if (hasEnabledParams) {
            return { format: 'queryparams', data: queryParams };
        }
    }
    return { format: 'none', data: null };
};
const MARKER_UNQ = "__UNQ_TPL__";
const TemplateProcessor = {
    processTemplates: function(obj, incCache) {
        incCache = incCache || {};
        if (typeof ALWAYS_DYNAMIC_VARS !== 'undefined') {
            for (const key in incCache) {
                if (incCache.hasOwnProperty(key)) {
                    const isAlwaysDynamic = ALWAYS_DYNAMIC_VARS.some(dv => key.includes(dv));
                    if (isAlwaysDynamic) {
                        delete incCache[key];
                    }
                }
            }
        }
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
                        const isRequestScoped = typeof REQUEST_SCOPED_DYNAMIC_VARS !== 'undefined' &&
                                               REQUEST_SCOPED_DYNAMIC_VARS.some(dv => varName.includes(dv));
                        const isAlwaysDynamic = typeof ALWAYS_DYNAMIC_VARS !== 'undefined' &&
                                               ALWAYS_DYNAMIC_VARS.some(dv => varName.includes(dv));
                        if (isAlwaysDynamic && incCache.hasOwnProperty(match)) {
                            delete incCache[match];
                        }
                        if (isAlwaysDynamic) {
                            try {
                                return typeof pm !== 'undefined' && pm.variables
                                    ? pm.variables.replaceIn(match)
                                    : match;
                            } catch {
                                return match;
                            }
                        }
                        if (isRequestScoped) {
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
const ResponseAnalyzer = {
    classifyError: function(code, responseBody, response) {
        // Philosophy: Differentiate actionable errors (stop) from data collection (continue)
        code = parseInt(code);
        
        // CRITICAL: Physical impossibility to continue testing
        if (code === 0 || isNaN(code)) return 'network';    // Connection failed, timeout, parse error
        if (code === 401 || code === 403) return 'auth';    // No credentials or permissions
        
        // Server errors (all 5xx range, not just specific codes)
        if (code >= 500 && code < 600) return 'serverError'; // Potential bugs (interesting!)
        
        // Rate limiting
        if (code === 429) return 'rateLimit';               // Rate limit (handled by failFast)
        
        // Client validation errors (all 4xx except auth and rate limit)
        // This automatically covers: 400, 404, 405, 409, 415, 422, 418 (I'm a teapot), 
        // 451 (Unavailable For Legal Reasons), and any future 4xx codes
        if (code >= 400 && code < 500) return 'validation'; // API validation working
        
        // Success
        if (code >= 200 && code < 300) return 'success';
        
        return 'other';
    },
    createSignature: function(code, responseBody, response, Utils, activeConfig) {
        try {
            const bodyStr = typeof responseBody === 'string'
                ? responseBody
                : JSON.stringify(responseBody);
            const normalized = typeof BugClustering !== 'undefined' && BugClustering.normalizeError
                ? BugClustering.normalizeError(bodyStr.substring(0, 500))
                : bodyStr.substring(0, 500);
            const errorClass = this.classifyError(code, responseBody, response) || 'NONE';
            return `${code}:${errorClass}:${Utils.hashDJB2(normalized)}`;
        } catch {
            return `${code}:ERROR:UNKNOWN`;
        }
    },
    checkAbort: function(result, activeConfig, stats) {
        if (!result) return false;
        
        const code = result.code;
        const errorClass = result.errorClass;
        const MAX_IDENTICAL_ERRORS = 50;
        
        // 1. Success continues testing
        if (code >= 200 && code < 300) {
            // Reset identical error counter on success
            if (this._identicalErrorCounter) {
                this._identicalErrorCounter = null;
            }
            return false;
        }
        if (['network', 'auth'].includes(errorClass)) {
            if (stats) {
                stats.abortReasons = stats.abortReasons || [];
                const reason = errorClass === 'network' 
                    ? `Network error (code ${code}) - cannot send requests`
                    : `Auth error (code ${code}) - no credentials or permissions`;
                stats.abortReasons.push(reason);
            }
            return true;
        }
        if (['validation', 'serverError', 'rateLimit'].includes(errorClass)) {
            const errorSignature = `${code}:${result.signature || 'UNKNOWN'}`;
            
            if (!this._identicalErrorCounter) {
                this._identicalErrorCounter = { signature: errorSignature, count: 1 };
            } else if (this._identicalErrorCounter.signature === errorSignature) {
                this._identicalErrorCounter.count++;
                
                // STOP after 50 identical errors in a row
                if (this._identicalErrorCounter.count >= MAX_IDENTICAL_ERRORS) {
                    if (stats) {
                        stats.abortReasons = stats.abortReasons || [];
                        stats.abortReasons.push(
                            `Identical ${errorClass} error ×${this._identicalErrorCounter.count} ` +
                            `(code ${code}) - API appears broken or stuck in error loop`
                        );
                    }
                    return true;
                }
            } else {
                // Error signature changed - reset counter (API is responding differently = data collection)
                this._identicalErrorCounter = { signature: errorSignature, count: 1 };
            }
        }
        
        // 4. CONTINUE on everything else (validation, rateLimit, serverError)
        //    Reasoning:
        //    - validation (400/404/405/409/415/422): Expected responses during fuzzing → DATA
        //    - rateLimit (429): Handled by failFast backoff mechanism
        //    - serverError (5xx): Potential bugs → INTERESTING, collect data
        //    BUT: Now with protection against infinite loops (see step 3)
        return false;
    },
    
    resetIdenticalErrorCounter: function() {
        if (this._identicalErrorCounter) {
            this._identicalErrorCounter = null;
        }
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
const MutationStages = {
    async executeBaseline(method, url, templateOriginal, bodyFormat, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!activeConfig.stages.baseline) return true;
        console.log('\n🎯 STAGE 1: BASELINE\n');
        
        ResponseAnalyzer.resetIdenticalErrorCounter();
        
        const responses = [];
        for (let i = 0; i < 3; i++) {
            if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) {
                return false;
            }
            const payload = Utils.deepCopy(templateOriginal);
            let processed = (bodyFormat === 'json')
                ? TemplateProcessor.processTemplates(payload, {})
                : payload;
            const result = await httpClient.send(
                method, url, processed, `BASELINE ${i + 1}/3`, bodyFormat, rateLimiter
            );
            if (result) {
                responses.push(result);
                safeAddResult(stats.stageResults.baseline, result, HARD_RESULTS_CAP);
                stats.total++;
                stats.codes[result.code] = (stats.codes[result.code] || 0) + 1;
                if (result.responseTime) stats.responseTimes.push(result.responseTime);
                if (ENABLE_MUTATION_LOGGING) {
                    console.log(`  ${i + 1}/3: [${result.code}] ${result.responseTime || 0}ms`);
                }
            }
            if (i < 2) await Utils.delay(activeConfig.delayMs);
        }
        const codes = responses.map(r => r.code);
        const allSame = codes.every(c => c === codes[0]);
        
        // v26.0.0: Enhanced baseline decision logic
        // SUCCESS: API is stable and returns 2xx/3xx
        if (allSame && codes[0] >= 200 && codes[0] < 400) {
            stats.baselineVerdict = 'PASSING';
            return true;
        }
        
        // CRITICAL STOP: Physical impossibility to continue (network, auth)
        else if (allSame && [0, 401, 403].includes(codes[0])) {
            if (codes[0] === 0) {
                stats.baselineVerdict = 'NETWORK_ERROR';
                stats.abortReasons.push('Baseline: Network connection failed - cannot send requests');
            } else if (codes[0] === 401) {
                stats.baselineVerdict = 'UNAUTHORIZED';
                stats.abortReasons.push('Baseline: 401 Unauthorized - authentication required');
            } else if (codes[0] === 403) {
                stats.baselineVerdict = 'FORBIDDEN';
                stats.abortReasons.push('Baseline: 403 Forbidden - insufficient permissions');
            }
            return false;  // STOP
        }
        
        else if (codes.some(c => c >= 500)) {
            const all5xx = codes.every(c => c >= 500);
            stats.baselineVerdict = all5xx ? 'FAILING' : 'INCONSISTENT';
            // CONTINUE - collect data even from unstable/broken API
            return true;
        }
        
        else {
            stats.baselineVerdict = 'INCONSISTENT';
            return true;
        }
    },
    async executeFuzzing(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, PostmanAdapter) {
        if (!activeConfig.stages.fuzz) return;
        if (activeConfig.targetPathsKeys && activeConfig.targetPathsKeys.length > 0 && bodyFormat !== 'json') {
            console.log(`ℹ️  Note: targetPathsKeys filtering is NOT ACTIVE for ${bodyFormat} format (JSON only)`);
        }
        
        ResponseAnalyzer.resetIdenticalErrorCounter();
        
        const mutations = [];
        for (const policy of activeConfig.fuzzing.usePolicies) {
            if (activeConfig.mutationPolicies[policy]) {
                mutations.push(...activeConfig.mutationPolicies[policy]);
            }
        }
        
        if ((bodyFormat === 'queryparams' || bodyFormat === 'urlencoded') && 
            activeConfig.mutationPolicies.testValues) {
            console.log(`ℹ️  Auto-switched to testValues for ${bodyFormat} format (${activeConfig.mutationPolicies.testValues.length} specialized values)`);
            console.log(`   (Original policies: ${activeConfig.fuzzing.usePolicies.join(', ')})\n`);
            mutations.length = 0; // Clear mutations array
            mutations.push(...activeConfig.mutationPolicies.testValues);
        }
        
        const uniqueMutations = [...new Set(mutations)];
        
        const primitiveNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'primitive', activeConfig, Utils);
        const objectNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'object', activeConfig, Utils);
        const arrayNodes = this.getFuzzableNodes(allNodes, bodyFormat, 'array', activeConfig, Utils);
        
        console.log(`\n🔀 STAGE 2: FUZZING - Primitives: ${primitiveNodes.length} | Objects: ${objectNodes.length} | Arrays: ${arrayNodes.length}\n`);
        for (const node of primitiveNodes) {
            if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) {
                console.log('🛑 Primitive fuzzing aborted');
                return;
            }
            let fieldMutations = uniqueMutations;
            for (const mutValue of fieldMutations) {
                const v = Utils.deepCopy(templateOriginal);
                let processed = (bodyFormat === 'json')
                    ? TemplateProcessor.processTemplates(v, {})
                    : v;
                const oldValue = MutationLogger.extractOldValue(processed, node.path, provider);
                if (provider && provider.setByPath(processed, node.path, mutValue)) {
                    MutationLogger.logReplace(node.pathStr, oldValue, mutValue, ENABLE_MUTATION_LOGGING);
                    if (typeof PostmanAdapter !== 'undefined') {
                        PostmanAdapter.setRequestBody(processed, bodyFormat);
                    }
                    const labelPrefix = 'FUZZ';
                    const result = await httpClient.send(
                        method, url, processed,
                        `${labelPrefix}:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                        bodyFormat, rateLimiter
                    );
                    if (result) {
                        this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                        safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                        safeAddResult(stats.stageResults.fuzz, result, HARD_RESULTS_CAP);
                    }
                    if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) {
                        console.log('🛑 Primitive fuzzing aborted');
                        return;
                    }
                    await Utils.delay(activeConfig.delayMs);
                }
            }
        }
        if (activeConfig.fuzzing.fuzzObjects) {
            if (bodyFormat === 'formdata' || bodyFormat === 'urlencoded') {
                if (ENABLE_MUTATION_LOGGING) {
                    console.log(`⏭️  Object fuzzing skipped: ${bodyFormat} format doesn't support objects\n`);
                }
            } else if (objectNodes.length === 0 && bodyFormat !== 'json') {
                if (ENABLE_MUTATION_LOGGING) {
                    console.log(`⏭️  Object fuzzing skipped: ${bodyFormat} format doesn't support objects\n`);
                }
            } else if (objectNodes.length > 0) {
                console.log(`\n📦 Fuzzing ${objectNodes.length} objects\n`);
                const objectMutations = activeConfig.mutationPolicies.objectMutations || [{}, null, {"key": "value"}];
                for (const node of objectNodes.slice(0, 20)) {
                    if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) return;
                    for (const mutValue of objectMutations) {
                        const v = Utils.deepCopy(templateOriginal);
                        let processed = (bodyFormat === 'json')
                            ? TemplateProcessor.processTemplates(v, {})
                            : v;
                        const oldValue = MutationLogger.extractOldValue(processed, node.path, provider);
                        if (provider && provider.setByPath(processed, node.path, mutValue)) {
                            MutationLogger.logReplace(node.pathStr, oldValue, mutValue, ENABLE_MUTATION_LOGGING);
                            if (typeof PostmanAdapter !== 'undefined') {
                                PostmanAdapter.setRequestBody(processed, bodyFormat);
                            }
                            const result = await httpClient.send(
                                method, url, processed,
                                `FUZZ:OBJ:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                                bodyFormat, rateLimiter
                            );
                            if (result) {
                                this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                                safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                                safeAddResult(stats.stageResults.fuzz, result, HARD_RESULTS_CAP);
                            }
                            if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) return;
                            await Utils.delay(activeConfig.delayMs);
                        }
                    }
                }
            }
        }
        if (activeConfig.fuzzing.fuzzArrays) {
            if (bodyFormat === 'formdata' || bodyFormat === 'urlencoded') {
                if (ENABLE_MUTATION_LOGGING) {
                    console.log(`⏭️  Array fuzzing skipped: ${bodyFormat} format doesn't support arrays\n`);
                }
            } else if (arrayNodes.length === 0 && bodyFormat !== 'json') {
                if (ENABLE_MUTATION_LOGGING) {
                    console.log(`⏭️  Array fuzzing skipped: ${bodyFormat} format doesn't support arrays\n`);
                }
            } else if (arrayNodes.length > 0) {
                console.log(`\n📊 Fuzzing ${arrayNodes.length} arrays\n`);
                const arrayMutations = activeConfig.mutationPolicies.arrayMutations || [[], null, [[]], [null]];
                for (const node of arrayNodes.slice(0, 20)) {
                    if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) return;
                    for (const mutValue of arrayMutations) {
                        const v = Utils.deepCopy(templateOriginal);
                        let processed = (bodyFormat === 'json')
                            ? TemplateProcessor.processTemplates(v, {})
                            : v;
                        const oldValue = MutationLogger.extractOldValue(processed, node.path, provider);
                        if (provider && provider.setByPath(processed, node.path, mutValue)) {
                            MutationLogger.logReplace(node.pathStr, oldValue, mutValue, ENABLE_MUTATION_LOGGING);
                            if (typeof PostmanAdapter !== 'undefined') {
                                PostmanAdapter.setRequestBody(processed, bodyFormat);
                            }
                            const result = await httpClient.send(
                                method, url, processed,
                                `FUZZ:ARR:${node.pathStr}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                                bodyFormat, rateLimiter
                            );
                            if (result) {
                                this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                                safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                                safeAddResult(stats.stageResults.fuzz, result, HARD_RESULTS_CAP);
                            }
                            if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) return;
                            await Utils.delay(activeConfig.delayMs);
                        }
                    }
                }
            }
        }
        const queryParams = PostmanAdapter.extractQueryParams();
        const queryKeys = Object.keys(queryParams);
        if (queryKeys.length > 0) {
            console.log(`\n🔗 Fuzzing ${queryKeys.length} query parameters\n`);
            for (const key of queryKeys) {
                if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) return;
                let paramMutations = uniqueMutations.slice(0, 10);
                for (const mutValue of paramMutations) {
                    const oldValue = queryParams[key];
                    MutationLogger.logReplace(`query.${key}`, oldValue, mutValue, ENABLE_MUTATION_LOGGING);
                    const modifiedParams = { ...queryParams, [key]: mutValue };
                    const newUrl = PostmanAdapter.buildUrlWithParams(url, modifiedParams);
                    let bodyData = Utils.deepCopy(templateOriginal);
                    if (bodyFormat === 'json') {
                        bodyData = TemplateProcessor.processTemplates(bodyData, {});
                    }
                    const labelPrefix = 'FUZZ';
                    const result = await httpClient.send(
                        method, newUrl, bodyData,
                        `${labelPrefix}:query.${key}=${Utils.safeStringify(mutValue).substring(0, 20)}`,
                        bodyFormat, rateLimiter
                    );
                    if (result) {
                        this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                        safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                        safeAddResult(stats.stageResults.fuzz, result, HARD_RESULTS_CAP);
                    }
                    if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) return;
                    await Utils.delay(activeConfig.delayMs);
                }
            }
        }
    },
    async executeSingleDelete(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!activeConfig.stages.singleDelete) return;
        if (activeConfig.targetPathsKeys && activeConfig.targetPathsKeys.length > 0) {
            console.log('ℹ️  Single Delete stage SKIPPED: targetPathsKeys is only supported for FUZZING stage');
            console.log('ℹ️  To run this stage, remove targetPathsKeys or set it to empty array []');
            return;
        }
        
        ResponseAnalyzer.resetIdenticalErrorCounter();
        
        let deleteNodes = this.getDeleteableNodes(allNodes, bodyFormat, activeConfig, Utils);
        deleteNodes = Utils.sortBottomUp(deleteNodes);
        
        console.log(`\n🗑️ STAGE 3: SINGLE DELETE - Testing ${deleteNodes.length} deletions\n`);
        for (const node of deleteNodes) {
            if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) return;
            const v = Utils.deepCopy(templateOriginal);
            let processed = (bodyFormat === 'json')
                ? TemplateProcessor.processTemplates(v, {})
                : v;
            const deletedValue = MutationLogger.extractOldValue(processed, node.path, provider);
            if (provider && provider.deleteByPath(processed, node.path)) {
                MutationLogger.logDelete(node.pathStr, deletedValue, ENABLE_MUTATION_LOGGING);
                let cleanedPayload = processed;
                if (provider && provider.cleanupEmpty && bodyFormat === 'json') {
                    const beforeSize = JSON.stringify(processed).length;
                    cleanedPayload = provider.cleanupEmpty(processed);
                    const afterSize = JSON.stringify(cleanedPayload).length;
                    if (beforeSize - afterSize > 50) {
                        if (ENABLE_MUTATION_LOGGING) {
                            console.log(`   🧹 Cleaned up empty containers: ${beforeSize} → ${afterSize} bytes`);
                        }
                    }
                }
                if (typeof PostmanAdapter !== 'undefined') {
                    PostmanAdapter.setRequestBody(cleanedPayload, bodyFormat);
                }
                const result = await httpClient.send(
                    method, url, cleanedPayload, `DEL-S:${node.pathStr}`, bodyFormat, rateLimiter
                );
                if (result) {
                    this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                    safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                    safeAddResult(stats.stageResults.singleDelete, result, HARD_RESULTS_CAP);
                    ResponseAnalyzer.detectRequiredField(node.pathStr, result.code, result.responseBody, stats);
                }
                if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) return;
                await Utils.delay(activeConfig.delayMs);
            }
        }
    },
    async executeCombinatorialDelete(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!activeConfig.stages.combinatorialDelete) return;
        if (activeConfig.targetPathsKeys && activeConfig.targetPathsKeys.length > 0) {
            console.log('ℹ️  Combinatorial Delete stage SKIPPED: targetPathsKeys is only supported for FUZZING stage');
            console.log('ℹ️  To run this stage, remove targetPathsKeys or set it to empty array []');
            return;
        }
        
        ResponseAnalyzer.resetIdenticalErrorCounter();
        
        let primitives = this.getPrimitiveNodes(allNodes, bodyFormat);
        const cfg = activeConfig.stage3Config;
        const effectiveMaxCombinations = Math.min(cfg.maxCombinations, HARD_COMBINATION_CAP);
        const combinations = [];
        if (cfg.startWithPairs && primitives.length >= 2) {
            for (let i = 0; i < primitives.length - 1; i++) {
                for (let j = i + 1; j < primitives.length; j++) {
                    combinations.push([primitives[i], primitives[j]]);
                    if (combinations.length >= effectiveMaxCombinations) break;
                }
                if (combinations.length >= effectiveMaxCombinations) break;
            }
        }
        if (combinations.length < effectiveMaxCombinations) {
            for (let size = 3; size <= Math.min(cfg.maxFieldsPerCombo, primitives.length); size++) {
                const remaining = effectiveMaxCombinations - combinations.length;
                const combos = this.generateCombinations(primitives, size, remaining);
                combinations.push(...combos);
                if (combinations.length >= effectiveMaxCombinations) break;
            }
        }
        
        console.log(`\n🧩 STAGE 4: COMBINATORIAL DELETE (Pairwise Testing) - Generated ${combinations.length} combinations\n`);
        
        for (const combo of combinations) {
            if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) return;
            const v = Utils.deepCopy(templateOriginal);
            let processed = (bodyFormat === 'json')
                ? TemplateProcessor.processTemplates(v, {})
                : v;
            const sortedCombo = Utils.sortBottomUp(combo);
            let deletedCount = 0;
            const deletedNodes = [];
            if (ENABLE_MUTATION_LOGGING) {
                console.log(`  [COMBO-DELETE] Combination of ${combo.length} fields:`);
            }
            for (const node of sortedCombo) {
                const deletedValue = MutationLogger.extractOldValue(processed, node.path, provider);
                if (provider && provider.deleteByPath(processed, node.path)) {
                    MutationLogger.logDelete(node.pathStr, deletedValue, ENABLE_MUTATION_LOGGING);
                    deletedCount++;
                    deletedNodes.push(node);
                }
            }
            if (deletedCount > 0) {
                let cleanedPayload = processed;
                if (provider && provider.cleanupEmpty && bodyFormat === 'json') {
                    const beforeSize = JSON.stringify(processed).length;
                    cleanedPayload = provider.cleanupEmpty(processed);
                    const afterSize = JSON.stringify(cleanedPayload).length;
                    if (beforeSize - afterSize > 50) {
                        if (ENABLE_MUTATION_LOGGING) {
                            console.log(`   🧹 Cleaned up empty containers: ${beforeSize} → ${afterSize} bytes`);
                        }
                    }
                }
                if (typeof PostmanAdapter !== 'undefined') {
                    PostmanAdapter.setRequestBody(cleanedPayload, bodyFormat);
                }
                const label = `COMB-DEL[${deletedCount}]:${deletedNodes.map(n => n.pathStr).join('+')}`;
                const result = await httpClient.send(
                    method, url, processed, label, bodyFormat, rateLimiter
                );
                if (result) {
                    this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                    safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                    safeAddResult(stats.stageResults.combinatorialDelete, result, HARD_RESULTS_CAP);
                }
                if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) return;
                await Utils.delay(activeConfig.delayMs);
            }
        }
    },
    async executeProgressiveDelete(method, url, templateOriginal, allNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer) {
        if (!activeConfig.stages.progressiveDelete) return;
        
        // RESTRICTION: targetPathsKeys not supported for this stage
        if (activeConfig.targetPathsKeys && activeConfig.targetPathsKeys.length > 0) {
            console.log('ℹ️  Progressive Delete stage SKIPPED: targetPathsKeys is only supported for FUZZING stage');
            console.log('ℹ️  To run this stage, remove targetPathsKeys or set it to empty array []');
            return;
        }
        
        ResponseAnalyzer.resetIdenticalErrorCounter();
        
        let deletableNodes = this.getAllDeletableNodes(allNodes, bodyFormat, activeConfig, Utils);
        const cfg = activeConfig.progressiveConfig || { continueOnError: false, logMinimalPayload: true };
        const sortedNodes = Utils.sortTopDown(deletableNodes);
        
        console.log(`\n📉 STAGE 5: PROGRESSIVE DELETE (Top-Down Greedy) - Starting with ${sortedNodes.length} nodes\n`);
        
        if (sortedNodes.length > 0) {
            const minDepth = Math.min(...sortedNodes.map(n => n.path.length));
            const maxDepth = Math.max(...sortedNodes.map(n => n.path.length));
            console.log(`ℹ️  Strategy: Deleting from root to leaves (depth ${minDepth} → ${maxDepth})\n`);
        }
        
        let currentPayload = Utils.deepCopy(templateOriginal);
        const originalSize = JSON.stringify(currentPayload).length;
        stats.optionalFields = stats.optionalFields || new Set();
        stats.requiredFields = stats.requiredFields || new Set();
        for (let i = 0; i < sortedNodes.length; i++) {
            if (checkGlobalTimeout(stats, activeConfig) || checkFailFast(stats, activeConfig)) {
                console.log(`\n⏹️ Progressive Delete stopped at field ${i + 1}/${sortedNodes.length}`);
                break;
            }
            const node = sortedNodes[i];
            let processedCurrent = (bodyFormat === 'json')
                ? TemplateProcessor.processTemplates(Utils.deepCopy(currentPayload), {})
                : Utils.deepCopy(currentPayload);
            const deletedValue = MutationLogger.extractOldValue(processedCurrent, node.path, provider);
            const deleted = provider.deleteByPath(processedCurrent, node.path);
            if (!deleted) {
                continue;
            }
            MutationLogger.logDelete(node.pathStr, deletedValue, ENABLE_MUTATION_LOGGING);
            let cleanedPayload = processedCurrent;
            if (provider && provider.cleanupEmpty && bodyFormat === 'json') {
                cleanedPayload = provider.cleanupEmpty(processedCurrent);
            }
            if (typeof PostmanAdapter !== 'undefined') {
                PostmanAdapter.setRequestBody(cleanedPayload, bodyFormat);
            }
            const label = `PROG-DEL[${i + 1}/${sortedNodes.length}]:-${node.pathStr}`;
            const result = await httpClient.send(
                method, url, cleanedPayload, label, bodyFormat, rateLimiter
            );
            if (result) {
                this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                safeAddResult(stats.stageResults.progressiveDelete, result, HARD_RESULTS_CAP);
                if (result.code >= 200 && result.code < 300) {
                    const testPayloadRaw = Utils.deepCopy(currentPayload);
                    provider.deleteByPath(testPayloadRaw, node.path);
                    if (provider && provider.cleanupEmpty && bodyFormat === 'json') {
                        currentPayload = provider.cleanupEmpty(testPayloadRaw);
                    } else {
                        currentPayload = testPayloadRaw;
                    }
                    stats.optionalFields.add(node.pathStr);
                } else {
                    stats.requiredFields.add(node.pathStr);
                    if (!cfg.continueOnError) {
                        console.log(`\n⏹️ Stopping at first required field (continueOnError=false)`);
                        break;
                    }
                }
            }
            if (result?.aborted || ResponseAnalyzer.checkAbort(result, activeConfig, stats)) {
                console.log(`\n⏹️ Progressive Delete aborted`);
                break;
            }
            await Utils.delay(activeConfig.delayMs);
        }
        if (bodyFormat === 'json') {
            const hasContent = Array.isArray(currentPayload)
                ? currentPayload.length > 0
                : Object.keys(currentPayload).length > 0;
            if (hasContent && stats.requiredFields.size === 0) {
                console.log('\n🔍 All fields are optional - testing empty payload...');
                const emptyPayload = Array.isArray(templateOriginal) ? [] : {};
                if (typeof PostmanAdapter !== 'undefined') {
                    PostmanAdapter.setRequestBody(emptyPayload, bodyFormat);
                }
                let processed = TemplateProcessor.processTemplates(emptyPayload, {});
                const result = await httpClient.send(
                    method, url, processed, 'PROG-DEL[EMPTY]', bodyFormat, rateLimiter
                );
                if (result) {
                    this.updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils);
                    safeAddResult(allStagesResults, result, HARD_RESULTS_CAP);
                    safeAddResult(stats.stageResults.progressiveDelete, result, HARD_RESULTS_CAP);
                    if (result.code >= 200 && result.code < 300) {
                        console.log('   ✅ Empty payload accepted - API requires NOTHING!');
                        currentPayload = emptyPayload;
                        stats.acceptsEmptyPayload = true;
                    } else {
                        console.log(`   ❌ Empty payload rejected (${result.code})`);
                        console.log(`   ⚠️  Note: 0 required fields detected, but API rejects empty payload`);
                        console.log(`   ⚠️  This may indicate required containers or business logic constraints`);
                        stats.acceptsEmptyPayload = false;
                        stats.emptyPayloadFinding = {
                            code: result.code,
                            message: 'API rejects empty payload despite all fields being individually optional',
                            implication: 'Possible required container structure or business logic validation'
                        };
                    }
                    await Utils.delay(activeConfig.delayMs);
                }
            }
        }
        stats.minimalPayload = currentPayload;
        const finalSize = JSON.stringify(currentPayload).length;
        const reduction = originalSize > 0 ? ((originalSize - finalSize) / originalSize * 100).toFixed(1) : 0;
        stats.payloadReduction = `${originalSize} → ${finalSize} bytes (${reduction}% reduction)`;
        
        // Log minimal payload if enabled and small enough
        if (bodyFormat === 'json' && cfg.logMinimalPayload && finalSize < 1000) {
            console.log('\n📋 Minimal working payload (< 1KB):');
            console.log(JSON.stringify(currentPayload, null, 2));
        }
    },
    getFuzzableNodes(allNodes, bodyFormat, nodeType, activeConfig, Utils) {
        let nodes = [];
        if (bodyFormat === 'formdata') {
            nodes = allNodes.filter(n =>
                (n.formDataType === 'text' || n.formDataType === 'file') &&
                Utils.isAllowed(n.path, activeConfig)
            );
        } else if (bodyFormat === 'urlencoded' || bodyFormat === 'queryparams' || bodyFormat === 'json') {
            if (nodeType === 'primitive') {
                nodes = allNodes.filter(n =>
                    n.valueType === 'primitive' &&
                    n.path.length > 0 &&
                    Utils.isAllowed(n.path, activeConfig)
                );
            } else if (nodeType === 'object') {
                nodes = allNodes.filter(n =>
                    n.valueType === 'object' &&
                    n.path.length > 0 &&
                    Utils.isAllowed(n.path, activeConfig)
                );
            } else if (nodeType === 'array') {
                nodes = allNodes.filter(n =>
                    n.valueType === 'array' &&
                    n.path.length > 0 &&
                    Utils.isAllowed(n.path, activeConfig)
                );
            }
        }
        return nodes;
    },
    getDeleteableNodes(allNodes, bodyFormat, activeConfig, Utils) {
        return this.getFuzzableNodes(allNodes, bodyFormat, 'primitive', activeConfig, Utils);
    },
    getPrimitiveNodes(allNodes, bodyFormat) {
        if (bodyFormat === 'formdata') {
            return allNodes.filter(n => n.formDataType === 'text');
        } else if (bodyFormat === 'urlencoded' || bodyFormat === 'queryparams' || bodyFormat === 'json') {
            return allNodes.filter(n =>
                n.valueType === 'primitive' &&
                n.path.length > 0
            );
        }
        return [];
    },
    getAllDeletableNodes(allNodes, bodyFormat, activeConfig, Utils) {
        if (bodyFormat === 'formdata') {
            return allNodes.filter(n => n.formDataType === 'text');
        } else if (bodyFormat === 'urlencoded' || bodyFormat === 'queryparams') {
            return allNodes.filter(n =>
                n.valueType === 'primitive' &&
                n.path.length > 0 &&
                Utils.isAllowed(n.path, activeConfig)
            );
        } else if (bodyFormat === 'json') {
            return allNodes.filter(n =>
                n.path.length > 0 &&
                Utils.isAllowed(n.path, activeConfig)
            );
        }
        return [];
    },
    generateCombinations(array, size, maxResults) {
        maxResults = Math.min(maxResults || Infinity, HARD_COMBINATION_CAP);
        const result = [];
        const combine = (start, combo, depth) => {
            if (depth > 10) return;
            if (result.length >= maxResults) return;
            if (combo.length === size) {
                result.push(combo.slice());
                return;
            }
            for (let i = start; i < array.length; i++) {
                if (result.length >= maxResults) break;
                combo.push(array[i]);
                combine(i + 1, combo, depth + 1);
                combo.pop();
            }
        };
        combine(0, [], 0);
        return result;
    },
    updateStatsFromResult(result, stats, ResponseAnalyzer, activeConfig, Utils) {
        stats.total++;
        
        // ENHANCED: Check MAX_TOTAL_REQUESTS quota protection
        if (MAX_TOTAL_REQUESTS > 0 && stats.total > MAX_TOTAL_REQUESTS) {
            console.error('╔═══════════════════════════════════════════════════════════╗');
            console.error('║              🚫 MAX_TOTAL_REQUESTS EXCEEDED               ║');
            console.error('╚═══════════════════════════════════════════════════════════╝');
            console.error(`\nRequest quota limit reached: ${MAX_TOTAL_REQUESTS}`);
            console.error(`Current requests: ${stats.total}`);
            console.error(`\n💡 This protects against API quota exhaustion`);
            console.error(`   Increase MAX_TOTAL_REQUESTS if needed for large tests`);
            console.error(`   Or disable specific stages to reduce request count\n`);
            throw new Error(`MAX_TOTAL_REQUESTS (${MAX_TOTAL_REQUESTS}) exceeded - stopping at ${stats.total} requests`);
        }
        
        stats.codes[result.code] = (stats.codes[result.code] || 0) + 1;
        if (result.responseTime) stats.responseTimes.push(result.responseTime);
        const errorType = ResponseAnalyzer.classifyError(result.code, result.responseBody, result.response, activeConfig);
        const signature = ResponseAnalyzer.createSignature(result.code, result.responseBody, result.response, Utils);
        result.errorClass = errorType;
        result.signature = signature;
        if (activeConfig.logShowResponse) {
            const icon = result.code >= 500 ? '💥' : result.code >= 400 ? '⚠️' : '✅';
            console.log(`${icon} [${result.code}] ${result.label} (${result.responseTime || 0}ms)`);
        }
    }
};
const BugClustering = {
    MAX_OCCURRENCES_SAMPLES: 5,
    normalizeError: function(message) {
        if (typeof message !== 'string') {
            message = String(message);
        }
        let normalized = message;
        normalized = normalized.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '[ID]');
        normalized = normalized.replace(/\d{6,}/g, '[ID]');
        normalized = normalized.replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/g, '[TIMESTAMP]');
        normalized = normalized.replace(/\d{10,13}/g, '[TIMESTAMP]');
        normalized = normalized.replace(/[0-9a-f]{32,64}/gi, '[HASH]');
        normalized = normalized.replace(/(?:\d{1,3}\.){3}\d{1,3}/g, '[IP]');
        normalized = normalized.replace(/https?:\/\/[^\s]+/g, '[URL]');
        return normalized.trim();
    },

    clusterBySignature: function(results) {
        const clusters = {};
        for (const result of results) {
            const statusCode = result.statusCode || result.code || 'unknown';
            const rawMessage = result.response?.error || result.response?.message || 'Unknown error';
            const signature = this.normalizeError(rawMessage);
            let bodyHash = '';
            try {
                const responseBody = result.responseBody || result.response?.body;
                if (responseBody) {
                    const bodyStr = typeof responseBody === 'string' 
                        ? responseBody 
                        : JSON.stringify(responseBody);
                    // Use first 500 chars for better differentiation
                    const bodySnippet = bodyStr.substring(0, 500);
                    // Simple hash function
                    bodyHash = this.simpleHash(bodySnippet).toString();
                }
            } catch (e) {
                bodyHash = 'no_body';
            }
            
            const clusterKey = `${statusCode}_${signature}_${bodyHash}`;
            
            if (!clusters[clusterKey]) {
                clusters[clusterKey] = {
                    signature: signature,
                    statusCode: statusCode,
                    bodyHash: bodyHash,
                    count: 0,
                    sampleOccurrences: []
                };
            }
            clusters[clusterKey].count++;
            if (clusters[clusterKey].sampleOccurrences.length < this.MAX_OCCURRENCES_SAMPLES) {
                clusters[clusterKey].sampleOccurrences.push({
                    label: result.label || 'unknown',
                    code: statusCode
                });
            }
        }
        const sortedClusters = Object.values(clusters).sort((a, b) => b.count - a.count);
        return sortedClusters;
    },
    
    // Simple hash function for body differentiation
    simpleHash: function(str) {
        let hash = 0;
        if (str.length === 0) return hash;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash);
    },
    getSortedClusters: function(clusters) {
        if (Array.isArray(clusters)) {
            return clusters;
        }
        if (clusters instanceof Map || (clusters && typeof clusters.values === 'function')) {
            return Array.from(clusters.values()).sort((a, b) => {
                const aCode = parseInt(a.code || a.statusCode) || 0;
                const bCode = parseInt(b.code || b.statusCode) || 0;
                if (aCode >= 500 && bCode < 500) return -1;
                if (aCode < 500 && bCode >= 500) return 1;
                return (b.count || 0) - (a.count || 0);
            });
        }
        if (typeof clusters === 'object' && clusters !== null) {
            return Object.values(clusters).sort((a, b) => (b.count || 0) - (a.count || 0));
        }
        return [];
    }
};
const createFreshStats = function() {
    return {
        total: 0,
        skipped: 0,
        codes: {},
        responseTimes: [],
        startTime: getTzSafeTimestamp(),
        abortReasons: [],
        stageResults: {
            baseline: [],
            fuzz: [],
            singleDelete: [],
            combinatorialDelete: [],
            progressiveDelete: []
        },
        baselineVerdict: null,
        baselineSignatures: [],
        baselineResponses: [],
        requiredFields: new Set(),
        optionalFields: new Set(),
        minimalPayload: null,
        payloadReduction: null,
        failureSignatures: new Set(),
        signatureCache: new Map(),
        bugClusters: new Map(),
        bodyFormat: 'unknown',
        formatStats: {
            formDataFields: 0,
            formDataFiles: 0,
            urlencodedFields: 0
        },
        bugs: 0,
        requests: 0,
        mutations: 0,
        warnings: []
    };
};
const validateRequiredVariables = function(templateOriginal, bodyFormat, activeConfig, TemplateProcessor) {
    if (!activeConfig.strictVariables) return;
    let jsonStr = '';
    if (bodyFormat === 'json') {
        jsonStr = JSON.stringify(templateOriginal);
    } else if (bodyFormat === 'formdata' || bodyFormat === 'urlencoded' || bodyFormat === 'queryparams') {
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
            if (!pm || !pm.variables) continue;
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
        console.error('  ║                     ⚠️ FATAL ERROR                        ║');
        console.error('  ╚═══════════════════════════════════════════════════════════╝');
        console.error(`\n${errorMsg}`);
        console.error('\nPlease set these variables before running the script.');
        console.log('\n💡 How to fix (add to Pre-request Script BEFORE engine code):');
        missingVars.forEach(v => {
            console.log(`   pm.collectionVariables.set('${v}', <value>);`);
        });
        throw new Error(errorMsg);
    }
};
const printSummary = function(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter) {
    const duration = ((getTzSafeTimestamp() - stats.startTime) / 1000).toFixed(1);
    const avgResp = stats.responseTimes.length
        ? Math.round(stats.responseTimes.reduce((a, b) => a + b, 0) / stats.responseTimes.length)
        : 0;
    console.log('📊 EXECUTION');
    console.log('────────────────────────────────────');
    console.log(`Requests:   ${stats.total} | Skipped: ${stats.skipped}`);
    console.log(`Duration:   ${duration}s | Avg: ${avgResp}ms`);
    console.log(`Format:     ${stats.bodyFormat.toUpperCase()}`);
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
    if (stats.bugClusters && stats.bugClusters.size > 0) {
        console.log('\n🧬 BUG CLUSTERS');
        console.log('────────────────────────────────────');
        const sortedClusters = BugClustering.getSortedClusters(stats.bugClusters);
        sortedClusters.slice(0, 10).forEach((cluster, idx) => {
            console.log(`${idx + 1}. [${cluster.code}] ${cluster.errorClass} - ${cluster.count}× occurrences`);
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
    console.log('');
    if (activeConfig.features.postmanTest) {
        const totalBugs = stats.failureSignatures.size || (stats.bugClusters ? stats.bugClusters.size : 0);
        if (totalBugs > 0) {
            PostmanAdapter.setTest(
                `Fuzzing v${ENGINE_VERSION}: Found ${totalBugs} unique bugs`,
                () => pm.expect(totalBugs).to.be.above(0),
                activeConfig
            );
        } else {
            PostmanAdapter.setTest(
                `Fuzzing v${ENGINE_VERSION}: No bugs found`,
                () => pm.expect(stats.baselineVerdict).to.equal('PASSING'),
                activeConfig
            );
        }
    }
};
(async function main() {
    const context = createEngineContext(MEMORY_LIMITS);
    const activeConfig = Object.freeze(CONFIG);
    
    // ENHANCED: Global timeout protection for Newman environment
    let globalTimeoutHandle = null;
    if (GLOBAL_TIMEOUT_MS > 0) {
        globalTimeoutHandle = setTimeout(() => {
            const elapsed = ((getTzSafeTimestamp() - (context.stats?.startTime || Date.now())) / 1000).toFixed(1);
            console.error('╔═══════════════════════════════════════════════════════════╗');
            console.error('║                  ⏱️  GLOBAL TIMEOUT                       ║');
            console.error('╚═══════════════════════════════════════════════════════════╝');
            console.error(`\nMaximum execution time (${GLOBAL_TIMEOUT_MS}ms) exceeded`);
            console.error(`Elapsed: ${elapsed}s`);
            console.error(`\n💡 This prevents infinite hangs in Newman/CI environments`);
            console.error(`   Increase GLOBAL_TIMEOUT_MS if needed for large tests\n`);
            throw new Error(`Global timeout (${GLOBAL_TIMEOUT_MS}ms) exceeded after ${elapsed}s`);
        }, GLOBAL_TIMEOUT_MS);
    }
    
    try {
        context.stats = createFreshStats();
        let stats = context.stats;
        try {
            if (typeof pm !== 'undefined' && pm.collectionVariables) {
                const engineRunning = pm.collectionVariables.get('engine_running');
                if (engineRunning === 'true') {
                    console.warn(`⚠️  Multiple ENGINE instances detected - behavior undefined, possible conflicts`);
                }
                pm.collectionVariables.set('engine_running', 'true');
            }
        } catch (e) {
        }
        const { method, url } = PostmanAdapter.extractMethodAndUrl();
        const { format: bodyFormat, data: bodyData } = detectBodyFormat(Utils);
        if (!bodyData) {
            if (typeof pm !== 'undefined' && pm.collectionVariables) {
                try {
                    pm.collectionVariables.set('engine_running', 'false');
                } catch (e) {}
            }
            return;
        }
        stats.bodyFormat = bodyFormat;
        const provider = DataProviderFactory.create(bodyFormat);
        validateRequiredVariables(bodyData, bodyFormat, activeConfig, TemplateProcessor);
        let allNodes = [];
        let templateOriginal = bodyData;
        if (bodyFormat === 'json') {
            allNodes = provider.collectNodes(templateOriginal, [], '', 0, new WeakSet(), MEMORY_LIMITS);
            
            // ENHANCED: Validate maxCollectNodesSize to prevent OOM
            if (MEMORY_LIMITS.maxCollectNodesSize > 0 && allNodes.length > MEMORY_LIMITS.maxCollectNodesSize) {
                console.error('╔═══════════════════════════════════════════════════════════╗');
                console.error('║                🧠 JSON STRUCTURE TOO LARGE                ║');
                console.error('╚═══════════════════════════════════════════════════════════╝');
                console.error(`\nJSON contains too many nodes: ${allNodes.length}`);
                console.error(`Maximum allowed: ${MEMORY_LIMITS.maxCollectNodesSize}`);
                console.error(`\n💡 Solutions:`);
                console.error(`   1. Use targetPathsKeys to test specific fields only`);
                console.error(`      Example: TARGET_PATHS_KEYS = ["data.0", "metadata"]`);
                console.error(`   2. Simplify JSON structure (reduce nesting/arrays)`);
                console.error(`   3. Increase MEMORY_LIMITS.maxCollectNodesSize (risk: OOM)\n`);
                throw new Error(`JSON too large: ${allNodes.length} nodes exceeds maxCollectNodesSize (${MEMORY_LIMITS.maxCollectNodesSize})`);
            }
            
            // Check nesting depth
            const maxDepth = allNodes.length > 0 ? Math.max(...allNodes.map(n => n.path.length)) : 0;
            if (MEMORY_LIMITS.maxCollectDepth > 0 && maxDepth > MEMORY_LIMITS.maxCollectDepth) {
                console.warn(`⚠️  Deep nesting detected: ${maxDepth} levels (max recommended: ${MEMORY_LIMITS.maxCollectDepth})`);
                console.warn(`   May cause stack overflow - consider flattening JSON structure\n`);
            }
            
            if (ENABLE_MUTATION_LOGGING && allNodes.length > 0) {
                JSONStructureMap.printMap(templateOriginal, provider, allNodes, bodyFormat, TemplateProcessor, Utils);
            }
        } else if (bodyFormat === 'formdata') {
            templateOriginal = parseBodyData(bodyData);
            allNodes = provider.collectNodes(templateOriginal);
            const textFields = allNodes.filter(n => n.formDataType === 'text');
            const fileFields = allNodes.filter(n => n.formDataType === 'file');
            stats.formatStats.formDataFields = textFields.length;
            stats.formatStats.formDataFiles = fileFields.length;
        } else if (bodyFormat === 'urlencoded') {
            templateOriginal = parseBodyData(bodyData);
            allNodes = provider.collectNodes(templateOriginal);
            stats.formatStats.urlencodedFields = allNodes.length;
        } else if (bodyFormat === 'queryparams') {
            templateOriginal = parseBodyData(bodyData);
            allNodes = provider.collectNodes(templateOriginal);
            stats.formatStats.queryParamsCount = allNodes.length;
        }
        
        // ============================================================================
        // APPLY PATH FILTERING (targetPathsKeys) - JSON FORMAT ONLY!
        // ============================================================================
        let filteredNodes = allNodes;
        
        if (activeConfig.targetPathsKeys && activeConfig.targetPathsKeys.length > 0) {
            // RESTRICTION: Check if format is JSON - fail fast if not
            if (bodyFormat !== 'json') {
                throw new Error(
                    `❌ targetPathsKeys only works with JSON format (current: ${bodyFormat})\n` +
                    `   Solution: Either remove targetPathsKeys or switch to JSON body format`
                );
            }
            
            // Validate and apply filtering for JSON format
            const validation = PathFilter.validateConfig(activeConfig);
            if (!validation.valid) {
                console.error('❌ Invalid targetPathsKeys configuration');
                validation.warnings.forEach(w => console.error(`  - ${w}`));
                throw new Error('Configuration validation failed');
            }
            
            if (validation.warnings.length > 0 && activeConfig.debug && activeConfig.debug.enabled) {
                console.warn('⚠️  PathFilter configuration warnings:');
                validation.warnings.forEach(w => console.warn(`  - ${w}`));
            }
            
            filteredNodes = PathFilter.filterNodes(allNodes, activeConfig);
            
            PathFilter.logFilterStats(
                allNodes.length,
                filteredNodes.length,
                activeConfig
            );
            
            if (filteredNodes.length > 0) {
                console.log(`ℹ️  Path filtering active: testing ${filteredNodes.length} of ${allNodes.length} nodes`);
                console.log(`ℹ️  Note: Only FUZZING stage is supported with targetPathsKeys`);
            }
        }
        
        const rateLimiter = createRateLimiter(activeConfig);
        const httpClient = createHttpClient(activeConfig);
        const allStagesResults = [];

        // Execute all stages using unified executor
        try {
            // Baseline stage
            const baselineOk = await executeStageWithHandler(
                'baseline',
                MutationStages.executeBaseline,
                [method, url, templateOriginal, bodyFormat, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer],
                context,
                activeConfig,
                stats,
                BugClustering,
                PostmanAdapter
            );

            if (!baselineOk) {
                return;
            }

            // Fuzzing stage
            await executeStageWithHandler(
                'fuzzing',
                MutationStages.executeFuzzing,
                [method, url, templateOriginal, filteredNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer, PostmanAdapter],
                context,
                activeConfig,
                stats,
                BugClustering,
                PostmanAdapter
            );

            // Single delete stage
            await executeStageWithHandler(
                'single-delete',
                MutationStages.executeSingleDelete,
                [method, url, templateOriginal, filteredNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer],
                context,
                activeConfig,
                stats,
                BugClustering,
                PostmanAdapter
            );

            // Combinatorial delete stage
            await executeStageWithHandler(
                'combinatorial-delete',
                MutationStages.executeCombinatorialDelete,
                [method, url, templateOriginal, filteredNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer],
                context,
                activeConfig,
                stats,
                BugClustering,
                PostmanAdapter
            );

            // Progressive delete stage
            await executeStageWithHandler(
                'progressive-delete',
                MutationStages.executeProgressiveDelete,
                [method, url, templateOriginal, filteredNodes, allStagesResults, bodyFormat, provider, activeConfig, Utils, TemplateProcessor, httpClient, rateLimiter, stats, ResponseAnalyzer],
                context,
                activeConfig,
                stats,
                BugClustering,
                PostmanAdapter
            );

        } catch (error) {
            if (!(error instanceof StageAbortError)) {
                throw error;
            }
            // Abort handled, continue to post-processing
        }

        const clusters = BugClustering.clusterBySignature(allStagesResults);
        stats.bugClusters = clusters;
        printSummary(stats, ENGINE_VERSION, activeConfig, BugClustering, PostmanAdapter);
    } catch (error) {
        console.error('❌ FATAL ERROR:', error.message);
        if (error.stack && activeConfig.logDetailedSteps) {
            console.log(error.stack);
        }
        throw error;
    } finally {
        // ENHANCED: Clear global timeout
        if (globalTimeoutHandle) {
            clearTimeout(globalTimeoutHandle);
        }
        
        if (typeof pm !== 'undefined' && pm.collectionVariables) {
            try {
                pm.collectionVariables.set('engine_running', 'false');
            } catch (e) {}
        }
        if (typeof cleanupEngineContext !== 'undefined' && context) {
            cleanupEngineContext(context);
        }
    }
})().catch(err => {
    console.error('❌ UNHANDLED PROMISE REJECTION:', err);
});
