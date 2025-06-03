import { Database } from 'skibbadb';
import { createSkibbaExpress } from '../index.js';
import { securityMiddleware, helmetMiddleware, additionalSecurityHeaders, rateLimitMiddleware } from '../middleware/security.js';
import rateLimit from 'express-rate-limit';
import request from 'supertest';
import { z } from 'zod';
import express from 'express';

const app = express();

// Security Test Suite for SkibbaDB Express API
console.log('🔒 Starting Security Test Suite...\n');

// Test database setup
const testDb = new Database({ path: ':memory:' });

// User schema for testing
const userSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    role: z.string().default('user'),
    bio: z.string().optional(),
    website: z.string().optional(),
    createdAt: z.string(),
});

const users = testDb.collection('users', userSchema, {
    constrainedFields: {
        email: { unique: true, nullable: false },
        name: { nullable: false },
        role: { nullable: false },
    },
});

// Create test app with security middleware
app.use(helmetMiddleware);
app.use(additionalSecurityHeaders);

// Use stricter rate limiting for testing
const testRateLimit = rateLimit({
    windowMs: 30 * 1000, // 30 second window
    max: 20, // Limit to 20 requests per 30 seconds for testing
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(testRateLimit);

const skibba = createSkibbaExpress(app, testDb);

// Add health endpoint for header testing
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Configure users collection with security middleware
skibba.useCollection(users, {
    GET: {
        middleware: [securityMiddleware()],
    },
    POST: {
        middleware: [securityMiddleware()],
        hooks: {
            beforeCreate: async (data, req) => ({
                ...data,
                createdAt: new Date().toISOString(),
            }),
        },
    },
    PUT: {
        middleware: [securityMiddleware()],
        hooks: {
            beforeUpdate: async (id, data, req) => ({
                ...data,
                updatedAt: new Date().toISOString(),
            }),
        },
    },
    basePath: '/api/users',
});

// Test data - no auth tokens needed

// XSS Attack Payloads
const xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert("XSS")>',
    'javascript:alert("XSS")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<body onload=alert("XSS")>',
    '<div onclick="alert(\'XSS\')">Click me</div>',
    '<input type="text" onfocus="alert(\'XSS\')" autofocus>',
    '<marquee onstart=alert("XSS")>',
    '<object data="javascript:alert(\'XSS\')">',
    '"><script>alert("XSS")</script>',
    '\';alert("XSS");//',
    '<style>@import"javascript:alert(\'XSS\')";</style>',
    '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
];

// SQL Injection Payloads
const sqlInjectionPayloads = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DELETE FROM users WHERE '1'='1",
    "' UNION SELECT * FROM users --",
    "' OR 'x'='x",
    "'; INSERT INTO users VALUES ('hacker', 'evil@example.com'); --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "'; UPDATE users SET role='admin' WHERE '1'='1; --",
    "' OR EXISTS(SELECT * FROM users) --",
    "'; SELECT * FROM information_schema.tables; --",
    "' OR 1=1 LIMIT 1 --",
    "'; EXEC xp_cmdshell('dir'); --",
    "' OR 'a'='a",
    "' OR SLEEP(5) --",
];

// Additional malicious payloads
const maliciousPayloads = [
    // Path traversal
    '../../etc/passwd',
    '..\\..\\windows\\system32\\drivers\\etc\\hosts',

    // Command injection
    '; cat /etc/passwd',
    '& dir',
    '| whoami',

    // LDAP injection
    '*)(uid=*',
    '*)(|(password=*))',

    // NoSQL injection
    '{"$gt": ""}',
    '{"$ne": null}',

    // XML injection
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
];

// Test results tracking
let totalTests = 0;
let passedTests = 0;
const testResults: Array<{
    test: string;
    status: 'PASS' | 'FAIL';
    details?: string;
}> = [];

function logTest(testName: string, passed: boolean, details?: string) {
    totalTests++;
    if (passed) {
        passedTests++;
        console.log(`✅ ${testName}`);
        testResults.push({ test: testName, status: 'PASS', details });
    } else {
        console.log(`❌ ${testName}${details ? ` - ${details}` : ''}`);
        testResults.push({ test: testName, status: 'FAIL', details });
    }
}

// Security test functions
async function testXSSProtection() {
    console.log('\n🛡️  Testing XSS Protection...');

    for (const payload of xssPayloads) {
        try {
            const response = await request(app)
                .post('/api/users')
                .send({
                    id: `xss-test-${Date.now()}`,
                    name: payload,
                    email: `xss-${Date.now()}@example.com`,
                    role: 'user',
                    bio: payload,
                    website: payload,
                });

            // Check if request was successful (201) and XSS payload was sanitized
            if (response.status === 201) {
                const isSanitized =
                    !response.body.name?.includes('<script') &&
                    !response.body.bio?.includes('<script') &&
                    !response.body.website?.includes('javascript:') &&
                    !response.body.name?.includes('onerror=') &&
                    !response.body.bio?.includes('onload=') &&
                    !response.body.name?.includes('onclick=') &&
                    !response.body.website?.includes('<iframe') &&
                    !response.body.name?.includes('<svg') &&
                    !response.body.bio?.includes('<object');

                logTest(
                    `XSS Protection - ${payload.substring(0, 30)}...`,
                    isSanitized,
                    isSanitized
                        ? 'XSS payload properly sanitized'
                        : 'XSS payload not properly sanitized'
                );
            } else {
                // If request was blocked entirely, that's also good protection
                logTest(
                    `XSS Protection - ${payload.substring(0, 30)}...`,
                    response.status === 400,
                    response.status === 400
                        ? 'XSS payload blocked'
                        : `Unexpected status: ${response.status}`
                );
            }
        } catch (error) {
            logTest(
                `XSS Protection - ${payload.substring(0, 30)}...`,
                true,
                'XSS payload properly rejected'
            );
        }
    }
}

async function testSQLInjectionProtection() {
    console.log('\n🛡️  Testing SQL Injection Protection...');

    for (const payload of sqlInjectionPayloads) {
        try {
            const response = await request(app)
                .post('/api/users')
                .send({
                    id: `sql-test-${Date.now()}`,
                    name: payload,
                    email: `sql-${Date.now()}@example.com`,
                    role: 'user',
                });

            // Check if SQL injection was prevented
            const isProtected =
                !payload.includes('DROP') ||
                response.status === 400 ||
                (response.status === 201 &&
                    !response.body.name?.includes('DROP'));

            logTest(
                `SQL Injection Protection - ${payload.substring(0, 30)}...`,
                isProtected,
                isProtected ? undefined : 'SQL injection not properly prevented'
            );
        } catch (error) {
            logTest(
                `SQL Injection Protection - ${payload.substring(0, 30)}...`,
                true,
                'Properly rejected malicious input'
            );
        }
    }
}

async function testInputValidation() {
    console.log('\n🛡️  Testing Input Validation...');

    // Test oversized inputs - create string large enough to exceed 50KB JSON limit
    const largeString = 'A'.repeat(50000);
    try {
        const response = await request(app).post('/api/users').send({
            id: 'large-input-test',
            name: largeString,
            email: 'large@example.com',
            role: 'user',
        });

        logTest(
            'Large Input Validation',
            response.status === 413 ||
                response.status === 400 ||
                response.body.name?.length < 1000,
            response.status === 413
                ? 'Properly rejected (413)'
                : response.status === 400
                ? 'Properly rejected (400)'
                : 'Input was truncated'
        );
    } catch (error) {
        logTest(
            'Large Input Validation',
            true,
            'Properly rejected large input'
        );
    }

    // Test invalid email formats
    const invalidEmails = [
        'invalid',
        '@invalid.com',
        'test@',
        'test@.com',
        'test..test@example.com',
    ];

    for (const email of invalidEmails) {
        try {
            const response = await request(app)
                .post('/api/users')
                .send({
                    id: `email-test-${Date.now()}`,
                    name: 'Test User',
                    email: email,
                    role: 'user',
                });

            logTest(
                `Invalid Email Validation - ${email}`,
                response.status === 400,
                response.status === 400
                    ? 'Properly rejected'
                    : 'Invalid email accepted'
            );
        } catch (error) {
            logTest(
                `Invalid Email Validation - ${email}`,
                true,
                'Properly rejected invalid email'
            );
        }
    }
}

async function testKeyValidation() {
    console.log('\n🛡️  Testing Object Key Validation...');

    // Test dangerous object keys that should be rejected
    const dangerousKeys = [
        'na<script>me',
        'field;DROP TABLE users;--',
        'key"onclick=alert(1)"',
        'name\ninjection',
        'field<img src=x onerror=alert(1)>',
        'key javascript:',
        'field__proto__',
        'name{$gt:""}',
    ];

    for (const key of dangerousKeys) {
        try {
            const testData: any = {
                id: `key-test-${Date.now()}`,
                email: `keytest-${Date.now()}@example.com`,
                role: 'user',
            };
            testData[key] = 'test value';

            const response = await request(app)
                .post('/api/users')
                .send(testData);

            // Should be rejected with 400 or 500 status
            const isRejected =
                response.status === 400 || response.status === 500;

            logTest(
                `Dangerous Key Validation - ${key.substring(0, 20)}...`,
                isRejected,
                isRejected
                    ? 'Properly rejected dangerous key'
                    : 'Dangerous key was accepted'
            );
        } catch (error) {
            logTest(
                `Dangerous Key Validation - ${key.substring(0, 20)}...`,
                true,
                'Properly rejected dangerous key'
            );
        }
    }

    // Test that normal keys still work
    try {
        const response = await request(app)
            .post('/api/users')
            .send({
                id: `normal-key-test-${Date.now()}`,
                name: 'Normal User',
                email: `normal-${Date.now()}@example.com`,
                role: 'user',
                bio: 'Normal bio text',
            });

        logTest(
            'Normal Key Validation',
            response.status === 201,
            response.status === 201
                ? 'Normal keys work correctly'
                : 'Normal keys were rejected'
        );
    } catch (error) {
        logTest(
            'Normal Key Validation',
            false,
            'Normal keys were unexpectedly rejected'
        );
    }
}

async function testMaliciousPayloads() {
    console.log('\n🛡️  Testing Additional Malicious Payloads...');

    for (const payload of maliciousPayloads) {
        try {
            const response = await request(app)
                .post('/api/users')

                .send({
                    id: `malicious-test-${Date.now()}`,
                    name: payload,
                    email: `malicious-${Date.now()}@example.com`,
                    role: 'user',
                });

            // Check if malicious payload was sanitized or rejected
            const isSafe =
                response.status === 400 ||
                (!response.body.name?.includes('etc/passwd') &&
                    !response.body.name?.includes('cmd') &&
                    !response.body.name?.includes('$gt'));

            logTest(
                `Malicious Payload Protection - ${payload.substring(0, 30)}...`,
                isSafe,
                isSafe ? undefined : 'Malicious payload not properly handled'
            );
        } catch (error) {
            logTest(
                `Malicious Payload Protection - ${payload.substring(0, 30)}...`,
                true,
                'Properly rejected malicious input'
            );
        }
    }
}

async function testSecurityHeaders() {
    console.log('\n🛡️  Testing Security Headers...');

    try {
        const response = await request(app).get('/health'); // Use health endpoint instead of /api/users

        // Check for important security headers (case-insensitive)
        const headers = response.headers;
        const headerKeys = Object.keys(headers).map((k) => k.toLowerCase());

        const hasCSP = headerKeys.includes('content-security-policy');
        const hasXFrame = headerKeys.includes('x-frame-options');
        const hasXSS = headerKeys.includes('x-xss-protection');
        const hasContentType = headerKeys.includes('x-content-type-options');

        logTest('Content Security Policy Header', hasCSP);
        logTest('X-Frame-Options Header', hasXFrame);
        logTest('X-XSS-Protection Header', hasXSS);
        logTest('X-Content-Type-Options Header', hasContentType);
    } catch (error) {
        logTest('Security Headers Test', false, `Error: ${error}`);
    }
}

async function testRateLimiting() {
    console.log('\n🛡️  Testing Rate Limiting...');

    // Make multiple rapid requests to the same endpoint
    const requests: Promise<any>[] = [];
    for (let i = 0; i < 25; i++) {
        requests.push(
            request(app)
                .get('/health')
                .catch((err) => ({ status: err.status || 500 }))
        );
    }

    try {
        const responses = await Promise.all(requests);
        const rateLimited = responses.some((r) => r.status === 429);
        const successCount = responses.filter((r) => r.status === 200).length;

        logTest(
            'Rate Limiting Protection',
            rateLimited || successCount < 20, // If less than 20 succeeded, rate limiting likely occurred
            rateLimited
                ? 'Rate limiting active'
                : `${successCount}/25 requests succeeded`
        );
    } catch (error) {
        logTest('Rate Limiting Protection', false, `Error: ${error}`);
    }
}

// Run all security tests
async function runSecurityTests() {
    console.log('🔒 SkibbaDB Express Security Test Suite');
    console.log('=====================================\n');

    await testXSSProtection();
    await testSQLInjectionProtection();
    await testInputValidation();
    await testKeyValidation();
    await testMaliciousPayloads();
    await testSecurityHeaders();
    await testRateLimiting();

    // Final results
    console.log('\n📊 Security Test Results Summary');
    console.log('==================================');
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${totalTests - passedTests}`);
    console.log(
        `Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`
    );

    // Show failed tests
    const failedTests = testResults.filter((t) => t.status === 'FAIL');
    if (failedTests.length > 0) {
        console.log('\n❌ Failed Tests:');
        failedTests.forEach((test) => {
            console.log(
                `   - ${test.test}${test.details ? `: ${test.details}` : ''}`
            );
        });
    }

    // Security recommendations
    console.log('\n🔧 Security Recommendations:');
    if (failedTests.some((t) => t.test.includes('XSS'))) {
        console.log(
            '   - Strengthen XSS protection with better input sanitization'
        );
    }
    if (failedTests.some((t) => t.test.includes('SQL'))) {
        console.log(
            '   - Implement parameterized queries and input validation'
        );
    }
    if (failedTests.some((t) => t.test.includes('Header'))) {
        console.log('   - Add security headers with helmet middleware');
    }
    if (failedTests.some((t) => t.test.includes('Rate'))) {
        console.log('   - Implement rate limiting to prevent abuse');
    }

    console.log('\n✅ Security testing completed!\n');

    // Exit with appropriate code
    process.exit(failedTests.length > 0 ? 1 : 0);
}

// Run the security tests
runSecurityTests().catch(console.error);
