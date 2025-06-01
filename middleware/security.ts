import { type Request, type Response, type NextFunction } from 'express';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// Create a DOMPurify instance for server-side use
const window = new JSDOM('').window;
const purify = DOMPurify(window as any);

// SQL injection patterns to detect and block
const SQL_INJECTION_PATTERNS = [
    // Classic SQL injection patterns
    /(\bor\b|\band\b)\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+['"`]?/i,
    /union\s+select/i,
    /select\s+\*\s+from/i,
    /drop\s+table/i,
    /delete\s+from/i,
    /update\s+\w+\s+set/i,
    /insert\s+into/i,
    /exec\s*\(/i,
    /execute\s*\(/i,
    /script\s*>/i,
    // SQL comments
    /--/,
    /\/\*/,
    /\*\//,
    // SQL string manipulation
    /;\s*(drop|delete|update|insert|create|alter|exec)/i,
    // Hex encoding attempts
    /0x[0-9a-f]+/i,
    // UNION attacks
    /\bunion\b.*\bselect\b/i,
    // Boolean based injection
    /'\s*(or|and)\s+'?\d+'?\s*[=><!]/i,
    // Time based injection
    /waitfor\s+delay/i,
    /sleep\s*\(/i,
    /benchmark\s*\(/i,
];

// Additional malicious payload patterns
const MALICIOUS_PAYLOAD_PATTERNS = [
    // Path traversal attacks
    /\.\.[\/\\]/,
    /\.\.%2f/i,
    /\.\.%5c/i,
    /\.\.\\/,
    /\.\.\//,

    // Command injection
    /;\s*(cat|ls|dir|type|more|head|tail|grep|find|whoami|id|pwd|uname)/i,
    /&\s*(cat|ls|dir|type|more|head|tail|grep|find|whoami|id|pwd|uname)/i,
    /\|\s*(cat|ls|dir|type|more|head|tail|grep|find|whoami|id|pwd|uname)/i,
    /`[^`]*`/, // Backtick command execution
    /\$\([^)]*\)/, // Command substitution

    // NoSQL injection
    /\{\s*['"]\$gt['"]?\s*:\s*['"]/i,
    /\{\s*['"]\$ne['"]?\s*:\s*/i,
    /\{\s*['"]\$regex['"]?\s*:\s*/i,
    /\{\s*['"]\$where['"]?\s*:\s*/i,
    /\{\s*['"]\$in['"]?\s*:\s*\[/i,
    /\{\s*['"]\$nin['"]?\s*:\s*\[/i,

    // LDAP injection
    /\(\s*\|/,
    /\)\s*\(/,
    /\*\)\s*\(/,

    // Server-side includes
    /<!--\s*#/,

    // File inclusion
    /php:\/\//i,
    /file:\/\//i,
    /data:\/\//i,

    // XML injection
    /<!ENTITY/i,
    /<!DOCTYPE.*\[/i,
];

// XSS patterns to detect and sanitize
const XSS_PATTERNS = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /<object[^>]*>.*?<\/object>/gi,
    /<embed[^>]*>/gi,
    /<link[^>]*>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload=/gi,
    /onerror=/gi,
    /onclick=/gi,
    /onmouseover=/gi,
    /onfocus=/gi,
    /onblur=/gi,
    /onchange=/gi,
    /onsubmit=/gi,
];

/**
 * Sanitizes input to prevent XSS attacks
 */
export function sanitizeInput(input: any): any {
    if (typeof input === 'string') {
        // First, use DOMPurify to clean the input
        let sanitized = purify.sanitize(input, {
            ALLOWED_TAGS: [], // No HTML tags allowed
            ALLOWED_ATTR: [], // No attributes allowed
            KEEP_CONTENT: true, // Keep text content
        });

        // Additional manual sanitization for edge cases
        sanitized = sanitized
            .replace(/javascript:/gi, '')
            .replace(/vbscript:/gi, '')
            .replace(/data:/gi, '')
            .replace(/\bon\w+\s*=/gi, '') // Remove event handlers
            .replace(/<[^>]*>/g, ''); // Remove any remaining HTML tags

        return sanitized;
    }

    if (Array.isArray(input)) {
        return input.map(sanitizeInput);
    }

    if (input && typeof input === 'object') {
        const sanitized: any = {};
        for (const [key, value] of Object.entries(input)) {
            // Sanitize both keys and values
            const sanitizedKey = sanitizeInput(key);
            const sanitizedValue = sanitizeInput(value);
            sanitized[sanitizedKey] = sanitizedValue;
        }
        return sanitized;
    }

    return input;
}

/**
 * Detects potential SQL injection attempts
 */
export function detectSQLInjection(input: any): boolean {
    if (typeof input === 'string') {
        return SQL_INJECTION_PATTERNS.some((pattern) => pattern.test(input));
    }

    if (Array.isArray(input)) {
        return input.some(detectSQLInjection);
    }

    if (input && typeof input === 'object') {
        return Object.entries(input).some(
            ([key, value]) =>
                detectSQLInjection(key) || detectSQLInjection(value)
        );
    }

    return false;
}

/**
 * Detects potential malicious payloads (path traversal, command injection, NoSQL injection, etc.)
 */
export function detectMaliciousPayload(input: any): boolean {
    if (typeof input === 'string') {
        return MALICIOUS_PAYLOAD_PATTERNS.some((pattern) =>
            pattern.test(input)
        );
    }

    if (Array.isArray(input)) {
        return input.some(detectMaliciousPayload);
    }

    if (input && typeof input === 'object') {
        // Convert object to JSON string to detect NoSQL injection patterns
        const jsonString = JSON.stringify(input);
        if (
            MALICIOUS_PAYLOAD_PATTERNS.some((pattern) =>
                pattern.test(jsonString)
            )
        ) {
            return true;
        }

        return Object.entries(input).some(
            ([key, value]) =>
                detectMaliciousPayload(key) || detectMaliciousPayload(value)
        );
    }

    return false;
}

/**
 * Detects potential XSS attempts
 */
export function detectXSS(input: any): boolean {
    if (typeof input === 'string') {
        return XSS_PATTERNS.some((pattern) => pattern.test(input));
    }

    if (Array.isArray(input)) {
        return input.some(detectXSS);
    }

    if (input && typeof input === 'object') {
        return Object.entries(input).some(
            ([key, value]) => detectXSS(key) || detectXSS(value)
        );
    }

    return false;
}

/**
 * Comprehensive security middleware that sanitizes input and detects attacks
 */
export const securityMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    try {
        // Check input size limits first - reject large inputs rather than truncate
        const requestBody = JSON.stringify(req.body || {});
        const requestQuery = JSON.stringify(req.query || {});

        if (requestBody.length > 50000) {
            // 50KB limit for request body
            console.warn(
                `🚨 Large request body rejected from ${req.ip}: ${requestBody.length} bytes`
            );
            res.status(413).json({
                error: 'Request too large',
                message: 'Request body exceeds size limit',
            });
            return;
        }

        if (requestQuery.length > 10000) {
            // 10KB limit for query params
            console.warn(
                `🚨 Large query parameters rejected from ${req.ip}: ${requestQuery.length} bytes`
            );
            res.status(413).json({
                error: 'Request too large',
                message: 'Query parameters exceed size limit',
            });
            return;
        }

        // Store original body for XSS detection before sanitization
        const originalBody = req.body
            ? JSON.parse(JSON.stringify(req.body))
            : null;

        // Check for various types of attacks in user-controlled data
        const userInputs = [req.body, req.query, req.params];

        // Only check specific suspicious headers, not all headers
        const suspiciousHeaders = {
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-real-ip': req.headers['x-real-ip'],
            referer: req.headers['referer'],
        };

        // Check for SQL injection
        for (const input of userInputs) {
            if (input && detectSQLInjection(input)) {
                console.warn(
                    `🚨 SQL Injection attempt detected from ${req.ip}:`,
                    input
                );
                res.status(400).json({
                    error: 'Security violation',
                    message: 'Malicious input detected and blocked',
                });
                return;
            }
        }

        // Check for malicious payloads (path traversal, command injection, NoSQL injection, etc.)
        for (const input of userInputs) {
            if (input && detectMaliciousPayload(input)) {
                console.warn(
                    `🚨 Malicious payload detected from ${req.ip}:`,
                    input
                );
                res.status(400).json({
                    error: 'Security violation',
                    message: 'Malicious payload detected and blocked',
                });
                return;
            }
        }

        // Check suspicious headers separately
        if (
            detectSQLInjection(suspiciousHeaders) ||
            detectMaliciousPayload(suspiciousHeaders)
        ) {
            console.warn(
                `🚨 Malicious content in headers from ${req.ip}:`,
                suspiciousHeaders
            );
            res.status(400).json({
                error: 'Security violation',
                message: 'Malicious input detected in headers',
            });
            return;
        }

        // Check for XSS in original data before sanitization
        if (originalBody && detectXSS(originalBody)) {
            console.warn(
                `🚨 XSS attempt detected and will be sanitized from ${req.ip}:`,
                originalBody
            );
        }

        // Sanitize request body to prevent XSS
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeInput(req.body);
        }

        // Sanitize query parameters - store in a new property since req.query is readonly
        if (req.query && typeof req.query === 'object') {
            // Create a new object with sanitized query parameters
            const sanitizedQuery = sanitizeInput(req.query);
            // Override the getter to return sanitized values
            Object.defineProperty(req, 'query', {
                value: sanitizedQuery,
                writable: false,
                enumerable: true,
                configurable: true,
            });
        }

        next();
    } catch (error) {
        console.error('Security middleware error:', error);
        res.status(500).json({
            error: 'Internal security error',
            message: 'Unable to process request',
        });
    }
};

/**
 * Rate limiting middleware to prevent brute force attacks
 */
export const rateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.warn(`🚨 Rate limit exceeded for ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests',
            message: 'Rate limit exceeded. Please try again later.',
        });
    },
});

/**
 * Strict rate limiting for write operations (POST, PUT, DELETE)
 */
export const strictRateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30, // Limit each IP to 30 write requests per windowMs
    message: {
        error: 'Too many requests',
        message: 'Write operation rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'GET', // Only apply to write operations
    handler: (req, res) => {
        console.warn(`🚨 Write operation rate limit exceeded for ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests',
            message:
                'Write operation rate limit exceeded. Please try again later.',
        });
    },
});

/**
 * Helmet middleware for additional security headers
 */
export const helmetMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false, // Allow for API usage
});

/**
 * Additional security headers middleware
 */
export const additionalSecurityHeaders = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    // Add additional security headers that helmet might not cover or to ensure they're set
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY'); // Explicitly set this header
    res.setHeader('X-XSS-Protection', '1; mode=block'); // Explicitly set this header
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
        'Permissions-Policy',
        'geolocation=(), microphone=(), camera=()'
    );
    res.setHeader(
        'Cache-Control',
        'no-store, no-cache, must-revalidate, private'
    );
    res.setHeader('Pragma', 'no-cache');

    next();
};

/**
 * Input validation middleware specifically for user data
 */
export const validateUserInput = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    if (req.method === 'POST' || req.method === 'PUT') {
        const { name, email, role } = req.body;

        // Additional validation for user-specific fields
        if (name && typeof name === 'string') {
            // Prevent extremely long names that could be used for attacks
            if (name.length > 100) {
                res.status(413).json({
                    error: 'Input too large',
                    message: 'Name must be less than 100 characters',
                });
                return;
            }

            // Ensure name doesn't contain suspicious characters
            if (!/^[a-zA-Z0-9\s\-_.]+$/.test(name)) {
                res.status(400).json({
                    error: 'Validation failed',
                    message: 'Name contains invalid characters',
                });
                return;
            }
        }

        if (email && typeof email === 'string') {
            // Basic email validation (Zod will do more comprehensive validation)
            if (email.length > 254) {
                // RFC 5321 limit
                res.status(413).json({
                    error: 'Input too large',
                    message: 'Email address is too long',
                });
                return;
            }

            // Basic email format validation
            const emailRegex =
                /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!emailRegex.test(email)) {
                res.status(400).json({
                    error: 'Validation failed',
                    message: 'Invalid email format',
                });
                return;
            }

            // Check for common email injection patterns
            const suspiciousEmailPatterns = [
                /\.\./, // Double dots
                /@.*@/, // Multiple @ symbols
                /[<>]/, // Angle brackets
                /[\r\n]/, // Newlines
            ];

            if (
                suspiciousEmailPatterns.some((pattern) => pattern.test(email))
            ) {
                res.status(400).json({
                    error: 'Validation failed',
                    message: 'Email contains invalid characters',
                });
                return;
            }
        }

        if (role && typeof role === 'string') {
            // Restrict roles to known values
            const allowedRoles = ['user', 'admin', 'moderator'];
            if (!allowedRoles.includes(role)) {
                res.status(400).json({
                    error: 'Validation failed',
                    message: 'Invalid role specified',
                });
                return;
            }
        }
    }

    next();
};
