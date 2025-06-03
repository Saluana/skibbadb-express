import { type Request, type Response, type NextFunction } from 'express';
import xss from 'xss';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// Configure XSS with a strict allowlist for performance
const xssOptions = {
    allowList: {}, // No HTML tags allowed by default
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style'],
    css: false, // Disable CSS parsing for performance
};

// Simple forbidden character sets for security threat detection
const FORBIDDEN_CHARS = {
    // Characters that are never allowed in user input (XSS prevention)
    NEVER_ALLOWED: ['<', '>', '{', '}', '\\', '`', '$'],

    // SQL-related characters that require validation
    SQL_SUSPICIOUS: [
        ';',
        '--',
        '/*',
        '*/',
        'union',
        'select',
        'drop',
        'delete',
        'insert',
        'update',
    ],

    // Script-related strings (XSS prevention)
    SCRIPT_SUSPICIOUS: ['javascript:', 'vbscript:', 'data:', 'file:', 'php:'],

    // Path traversal patterns
    PATH_TRAVERSAL: [
        '../',
        '..\\',
        '../',
        '..\\\\',
        '/etc/',
        '\\windows\\',
        '/passwd',
        '/hosts',
    ],
};

/**
 * Configuration for which fields need sanitization
 * Only free-text fields that could contain user HTML/script content need sanitization
 */
export interface SanitizationConfig {
    // Fields that contain free-text content requiring XSS sanitization
    freeTextFields?: string[];
    // Fields that should only be validated but not sanitized (e.g., structured data)
    structuredFields?: string[];
    // Whether to sanitize all string fields by default (performance impact)
    sanitizeAllStrings?: boolean;
}

/**
 * Default sanitization config for common field patterns
 */
const DEFAULT_SANITIZATION_CONFIG: SanitizationConfig = {
    freeTextFields: [
        'description',
        'bio',
        'content',
        'message',
        'comment',
        'note',
        'text',
        'body',
        'summary',
        'details',
        'review',
        'feedback',
        'caption',
    ],
    structuredFields: [
        'id',
        'email',
        'url',
        'name',
        'title',
        'role',
        'status',
        'type',
        'createdAt',
        'updatedAt',
        'age',
        'count',
        'price',
        'phone',
    ],
    sanitizeAllStrings: false,
};

/**
 * Lightweight string sanitization for free-text fields only
 */
function sanitizeString(input: string): string {
    // Use lightweight xss package instead of DOMPurify + JSDOM
    let sanitized = xss(input, xssOptions);

    // Additional lightweight sanitization for common attack vectors
    sanitized = sanitized
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '')
        .replace(/data:/gi, '')
        .replace(/\bon\w+\s*=/gi, ''); // Remove event handlers

    return sanitized;
}

/**
 * Optimized sanitization that only processes free-text fields
 * Performance optimization: O(N) instead of O(N × regexes) for the entire object tree
 */
export function sanitizeInput(
    input: any,
    config: SanitizationConfig = DEFAULT_SANITIZATION_CONFIG
): any {
    return sanitizeInputWithPath(input, [], config);
}

/**
 * Internal function that tracks the path to determine field types
 */
function sanitizeInputWithPath(
    input: any,
    path: string[],
    config: SanitizationConfig
): any {
    if (typeof input === 'string') {
        const currentField = path[path.length - 1];

        // For array elements, use the parent field name for context
        const fieldName = isNaN(Number(currentField))
            ? currentField
            : path[path.length - 2];

        // Only sanitize if it's a known free-text field or if sanitizeAllStrings is enabled
        const isFreeTextField = config.freeTextFields?.includes(fieldName);
        const isStructuredField = config.structuredFields?.includes(fieldName);

        if (
            isFreeTextField ||
            (config.sanitizeAllStrings && !isStructuredField)
        ) {
            return sanitizeString(input);
        }

        // For structured fields, return as-is (validation happens elsewhere)
        return input;
    }

    if (Array.isArray(input)) {
        // Pass the current path so array elements inherit parent field context
        return input.map((item, index) =>
            sanitizeInputWithPath(item, [...path, index.toString()], config)
        );
    }

    if (input && typeof input === 'object') {
        const sanitized: any = {};
        for (const [key, value] of Object.entries(input)) {
            // Validate object keys for XSS/injection threats only
            if (typeof key === 'string') {
                const keyValidation = validateObjectKey(key);
                if (!keyValidation.isValid) {
                    throw new Error(
                        `Invalid object key "${key}": ${keyValidation.reason}`
                    );
                }
            }
            // Recursively process values with updated path
            const sanitizedValue = sanitizeInputWithPath(
                value,
                [...path, key],
                config
            );
            sanitized[key] = sanitizedValue; // Use original key, not sanitized
        }
        return sanitized;
    }

    return input;
}

/**
 * Legacy function for backward compatibility - recursively sanitizes everything
 * @deprecated Use sanitizeInput with proper field configuration instead
 * WARNING: This function still sanitizes keys, which can cause property name collisions
 */
export function sanitizeInputRecursive(input: any): any {
    if (typeof input === 'string') {
        return sanitizeString(input);
    }

    if (Array.isArray(input)) {
        return input.map(sanitizeInputRecursive);
    }

    if (input && typeof input === 'object') {
        const sanitized: any = {};
        for (const [key, value] of Object.entries(input)) {
            // WARNING: This still sanitizes keys for backward compatibility
            // Consider migrating to sanitizeInput() for safer key handling
            const sanitizedKey = sanitizeInputRecursive(key);
            const sanitizedValue = sanitizeInputRecursive(value);
            sanitized[sanitizedKey] = sanitizedValue;
        }
        return sanitized;
    }

    return input;
}

/**
 * Sanitizes rich text content with a limited allowlist for specific use cases
 * Only use this for fields that explicitly require HTML content
 */
export function sanitizeRichText(input: string): string {
    const richTextOptions = {
        allowList: {
            // Only allow safe formatting tags
            p: [],
            br: [],
            strong: [],
            em: [],
            b: [],
            i: [],
            u: [],
            ul: [],
            ol: [],
            li: [],
            h1: [],
            h2: [],
            h3: [],
            h4: [],
            h5: [],
            h6: [],
        },
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
        css: false, // Still disable CSS for performance
    };

    return xss(input, richTextOptions);
}

/**
 * Validates input for XSS and SQL injection attempts only
 */
export function validateSecurityThreats(input: any): {
    isValid: boolean;
    reason?: string;
} {
    if (typeof input === 'string') {
        const lowerInput = input.toLowerCase();

        // Check for XSS-related patterns
        if (
            FORBIDDEN_CHARS.NEVER_ALLOWED.some((char) => input.includes(char))
        ) {
            return { isValid: false, reason: 'Contains forbidden characters' };
        }

        // Check for SQL injection patterns
        if (
            FORBIDDEN_CHARS.SQL_SUSPICIOUS.some((term) =>
                lowerInput.includes(term)
            )
        ) {
            return {
                isValid: false,
                reason: 'Contains SQL-suspicious content',
            };
        }

        // Check for script injection patterns
        if (
            FORBIDDEN_CHARS.SCRIPT_SUSPICIOUS.some((term) =>
                lowerInput.includes(term)
            )
        ) {
            return {
                isValid: false,
                reason: 'Contains script-suspicious content',
            };
        }

        // Check for path traversal patterns
        if (
            FORBIDDEN_CHARS.PATH_TRAVERSAL.some((term) =>
                lowerInput.includes(term)
            )
        ) {
            return {
                isValid: false,
                reason: 'Contains path traversal patterns',
            };
        }

        return { isValid: true };
    }

    if (Array.isArray(input)) {
        for (const item of input) {
            const result = validateSecurityThreats(item);
            if (!result.isValid) {
                return result;
            }
        }
        return { isValid: true };
    }

    if (input && typeof input === 'object') {
        for (const [key, value] of Object.entries(input)) {
            // Check keys for dangerous patterns
            const keyResult = validateSecurityThreats(key);
            if (!keyResult.isValid) {
                return {
                    isValid: false,
                    reason: `Invalid key: ${keyResult.reason}`,
                };
            }

            // Check values for dangerous patterns
            const valueResult = validateSecurityThreats(value);
            if (!valueResult.isValid) {
                return valueResult;
            }
        }
        return { isValid: true };
    }

    return { isValid: true };
}

/**
 * Simple validation for object keys to prevent dangerous patterns
 */
export function validateObjectKey(key: string): {
    isValid: boolean;
    reason?: string;
} {
    if (typeof key !== 'string') {
        return { isValid: false, reason: 'Object keys must be strings' };
    }

    // Check for dangerous key patterns that could indicate XSS or injection attempts
    const dangerousKeyPatterns = [
        /__proto__/,
        /constructor/,
        /prototype/,
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i, // onclick, onload, etc.
        /[<>{}]/,
        /[;'"]/,
        /\$\w+/, // MongoDB-style operators
        /\n|\r/, // Newlines
    ];

    for (const pattern of dangerousKeyPatterns) {
        if (pattern.test(key)) {
            return {
                isValid: false,
                reason: 'Key contains dangerous characters or patterns',
            };
        }
    }

    return { isValid: true };
}

/**
 * Security middleware focused on XSS and SQL injection protection
 * Input validation (email, formats, etc.) should be handled by Zod or application layer
 */
export const securityMiddleware =
    (options?: {
        maxBodySize?: number; // Max body size in bytes (default: 50KB)
        maxQuerySize?: number; // Max query size in bytes (default: 10KB)
    }) =>
    (req: Request, res: Response, next: NextFunction): void => {
        const maxBodySize = options?.maxBodySize || 50000; // 50KB default
        const maxQuerySize = options?.maxQuerySize || 10000; // 10KB default

        try {
            // Check input size limits first - reject large inputs rather than truncate
            const requestBody = JSON.stringify(req.body || {});
            const requestQuery = JSON.stringify(req.query || {});

            if (requestBody.length > maxBodySize) {
                console.warn(
                    `🚨 Large request body rejected from ${req.ip}: ${requestBody.length} bytes (limit: ${maxBodySize})`
                );
                res.status(413).json({
                    error: 'Request too large',
                    message: 'Request body exceeds size limit',
                });
                return;
            }

            if (requestQuery.length > maxQuerySize) {
                console.warn(
                    `🚨 Large query parameters rejected from ${req.ip}: ${requestQuery.length} bytes (limit: ${maxQuerySize})`
                );
                res.status(413).json({
                    error: 'Request too large',
                    message: 'Query parameters exceed size limit',
                });
                return;
            }

            // Fast security threat validation for all user inputs
            const userInputs = [
                { data: req.body, name: 'body' },
                { data: req.query, name: 'query' },
                { data: req.params, name: 'params' },
            ];

            // Only check specific suspicious headers, not all headers
            const suspiciousHeaders = {
                'x-forwarded-for': req.headers['x-forwarded-for'],
                'x-real-ip': req.headers['x-real-ip'],
                referer: req.headers['referer'],
            };

            // Validate all user inputs for XSS and SQL injection threats only
            for (const { data, name } of userInputs) {
                if (data) {
                    const validation = validateSecurityThreats(data);
                    if (!validation.isValid) {
                        console.warn(
                            `🚨 Security threat detected in ${name} from ${req.ip}:`,
                            { reason: validation.reason }
                        );
                        res.status(400).json({
                            error: 'Security violation',
                            message: `Security threat detected in ${name}: ${validation.reason}`,
                        });
                        return;
                    }
                }
            }

            // Check suspicious headers for security threats
            const headerValidation = validateSecurityThreats(suspiciousHeaders);
            if (!headerValidation.isValid) {
                console.warn(
                    `🚨 Security threat detected in headers from ${req.ip}:`,
                    { reason: headerValidation.reason }
                );
                res.status(400).json({
                    error: 'Security violation',
                    message: 'Security threat detected in headers',
                });
                return;
            }

            // Lightweight XSS sanitization using allowlist approach (no DOM construction)
            if (req.body && typeof req.body === 'object') {
                try {
                    req.body = sanitizeInput(req.body);
                } catch (sanitizeError: any) {
                    console.warn(
                        `🚨 Dangerous object key detected in request body from ${req.ip}:`,
                        { error: sanitizeError.message }
                    );
                    res.status(400).json({
                        error: 'Security violation',
                        message:
                            sanitizeError.message ||
                            'Invalid object key detected',
                    });
                    return;
                }
            }

            // Lightweight sanitization of query parameters (no DOM construction)
            if (req.query && typeof req.query === 'object') {
                try {
                    // Create a new object with sanitized query parameters
                    const sanitizedQuery = sanitizeInput(req.query);
                    // Override the getter to return sanitized values
                    Object.defineProperty(req, 'query', {
                        value: sanitizedQuery,
                        writable: false,
                        enumerable: true,
                        configurable: true,
                    });
                } catch (sanitizeError: any) {
                    console.warn(
                        `🚨 Dangerous object key detected in query parameters from ${req.ip}:`,
                        { error: sanitizeError.message }
                    );
                    res.status(400).json({
                        error: 'Security violation',
                        message:
                            sanitizeError.message ||
                            'Invalid object key detected',
                    });
                    return;
                }
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
 * Basic security validation middleware for user data (legacy)
 * Note: This is a minimal version. Input validation should be handled by Zod schemas.
 * This only checks for basic security threats.
 */
export const validateUserInput = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    if (req.method === 'POST' || req.method === 'PUT') {
        // Only check for obvious security threats in the request body
        const validation = validateSecurityThreats(req.body);
        if (!validation.isValid) {
            console.warn(
                `🚨 Security threat detected in user input from ${req.ip}:`,
                { reason: validation.reason }
            );
            res.status(400).json({
                error: 'Security violation',
                message: `Security threat detected: ${validation.reason}`,
            });
            return;
        }
    }

    next();
};
