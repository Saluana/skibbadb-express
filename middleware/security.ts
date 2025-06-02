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

// Whitelist approach for allowed characters in different contexts
const ALLOWED_PATTERNS = {
    // Safe alphanumeric with common punctuation for general text
    GENERAL_TEXT: /^[a-zA-Z0-9\s\-_.@+,!?()[\]{}:;'"\/\n\r]*$/,
    
    // Strict alphanumeric only for identifiers
    IDENTIFIER: /^[a-zA-Z0-9_-]+$/,
    
    // Email pattern (basic but secure)
    EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    
    // URL pattern (basic but secure)
    URL: /^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]*)?$/,
    
    // Numeric values
    NUMBER: /^-?\d+(?:\.\d+)?$/,
    
    // Boolean values
    BOOLEAN: /^(true|false)$/i,
    
    // Date/time ISO format
    DATETIME: /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)?$/,
};

// Simple forbidden character sets (much faster than complex regex)
const FORBIDDEN_CHARS = {
    // Characters that are never allowed in user input
    NEVER_ALLOWED: ['<', '>', '{', '}', '\\', '`', '$'],
    
    // SQL-related characters that require validation
    SQL_SUSPICIOUS: [';', '--', '/*', '*/', 'union', 'select', 'drop', 'delete', 'insert', 'update'],
    
    // Script-related strings
    SCRIPT_SUSPICIOUS: ['javascript:', 'vbscript:', 'data:', 'file:', 'php:'],
};

/**
 * Sanitizes input to prevent XSS attacks using lightweight xss package
 * Validates on input, expects output escaping to be handled by frontend
 */
export function sanitizeInput(input: any): any {
    if (typeof input === 'string') {
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
 * Sanitizes rich text content with a limited allowlist for specific use cases
 * Only use this for fields that explicitly require HTML content
 */
export function sanitizeRichText(input: string): string {
    const richTextOptions = {
        allowList: {
            // Only allow safe formatting tags
            'p': [],
            'br': [],
            'strong': [],
            'em': [],
            'b': [],
            'i': [],
            'u': [],
            'ul': [],
            'ol': [],
            'li': [],
            'h1': [],
            'h2': [],
            'h3': [],
            'h4': [],
            'h5': [],
            'h6': [],
        },
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
        css: false, // Still disable CSS for performance
    };

    return xss(input, richTextOptions);
}

/**
 * Validates input using whitelist approach - much faster than regex blacklists
 */
export function validateInputSafety(input: any, context: 'general' | 'identifier' | 'email' | 'url' | 'number' = 'general'): { isValid: boolean; reason?: string } {
    if (typeof input === 'string') {
        // Fast character-based validation first
        const lowerInput = input.toLowerCase();
        
        // Check for never-allowed characters
        if (FORBIDDEN_CHARS.NEVER_ALLOWED.some(char => input.includes(char))) {
            return { isValid: false, reason: 'Contains forbidden characters' };
        }
        
        // Check for SQL-suspicious strings (simple includes, not regex)
        if (FORBIDDEN_CHARS.SQL_SUSPICIOUS.some(term => lowerInput.includes(term))) {
            return { isValid: false, reason: 'Contains SQL-suspicious content' };
        }
        
        // Check for script-suspicious strings
        if (FORBIDDEN_CHARS.SCRIPT_SUSPICIOUS.some(term => lowerInput.includes(term))) {
            return { isValid: false, reason: 'Contains script-suspicious content' };
        }
        
        // Context-specific validation with simple patterns
        switch (context) {
            case 'identifier':
                if (!ALLOWED_PATTERNS.IDENTIFIER.test(input)) {
                    return { isValid: false, reason: 'Invalid identifier format' };
                }
                break;
            case 'email':
                if (!ALLOWED_PATTERNS.EMAIL.test(input)) {
                    return { isValid: false, reason: 'Invalid email format' };
                }
                break;
            case 'url':
                if (!ALLOWED_PATTERNS.URL.test(input)) {
                    return { isValid: false, reason: 'Invalid URL format' };
                }
                break;
            case 'number':
                if (!ALLOWED_PATTERNS.NUMBER.test(input)) {
                    return { isValid: false, reason: 'Invalid number format' };
                }
                break;
            case 'general':
            default:
                if (!ALLOWED_PATTERNS.GENERAL_TEXT.test(input)) {
                    return { isValid: false, reason: 'Contains invalid characters' };
                }
                break;
        }
        
        return { isValid: true };
    }

    if (Array.isArray(input)) {
        for (const item of input) {
            const result = validateInputSafety(item, context);
            if (!result.isValid) {
                return result;
            }
        }
        return { isValid: true };
    }

    if (input && typeof input === 'object') {
        for (const [key, value] of Object.entries(input)) {
            // Validate keys as identifiers
            const keyResult = validateInputSafety(key, 'identifier');
            if (!keyResult.isValid) {
                return { isValid: false, reason: `Invalid key: ${keyResult.reason}` };
            }
            
            // Validate values based on context
            const valueResult = validateInputSafety(value, context);
            if (!valueResult.isValid) {
                return valueResult;
            }
        }
        return { isValid: true };
    }

    return { isValid: true };
}

/**
 * Simple type-based validation for known field types
 */
export function validateFieldType(value: any, fieldName: string): { isValid: boolean; reason?: string } {
    // Define expected field types based on common patterns
    const fieldTypeMap: Record<string, string> = {
        'id': 'identifier',
        'email': 'email',
        'website': 'url',
        'url': 'url',
        'name': 'general',
        'title': 'general',
        'description': 'general',
        'bio': 'general',
        'role': 'identifier',
        'status': 'identifier',
        'age': 'number',
        'count': 'number',
        'price': 'number',
        'createdAt': 'general', // Allow datetime strings
        'updatedAt': 'general',
    };

    const context = fieldTypeMap[fieldName] || 'general';
    return validateInputSafety(value, context as any);
}

/**
 * Comprehensive security middleware with optimized validation approach
 * Performance optimizations:
 * - Whitelist validation instead of regex blacklists (prevents ReDoS)
 * - Simple character/string checks instead of complex patterns
 * - Schema-based field type validation
 * - Lightweight XSS sanitization with allowlist approach
 * - Frontend must still handle output escaping
 * - No heavy DOM construction per request
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

        // Fast whitelist-based validation for all user inputs
        const userInputs = [
            { data: req.body, name: 'body' },
            { data: req.query, name: 'query' },
            { data: req.params, name: 'params' }
        ];

        // Only check specific suspicious headers, not all headers
        const suspiciousHeaders = {
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-real-ip': req.headers['x-real-ip'],
            referer: req.headers['referer'],
        };

        // Validate all user inputs using whitelist approach (much faster than regex blacklists)
        for (const { data, name } of userInputs) {
            if (data && typeof data === 'object') {
                for (const [key, value] of Object.entries(data)) {
                    const fieldValidation = validateFieldType(value, key);
                    if (!fieldValidation.isValid) {
                        console.warn(
                            `🚨 Invalid input detected in ${name}.${key} from ${req.ip}:`,
                            { value, reason: fieldValidation.reason }
                        );
                        res.status(400).json({
                            error: 'Validation failed',
                            message: `Invalid ${key}: ${fieldValidation.reason}`,
                            field: key
                        });
                        return;
                    }
                }
            } else if (data) {
                const validation = validateInputSafety(data);
                if (!validation.isValid) {
                    console.warn(
                        `🚨 Invalid input detected in ${name} from ${req.ip}:`,
                        { data, reason: validation.reason }
                    );
                    res.status(400).json({
                        error: 'Validation failed',
                        message: `Invalid ${name}: ${validation.reason}`,
                    });
                    return;
                }
            }
        }

        // Check suspicious headers with whitelist validation
        const headerValidation = validateInputSafety(suspiciousHeaders);
        if (!headerValidation.isValid) {
            console.warn(
                `🚨 Invalid content in headers from ${req.ip}:`,
                { headers: suspiciousHeaders, reason: headerValidation.reason }
            );
            res.status(400).json({
                error: 'Security violation',
                message: 'Invalid input detected in headers',
            });
            return;
        }

        // Lightweight XSS sanitization using allowlist approach (no DOM construction)
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeInput(req.body);
        }

        // Lightweight sanitization of query parameters (no DOM construction)
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
