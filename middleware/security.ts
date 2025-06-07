import { type Request, type Response, type NextFunction } from 'express';
import xss from 'xss';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

/* ────────────────────────────────────────────────────────────────────────────
   CONSTANTS / ONE‑TIME COMPILED STRUCTURES
   ────────────────────────────────────────────────────────────────────────── */

const FREE_TEXT_SET = new Set([
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
]);

const STRUCTURED_SET = new Set([
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
]);

const NEVER_ALLOWED_SET = new Set(['<', '>', '{', '}', '\\', '`', '$']);

/* Pre‑compiled case‑insensitive regexes for fast test() */
const SQL_RX = /\b(;|--|\/\*|\*\/|union|select|drop|delete|insert|update)\b/i;
const SCRIPT_RX = /\b(javascript:|vbscript:|data:|file:|php:)\b/i;
const PATH_TRAVERSAL_RX = /\.\.[\\/]|\/etc\/|\\windows\\|\/passwd|\/hosts/i;
const DANGEROUS_KEY_RX =
    /(__proto__|constructor|prototype|<script|javascript:|on\w+\s*=|[<>{};'"]|\$\w+|\r|\n)/i;

/* XSS options – created once */
const xssOptions = {
    allowList: {},
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style'],
    css: false,
};

/* ────────────────────────────────────────────────────────────────────────────
   FAST HELPERS
   ────────────────────────────────────────────────────────────────────────── */

const sanitizeString = (input: string): string =>
    xss(input, xssOptions)
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '')
        .replace(/data:/gi, '')
        .replace(/\bon\w+\s*=/gi, '');

export const validateSecurityThreats = (
    value: any
): { isValid: boolean; reason?: string } => {
    const stack = [value];

    while (stack.length) {
        const item = stack.pop();

        if (typeof item === 'string') {
            const lower = item.toLowerCase();

            if ([...item].some((ch) => NEVER_ALLOWED_SET.has(ch)))
                return {
                    isValid: false,
                    reason: 'Contains forbidden characters',
                };
            if (SQL_RX.test(lower))
                return {
                    isValid: false,
                    reason: 'Contains SQL‑suspicious content',
                };
            if (SCRIPT_RX.test(lower))
                return {
                    isValid: false,
                    reason: 'Contains script‑suspicious content',
                };
            if (PATH_TRAVERSAL_RX.test(lower))
                return {
                    isValid: false,
                    reason: 'Contains path traversal patterns',
                };
        } else if (Array.isArray(item)) {
            stack.push(...item);
        } else if (item && typeof item === 'object') {
            for (const [k, v] of Object.entries(item)) {
                /* Validate keys only once here */
                if (typeof k === 'string' && DANGEROUS_KEY_RX.test(k))
                    return { isValid: false, reason: 'Dangerous object key' };
                stack.push(v);
            }
        }
    }
    return { isValid: true };
};

const sanitizeInputFast = (value: any, parentKey = ''): any => {
    if (typeof value === 'string') {
        const isFree = FREE_TEXT_SET.has(parentKey);
        const isStruct = STRUCTURED_SET.has(parentKey);
        if (
            isFree ||
            (!isStruct && DEFAULT_SANITIZATION_CONFIG.sanitizeAllStrings)
        )
            return sanitizeString(value);
        return value;
    }

    if (Array.isArray(value))
        return value.map((v) => sanitizeInputFast(v, parentKey)); // parent key unchanged

    if (value && typeof value === 'object') {
        const out: Record<string, any> = {};
        for (const [k, v] of Object.entries(value)) {
            /* key already validated by higher‑level call */
            out[k] = sanitizeInputFast(v, k);
        }
        return out;
    }

    return value;
};

export interface SanitizationConfig {
    freeTextFields?: string[];
    structuredFields?: string[];
    sanitizeAllStrings?: boolean;
}

const DEFAULT_SANITIZATION_CONFIG: SanitizationConfig = {
    freeTextFields: [...FREE_TEXT_SET],
    structuredFields: [...STRUCTURED_SET],
    sanitizeAllStrings: false,
};

/* ────────────────────────────────────────────────────────────────────────────
   PUBLIC API
   ────────────────────────────────────────────────────────────────────────── */

export const sanitizeInput = sanitizeInputFast; // same signature
export const sanitizeInputRecursive = (input: any): any =>
    sanitizeString(typeof input === 'string' ? input : JSON.stringify(input)); // legacy – retain behaviour but simplified

export const sanitizeRichText = (input: string): string =>
    xss(input, {
        allowList: {
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
        css: false,
    });

export const validateObjectKey = (key: string) =>
    typeof key === 'string' && !DANGEROUS_KEY_RX.test(key)
        ? { isValid: true }
        : {
              isValid: false,
              reason: 'Key contains dangerous characters or patterns',
          };

/* ────────────────────────────────────────────────────────────────────────────
   EXPRESS MIDDLEWARE
   ────────────────────────────────────────────────────────────────────────── */

export const securityMiddleware =
    (opts?: { maxBodySize?: number; maxQuerySize?: number }) =>
    (req: Request, res: Response, next: NextFunction): void => {
        try {
            const maxBody = opts?.maxBodySize ?? 50_000; // 50 KB
            const maxQuery = opts?.maxQuerySize ?? 10_000; // 10 KB

            /* Size checks – prefer content‑length header if present */
            const bodySize =
                Number(req.headers['content-length']) ||
                Buffer.byteLength(
                    (req as any).rawBody ?? JSON.stringify(req.body || {})
                );
            const querySize = Buffer.byteLength(
                JSON.stringify(req.query || {})
            );

            if (bodySize > maxBody) {
                res.status(413).json({
                    error: 'Request too large',
                    message: 'Request body size exceeds the configured limit',
                });
                return;
            }
            if (querySize > maxQuery) {
                res.status(413).json({
                    error: 'Request too large',
                    message: 'Query parameters size exceeds the configured limit',
                });
                return;
            }

            /* Unified validation for body, query & params */
            const threat = validateSecurityThreats({
                body: req.body,
                query: req.query,
                params: req.params,
            });
            if (!threat.isValid) {
                res.status(400).json({
                    error: 'Security violation',
                    message: `Potential security threat detected: ${threat.reason}`,
                });
                return;
            }

            /* Sanitize */
            if (req.body && typeof req.body === 'object')
                req.body = sanitizeInputFast(req.body);
            if (req.query && typeof req.query === 'object') {
                const sanitized = sanitizeInputFast(req.query);
                Object.defineProperty(req, 'query', {
                    value: sanitized,
                    writable: false,
                });
            }

            next();
        } catch (err) {
            console.error('Security middleware error', err);
            res.status(500).json({
                error: 'Internal security error',
                message: 'Security middleware failed to process the request',
            });
        }
    };

export const rateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
    },
    handler: (req, res) => {
        console.warn(`🚨 Rate limit exceeded for ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests',
            message: 'Rate limit exceeded. Please try again later.',
        });
    },
});

export const strictRateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'GET',
    message: {
        error: 'Too many requests',
        message: 'Write operation rate limit exceeded. Please try again later.',
    },
    handler: (req, res) => {
        console.warn(`🚨 Write operation rate limit exceeded for ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests',
            message:
                'Write operation rate limit exceeded. Please try again later.',
        });
    },
});

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
    crossOriginEmbedderPolicy: false,
});

export const additionalSecurityHeaders = (
    _req: Request,
    res: Response,
    next: NextFunction
): void => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
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

export const validateUserInput = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    if (req.method === 'POST' || req.method === 'PUT') {
        const result = validateSecurityThreats(req.body);
        if (!result.isValid) {
            res.status(400).json({
                error: 'Security violation',
                message: `Input failed security validation: ${result.reason}`,
            });
            return;
        }
    }
    next();
};
