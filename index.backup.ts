import express, {
    type Request,
    type Response,
    type RequestHandler,
    type NextFunction,
} from 'express';
import { Database, Collection } from 'skibbadb';
import type { z } from 'zod';
import { sanitizeInput } from './middleware/security.js';
import rateLimit from 'express-rate-limit';

/**
 * Hooks that can be configured for different HTTP methods to customize behavior
 * before and after database operations. All hooks are optional.
 */
export interface MethodHooks {
    // GET hooks
    /** Called before executing a query. Can modify the query object. */
    beforeQuery?: (query: any, req: Request) => Promise<any>;
    /** Called after query execution. Can modify the results before returning to client. */
    afterQuery?: (results: any[], req: Request) => Promise<any[]>;

    // POST hooks
    /** Called before creating a new document. Can modify or validate the data. */
    beforeCreate?: (data: any, req: Request) => Promise<any>;
    /** Called after document creation. Can modify the result before returning to client. */
    afterCreate?: (result: any, req: Request) => Promise<any>;

    // PUT hooks
    /** Called before updating a document. Can modify or validate the data. */
    beforeUpdate?: (id: string, data: any, req: Request) => Promise<any>;
    /** Called after document update. Can modify the result before returning to client. */
    afterUpdate?: (result: any, req: Request) => Promise<any>;

    // DELETE hooks
    /** Called before deleting a document. Return false to cancel the deletion. */
    beforeDelete?: (id: string, req: Request) => Promise<boolean>; // return false to cancel
    /** Called after successful document deletion. */
    afterDelete?: (id: string, req: Request) => Promise<void>;
}

/**
 * Configuration options for individual HTTP methods (GET, POST, PUT, DELETE)
 */
export interface MethodConfig {
    /** Express middleware to apply to this specific method */
    middleware?: RequestHandler[];
    /** Lifecycle hooks for this method */
    hooks?: MethodHooks;
    /** Rate limiting configuration for this method */
    rateLimitOptions?: {
        windowMs?: number; // Time window in milliseconds
        max?: number; // Max requests per window
    };
    /** Request body size limits for this method */
    uploadLimitOptions?: {
        jsonLimit?: string; // JSON body size limit (e.g., '50kb')
        urlEncodedLimit?: string; // URL-encoded body size limit
    };
}

/**
 * Configuration for a collection's REST API endpoints.
 * Controls which HTTP methods are enabled and their specific configurations.
 */
export interface CollectionConfig {
    /** Configuration for GET endpoints (retrieve operations) */
    GET?: MethodConfig;
    /** Configuration for POST endpoints (create operations) */
    POST?: MethodConfig;
    /** Configuration for PUT endpoints (update operations) */
    PUT?: MethodConfig;
    /** Configuration for DELETE endpoints (delete operations) */
    DELETE?: MethodConfig;
    /** Base URL path for this collection. Defaults to '/{collectionName}' */
    basePath?: string;
    /** Global middleware applied to all methods for this collection */
    middleware?: RequestHandler[]; // Global middleware for this collection
    /** Global rate limiting for this collection */
    rateLimitOptions?: {
        windowMs?: number; // Time window in milliseconds
        max?: number; // Max requests per window
        strict?: boolean; // Whether to use strict rate limiting for write operations
    };
    /** Global request body size limits for this collection */
    uploadLimitOptions?: {
        jsonLimit?: string; // JSON body size limit (e.g., '50kb')
        urlEncodedLimit?: string; // URL-encoded body size limit
    };
}

/**
 * Extended Express application with SkibbaDB integration capabilities.
 * Provides the `useCollection` method to automatically generate REST API endpoints.
 */
export interface SkibbaExpressApp extends express.Application {
    /**
     * Automatically generates REST API endpoints for a SkibbaDB collection.
     * Creates routes for GET, POST, PUT, and DELETE operations based on configuration.
     *
     * @param collection - The SkibbaDB collection to create endpoints for
     * @param config - Optional configuration for the endpoints and middleware
     */
    useCollection<T extends z.ZodType<any, z.ZodTypeDef, any>>(
        collection: Collection<T>,
        config?: CollectionConfig
    ): void;
}

// Re-export types and interfaces for convenience
export type { Database, Collection } from 'skibbadb';
export type { Request, Response, RequestHandler, NextFunction } from 'express';

// Re-export security utilities for easy access
export {
    sanitizeInput,
    sanitizeInputRecursive,
    sanitizeRichText,
    validateSecurityThreats,
    validateObjectKey,
    securityMiddleware,
    rateLimitMiddleware,
    strictRateLimitMiddleware,
    helmetMiddleware,
    additionalSecurityHeaders,
    validateUserInput,
} from './middleware/security.js';

// Re-export types for convenience
export type { SanitizationConfig } from './middleware/security.js';

/**
 * Creates a SkibbaDB-enhanced Express application with automatic REST API generation.
 * Adds middleware for JSON parsing, error handling, and security measures.
 *
 * @param app - Express application instance
 * @param database - SkibbaDB database instance (currently unused but kept for future features)
 * @param globalOptions - Global configuration options
 * @param globalOptions.uploadLimitOptions - Default request body size limits
 * @returns Enhanced Express app with `useCollection` method
 *
 * @example
 * ```typescript
 * const app = express();
 * const database = new Database('./data');
 * const skibbaApp = createSkibbaExpress(app, database);
 *
 * // Auto-generate REST endpoints for a collection
 * skibbaApp.useCollection(usersCollection, {
 *   GET: { middleware: [authMiddleware] },
 *   POST: { hooks: { beforeCreate: validateUser } }
 * });
 * ```
 */
export function createSkibbaExpress(
    app: express.Application,
    database: Database,
    globalOptions?: {
        uploadLimitOptions?: {
            jsonLimit?: string;
            urlEncodedLimit?: string;
        };
    }
): SkibbaExpressApp {
    // Default middleware with built-in error handling and request size limits
    // Use 50kb as default to match security middleware
    const jsonLimit = globalOptions?.uploadLimitOptions?.jsonLimit || '50kb';
    const urlEncodedLimit =
        globalOptions?.uploadLimitOptions?.urlEncodedLimit || '50kb';

    app.use(express.json({ limit: jsonLimit }));
    app.use(express.urlencoded({ extended: true, limit: urlEncodedLimit }));

    // JSON parsing error handler for malformed JSON and size limits
    app.use((err: any, req: Request, res: Response, next: NextFunction) => {
        if (err instanceof SyntaxError && 'body' in err) {
            res.status(400).json({
                error: 'Invalid JSON',
                message: 'Request body contains invalid JSON',
            });
            return;
        }
        if (err.type === 'entity.too.large') {
            res.status(413).json({
                error: 'Payload too large',
                message: 'Request body exceeds size limit',
            });
            return;
        }
        next(err);
    });

    /**
     * Creates a rate limiter middleware with specified options.
     * Used for general API rate limiting.
     */
    function createRateLimiter(
        options: CollectionConfig['rateLimitOptions'] = {}
    ) {
        const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes default
        const max = options.max || 100; // 100 requests default

        return rateLimit({
            windowMs,
            max,
            message: {
                error: 'Too many requests',
                message: 'Rate limit exceeded. Please try again later.',
            },
            standardHeaders: true,
            legacyHeaders: false,
            handler: (req, res) => {
                console.warn(`🚨 Collection rate limit exceeded for ${req.ip}`);
                res.status(429).json({
                    error: 'Too many requests',
                    message: 'Rate limit exceeded. Please try again later.',
                });
            },
        });
    }

    /**
     * Creates a stricter rate limiter specifically for write operations (POST, PUT, DELETE).
     * Has lower limits than the general rate limiter to prevent abuse.
     */
    function createStrictRateLimiter(
        options: CollectionConfig['rateLimitOptions'] = {}
    ) {
        const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes default
        const max = options.max || 30; // 30 requests default for write operations

        return rateLimit({
            windowMs,
            max,
            message: {
                error: 'Too many requests',
                message:
                    'Write operation rate limit exceeded. Please try again later.',
            },
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => req.method === 'GET', // Only apply to write operations
            handler: (req, res) => {
                console.warn(
                    `🚨 Strict write operation rate limit exceeded for ${req.ip}`
                );
                res.status(429).json({
                    error: 'Too many requests',
                    message:
                        'Write operation rate limit exceeded. Please try again later.',
                });
            },
        });
    }

    /**
     * Creates middleware to enforce request body size limits for JSON and URL-encoded data.
     * Helps prevent memory exhaustion attacks and large payload abuse.
     */
    function createUploadSizeMiddleware(
        options: CollectionConfig['uploadLimitOptions'] = {}
    ) {
        const jsonLimit = options.jsonLimit || '50kb';
        const urlEncodedLimit = options.urlEncodedLimit || '50kb';

        // Convert size strings to bytes for comparison
        const parseSize = (sizeStr: string): number => {
            const match = sizeStr.match(/^(\d+(?:\.\d+)?)(kb|mb|gb)?$/i);
            if (!match) return 50 * 1024; // Default 50KB

            const num = parseFloat(match[1]);
            const unit = (match[2] || '').toLowerCase();

            switch (unit) {
                case 'gb':
                    return num * 1024 * 1024 * 1024;
                case 'mb':
                    return num * 1024 * 1024;
                case 'kb':
                    return num * 1024;
                default:
                    return num; // Assume bytes
            }
        };

        const jsonLimitBytes = parseSize(jsonLimit);
        const urlEncodedLimitBytes = parseSize(urlEncodedLimit);

        return [
            // Check Content-Length header before any parsing occurs
            (req: Request, res: Response, next: NextFunction) => {
                const contentLength = req.get('Content-Length');
                if (contentLength) {
                    const size = parseInt(contentLength, 10);
                    const contentType = req.get('Content-Type') || '';

                    if (
                        contentType.includes('application/json') &&
                        size > jsonLimitBytes
                    ) {
                        console.log(
                            `🚨 Upload size middleware rejecting ${size} bytes (limit: ${jsonLimitBytes} for ${jsonLimit})`
                        );
                        res.status(413).json({
                            error: 'Payload too large',
                            message: 'Request body exceeds size limit',
                        });
                        return;
                    }

                    if (
                        contentType.includes(
                            'application/x-www-form-urlencoded'
                        ) &&
                        size > urlEncodedLimitBytes
                    ) {
                        console.log(
                            `🚨 Upload size middleware rejecting ${size} bytes (limit: ${urlEncodedLimitBytes} for ${urlEncodedLimit})`
                        );
                        res.status(413).json({
                            error: 'Payload too large',
                            message: 'Request body exceeds size limit',
                        });
                        return;
                    }
                } else {
                    console.log(
                        `📝 No Content-Length header, limits: ${jsonLimit}`
                    );
                }
                next();
            },
        ];
    }

    /**
     * Applies method-specific middleware configuration including custom upload limits,
     * rate limiting, and user-defined middleware in the correct order.
     */
    function applyMethodMiddleware(
        methodConfig: MethodConfig
    ): RequestHandler[] {
        const middlewares: RequestHandler[] = [];

        // Add custom upload size limits if specified
        if (methodConfig.uploadLimitOptions) {
            middlewares.push(
                ...createUploadSizeMiddleware(methodConfig.uploadLimitOptions)
            );
        }

        // Add custom rate limiting if specified
        if (methodConfig.rateLimitOptions) {
            const customRateLimit = createRateLimiter(
                methodConfig.rateLimitOptions
            );
            middlewares.push(customRateLimit);
        }

        // Add method-specific middleware
        if (methodConfig.middleware) {
            middlewares.push(...methodConfig.middleware);
        }

        return middlewares;
    }

    // Add the useCollection method to the app
    (app as any).useCollection = function <
        T extends z.ZodType<any, z.ZodTypeDef, any>
    >(collection: Collection<T>, config: CollectionConfig = {}) {
        const basePath =
            config.basePath || `/${(collection as any).collectionSchema.name}`;
        const router = express.Router();

        // Apply global middleware for this collection
        if (config.middleware) {
            router.use(...config.middleware);
        }

        // Apply upload size limits (custom or default) BEFORE rate limiting
        // Collections without custom limits should use the default 50KB limit
        console.log(
            `🔧 Collection ${basePath} upload config:`,
            config.uploadLimitOptions
        );
        const uploadLimits = config.uploadLimitOptions || {
            jsonLimit: '50kb',
            urlEncodedLimit: '50kb',
        };
        console.log(`🔧 Using upload limits for ${basePath}:`, uploadLimits);
        router.use(...createUploadSizeMiddleware(uploadLimits));

        // Apply custom rate limiting if specified
        if (config.rateLimitOptions) {
            const customRateLimit = createRateLimiter(config.rateLimitOptions);
            router.use(customRateLimit);

            // Apply strict rate limiting for write operations if enabled
            if (config.rateLimitOptions.strict) {
                const customStrictRateLimit = createStrictRateLimiter(
                    config.rateLimitOptions
                );
                router.use(customStrictRateLimit);
            }
        }

        // GET /:id - Get single item
        if (config.GET) {
            const middleware = applyMethodMiddleware(config.GET);
            router.get(
                '/:id',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        const id = req.params.id;

                        // Validate ID parameter format (basic security check)
                        if (!id || typeof id !== 'string' || id.length > 100) {
                            res.status(400).json({
                                error: 'Invalid ID parameter',
                                message:
                                    'ID parameter is required and must be a valid string',
                            });
                            return;
                        }

                        // Sanitize the ID parameter to prevent injection attacks
                        const sanitizedId = sanitizeInput(id);

                        let query = collection
                            .where('_id' as any)
                            .eq(sanitizedId);

                        // Apply beforeQuery hook
                        if (config.GET?.hooks?.beforeQuery) {
                            query = await config.GET.hooks.beforeQuery(
                                query,
                                req
                            );
                        }

                        const result = await query.first();

                        if (!result) {
                            res.status(404).json({ error: 'Not found' });
                            return;
                        }

                        // Apply afterQuery hook
                        let finalResult = [result];
                        if (config.GET?.hooks?.afterQuery) {
                            finalResult = await config.GET.hooks.afterQuery(
                                finalResult,
                                req
                            );
                        }

                        res.json(finalResult[0]);
                    } catch (error) {
                        next(error);
                    }
                }
            );

            // GET / - Get all items (with pagination and filtering)
            router.get(
                '/',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        /**
                         * Validates if a field name exists in the collection's Zod schema.
                         * Supports nested field access with dot notation.
                         * Used to prevent injection attacks through invalid field names.
                         */
                        function isValidField(field: string): boolean {
                            if (field.includes('.')) return true; // allow nested fields
                            const schema = (collection as any).collectionSchema
                                .schema;
                            let validFields: string[] = [];

                            // Try different ways to access Zod schema shape
                            if (schema.shape) {
                                validFields = Object.keys(schema.shape);
                            } else if (schema._def && schema._def.shape) {
                                validFields = Object.keys(schema._def.shape);
                            } else if (
                                schema._def &&
                                typeof schema._def.shape === 'function'
                            ) {
                                validFields = Object.keys(schema._def.shape());
                            }

                            // If we still don't have valid fields, try parsing the schema
                            if (validFields.length === 0) {
                                try {
                                    const parsed = schema.safeParse({});
                                    if (parsed.error) {
                                        validFields = parsed.error.issues
                                            .map((issue: any) => issue.path[0])
                                            .filter(Boolean);
                                    }
                                } catch (e) {
                                    // Fallback: allow common fields or return false
                                    console.warn(
                                        'Could not extract schema fields for validation'
                                    );
                                }
                            }

                            return validFields.includes(field);
                        }

                        let query = collection.query();

                        // Create sanitized query copy to avoid mutating req.query
                        const sanitizedQuery = { ...req.query };
                        (req as any).sanitizedQuery = sanitizedQuery;

                        /**
                         * Safely parses and validates unsigned integer parameters from query strings.
                         * Prevents injection attacks and ensures values are within acceptable ranges.
                         *
                         * @param value - The string value to parse
                         * @param paramName - Name of the parameter (for error messages)
                         * @param min - Minimum allowed value
                         * @param max - Maximum allowed value (optional)
                         * @returns Parsed integer or undefined if value is empty
                         * @throws Error if value is invalid or out of range
                         */
                        function parseUnsignedInt(
                            value: string | undefined,
                            paramName: string,
                            min: number = 0,
                            max?: number
                        ): number | undefined {
                            if (value === undefined || value === '')
                                return undefined;

                            // Check if value contains only digits (and optional leading/trailing whitespace)
                            const trimmedValue = value.toString().trim();
                            if (!/^\d+$/.test(trimmedValue)) {
                                throw new Error(
                                    `${paramName} must be a valid unsigned integer`
                                );
                            }

                            const parsed = parseInt(trimmedValue, 10);

                            // Additional safety check for NaN (though regex should prevent this)
                            if (isNaN(parsed)) {
                                throw new Error(
                                    `${paramName} must be a valid unsigned integer`
                                );
                            }

                            if (parsed < min) {
                                throw new Error(
                                    `${paramName} must be at least ${min}`
                                );
                            }

                            if (max !== undefined && parsed > max) {
                                throw new Error(
                                    `${paramName} must not exceed ${max}`
                                );
                            }

                            return parsed;
                        }

                        // Parse and validate pagination parameters
                        let page: number | undefined;
                        let limit: number | undefined;
                        let offset: number | undefined;

                        try {
                            page = parseUnsignedInt(
                                sanitizedQuery.page as string,
                                'Page',
                                1
                            );
                            limit = parseUnsignedInt(
                                sanitizedQuery.limit as string,
                                'Limit',
                                1,
                                1000
                            );
                            offset = parseUnsignedInt(
                                sanitizedQuery.offset as string,
                                'Offset',
                                0
                            );
                        } catch (error: any) {
                            res.status(400).json({
                                error: 'Invalid pagination parameter',
                                message: error.message,
                            });
                            return;
                        }

                        // Parse sorting parameters
                        const orderBy = sanitizedQuery.orderBy as string;
                        const sortDirection =
                            (sanitizedQuery.sort as string) || 'asc';

                        if (
                            orderBy &&
                            !['asc', 'desc'].includes(sortDirection)
                        ) {
                            res.status(400).json({
                                error: 'Invalid sort parameter',
                                message:
                                    'Sort direction must be either "asc" or "desc"',
                            });
                            return;
                        }

                        const excludedParams = new Set([
                            'page',
                            'limit',
                            'offset',
                            'orderBy',
                            'sort',
                        ]);

                        // Validate filter fields before applying
                        for (const [key, value] of Object.entries(
                            sanitizedQuery
                        )) {
                            if (
                                excludedParams.has(key) ||
                                value === undefined ||
                                value === ''
                            ) {
                                continue;
                            }
                            let field = key;
                            if (key.endsWith('_gt')) field = key.slice(0, -3);
                            else if (key.endsWith('_gte'))
                                field = key.slice(0, -4);
                            else if (key.endsWith('_lt'))
                                field = key.slice(0, -3);
                            else if (key.endsWith('_lte'))
                                field = key.slice(0, -4);
                            else if (key.endsWith('_like'))
                                field = key.slice(0, -5);
                            else if (key.endsWith('_in'))
                                field = key.slice(0, -3);
                            if (!isValidField(field)) {
                                res.status(400).json({
                                    error: 'Invalid filter parameter',
                                    message: `Invalid filter for field "${field}": Field '${field}' does not exist in schema`,
                                });
                                return;
                            }
                        }

                        // Validate sort field before applying
                        if (orderBy && !isValidField(orderBy)) {
                            res.status(400).json({
                                error: 'Invalid sort parameter',
                                message: `Invalid sort field "${orderBy}": Field '${orderBy}' does not exist in schema`,
                            });
                            return;
                        }

                        // Apply filtering based on query parameters
                        // const excludedParams = new Set([
                        //     'page',
                        //     'limit',
                        //     'offset',
                        //     'orderBy',
                        //     'sort',
                        // ]);

                        // Validate filter fields before applying
                        for (const [key, value] of Object.entries(
                            sanitizedQuery
                        )) {
                            if (
                                excludedParams.has(key) ||
                                value === undefined ||
                                value === ''
                            ) {
                                continue;
                            }

                            try {
                                // Handle different filter operators
                                if (key.endsWith('_gt')) {
                                    const field = key.slice(0, -3);
                                    query = query
                                        .where(field)
                                        .gt(
                                            isNaN(Number(value as string))
                                                ? value
                                                : Number(value as string)
                                        );
                                } else if (key.endsWith('_gte')) {
                                    const field = key.slice(0, -4);
                                    query = query
                                        .where(field)
                                        .gte(
                                            isNaN(Number(value as string))
                                                ? value
                                                : Number(value as string)
                                        );
                                } else if (key.endsWith('_lt')) {
                                    const field = key.slice(0, -3);
                                    query = query
                                        .where(field)
                                        .lt(
                                            isNaN(Number(value as string))
                                                ? value
                                                : Number(value as string)
                                        );
                                } else if (key.endsWith('_lte')) {
                                    const field = key.slice(0, -4);
                                    query = query
                                        .where(field)
                                        .lte(
                                            isNaN(Number(value as string))
                                                ? value
                                                : Number(value as string)
                                        );
                                } else if (key.endsWith('_like')) {
                                    const field = key.slice(0, -5);
                                    query = query
                                        .where(field)
                                        .like(value as string);
                                } else if (key.endsWith('_in')) {
                                    const field = key.slice(0, -3);
                                    const values = Array.isArray(value)
                                        ? value
                                        : [value];
                                    query = query.where(field).in(values);
                                } else {
                                    // Default to equality filter
                                    // Convert string boolean values to actual booleans
                                    let convertedValue: any = value;
                                    if (value === 'true') {
                                        convertedValue = true;
                                    } else if (value === 'false') {
                                        convertedValue = false;
                                    } else if (
                                        !isNaN(Number(value as string))
                                    ) {
                                        // Convert numeric strings to numbers for proper comparison
                                        convertedValue = Number(
                                            value as string
                                        );
                                    }
                                    query = query.where(key).eq(convertedValue);
                                }
                            } catch (filterError: any) {
                                // If field doesn't exist or filter fails, return error
                                if (
                                    filterError &&
                                    filterError.name === 'ValidationError'
                                ) {
                                    res.status(400).json({
                                        error: 'Invalid filter parameter',
                                        message: `Invalid filter for field "${key}": ${filterError.message}`,
                                    });
                                } else {
                                    res.status(400).json({
                                        error: 'Invalid filter parameter',
                                        message: `Invalid filter for field "${key}": ${
                                            filterError instanceof Error
                                                ? filterError.message
                                                : 'Unknown error'
                                        }`,
                                    });
                                }
                                return;
                            }
                        }

                        // Apply sorting
                        if (orderBy) {
                            try {
                                query = query.orderBy(
                                    orderBy,
                                    sortDirection as 'asc' | 'desc'
                                );
                            } catch (sortError: any) {
                                if (
                                    sortError &&
                                    sortError.name === 'ValidationError'
                                ) {
                                    res.status(400).json({
                                        error: 'Invalid sort parameter',
                                        message: `Invalid sort field "${orderBy}": ${sortError.message}`,
                                    });
                                } else {
                                    res.status(400).json({
                                        error: 'Invalid sort parameter',
                                        message: `Invalid sort field "${orderBy}": ${
                                            sortError instanceof Error
                                                ? sortError.message
                                                : 'Unknown error'
                                        }`,
                                    });
                                }
                                return;
                            }
                        }

                        // Apply pagination
                        if (page !== undefined && limit !== undefined) {
                            query = query.page(page, limit);
                        } else if (limit !== undefined) {
                            query = query.limit(limit);
                            if (offset !== undefined) {
                                query = query.offset(offset);
                            }
                        } else if (offset !== undefined) {
                            query = query.offset(offset);
                        }

                        // Apply beforeQuery hook
                        if (config.GET?.hooks?.beforeQuery) {
                            query = await config.GET.hooks.beforeQuery(
                                query,
                                req
                            );
                        }

                        let results: any[];
                        try {
                            results = await query.toArray();
                        } catch (error: any) {
                            if (error && error.name === 'ValidationError') {
                                res.status(400).json({
                                    error: 'Invalid filter parameter',
                                    message: error.message,
                                });
                                return;
                            }
                            throw error;
                        }

                        // Apply afterQuery hook
                        let finalResults = results;
                        if (config.GET?.hooks?.afterQuery) {
                            finalResults = await config.GET.hooks.afterQuery(
                                results,
                                req
                            );
                        }

                        // Prepare response with pagination metadata if pagination was used
                        if (page !== undefined && limit !== undefined) {
                            // Get total count for pagination metadata
                            let countQuery = collection.query();

                            // Apply same filters for count (but no pagination/sorting)
                            for (const [key, value] of Object.entries(
                                sanitizedQuery
                            )) {
                                if (
                                    excludedParams.has(key) ||
                                    value === undefined ||
                                    value === ''
                                ) {
                                    continue;
                                }

                                try {
                                    if (key.endsWith('_gt')) {
                                        const field = key.slice(0, -3);
                                        const numValue = isNaN(
                                            Number(value as string)
                                        )
                                            ? value
                                            : Number(value as string);
                                        countQuery = countQuery
                                            .where(field)
                                            .gt(numValue);
                                    } else if (key.endsWith('_gte')) {
                                        const field = key.slice(0, -4);
                                        const numValue = isNaN(
                                            Number(value as string)
                                        )
                                            ? value
                                            : Number(value as string);
                                        countQuery = countQuery
                                            .where(field)
                                            .gte(numValue);
                                    } else if (key.endsWith('_lt')) {
                                        const field = key.slice(0, -3);
                                        const numValue = isNaN(
                                            Number(value as string)
                                        )
                                            ? value
                                            : Number(value as string);
                                        countQuery = countQuery
                                            .where(field)
                                            .lt(numValue);
                                    } else if (key.endsWith('_lte')) {
                                        const field = key.slice(0, -4);
                                        const numValue = isNaN(
                                            Number(value as string)
                                        )
                                            ? value
                                            : Number(value as string);
                                        countQuery = countQuery
                                            .where(field)
                                            .lte(numValue);
                                    } else if (key.endsWith('_like')) {
                                        const field = key.slice(0, -5);
                                        countQuery = countQuery
                                            .where(field)
                                            .like(value as string);
                                    } else if (key.endsWith('_in')) {
                                        const field = key.slice(0, -3);
                                        const values = Array.isArray(value)
                                            ? value
                                            : [value];
                                        countQuery = countQuery
                                            .where(field)
                                            .in(values);
                                    } else {
                                        // Convert string boolean values to actual booleans for count query
                                        let convertedValue: any = value;
                                        if (value === 'true') {
                                            convertedValue = true;
                                        } else if (value === 'false') {
                                            convertedValue = false;
                                        } else if (
                                            !isNaN(Number(value as string))
                                        ) {
                                            convertedValue = Number(
                                                value as string
                                            );
                                        }
                                        countQuery = countQuery
                                            .where(key)
                                            .eq(convertedValue);
                                    }
                                } catch {
                                    // Ignore filter errors for count query
                                }
                            }

                            let totalCount: number;
                            try {
                                totalCount = await countQuery.executeCount();
                            } catch (error: any) {
                                if (error && error.name === 'ValidationError') {
                                    res.status(400).json({
                                        error: 'Invalid filter parameter',
                                        message: error.message,
                                    });
                                    return;
                                }
                                throw error;
                            }
                            const totalPages = Math.ceil(totalCount / limit);

                            res.json({
                                data: finalResults,
                                pagination: {
                                    page,
                                    limit,
                                    totalCount,
                                    totalPages,
                                    hasNextPage: page < totalPages,
                                    hasPreviousPage: page > 1,
                                },
                            });
                        } else {
                            res.json(finalResults);
                        }
                    } catch (error) {
                        next(error);
                    }
                }
            );
        }

        // POST / - Create new item
        if (config.POST) {
            const middleware = applyMethodMiddleware(config.POST);
            router.post(
                '/',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        let data = req.body;

                        // Enhanced validation for request body
                        if (
                            !data ||
                            typeof data !== 'object' ||
                            Array.isArray(data)
                        ) {
                            res.status(400).json({
                                error: 'Invalid request body',
                                message:
                                    'Request body must be a valid JSON object',
                            });
                            return;
                        }

                        /**
                         * Security check to prevent prototype pollution attacks.
                         * Recursively scans object for dangerous keys that could modify prototypes.
                         */
                        const dangerousKeys = [
                            '__proto__',
                            'constructor',
                            'prototype',
                        ];
                        const checkForDangerousKeys = (obj: any): boolean => {
                            if (typeof obj !== 'object' || obj === null)
                                return false;

                            for (const key of Object.keys(obj)) {
                                if (dangerousKeys.includes(key)) return true;
                                if (
                                    typeof obj[key] === 'object' &&
                                    checkForDangerousKeys(obj[key])
                                ) {
                                    return true;
                                }
                            }
                            return false;
                        };

                        if (checkForDangerousKeys(data)) {
                            res.status(400).json({
                                error: 'Security violation',
                                message: 'Dangerous object keys detected',
                            });
                            return;
                        }

                        // Apply beforeCreate hook
                        if (config.POST?.hooks?.beforeCreate) {
                            data = await config.POST.hooks.beforeCreate(
                                data,
                                req
                            );
                        }

                        const result = await collection.insert(data);

                        // Apply afterCreate hook
                        let finalResult = result;
                        if (config.POST?.hooks?.afterCreate) {
                            finalResult = await config.POST.hooks.afterCreate(
                                result,
                                req
                            );
                        }

                        res.status(201).json(finalResult);
                    } catch (error: any) {
                        // Handle validation errors from Zod
                        if (error.name === 'ZodError') {
                            res.status(400).json({
                                error: 'Validation failed',
                                details: error.errors.map((err: any) => ({
                                    field: err.path.join('.'),
                                    message: err.message,
                                })),
                            });
                            return;
                        }

                        // Handle SkibbaDB-specific errors
                        if (
                            error.message &&
                            error.message.includes('Document validation failed')
                        ) {
                            res.status(400).json({
                                error: 'Validation failed',
                                message: 'Document validation failed',
                            });
                            return;
                        }

                        if (
                            error.message &&
                            error.message.includes(
                                'Document with id already exists'
                            )
                        ) {
                            res.status(409).json({
                                error: 'Conflict',
                                message: 'Document with id already exists',
                            });
                            return;
                        }

                        // Handle unique constraint violations
                        if (
                            error.message &&
                            error.message.includes('UNIQUE constraint failed')
                        ) {
                            const field =
                                error.message.match(
                                    /UNIQUE constraint failed: \w+\.(\w+)/
                                )?.[1] || 'field';
                            res.status(409).json({
                                error: 'Constraint violation',
                                message: `${field} already exists`,
                            });
                            return;
                        }

                        // Handle other database errors
                        if (
                            error.message &&
                            (error.message.includes('NOT NULL') ||
                                error.message.includes('constraint'))
                        ) {
                            res.status(400).json({
                                error: 'Database constraint violation',
                                message: error.message,
                            });
                            return;
                        }

                        next(error);
                    }
                }
            );
        }

        // PUT /:id - Update item
        if (config.PUT) {
            const middleware = applyMethodMiddleware(config.PUT);
            router.put(
                '/:id',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        let data = req.body;
                        const id = req.params.id;

                        // Validate ID parameter
                        if (!id || typeof id !== 'string' || id.length > 100) {
                            res.status(400).json({
                                error: 'Invalid ID parameter',
                                message:
                                    'ID parameter is required and must be a valid string',
                            });
                            return;
                        }

                        // Sanitize the ID parameter
                        const sanitizedId = sanitizeInput(id);

                        // Enhanced validation for request body
                        if (
                            !data ||
                            typeof data !== 'object' ||
                            Array.isArray(data)
                        ) {
                            res.status(400).json({
                                error: 'Invalid request body',
                                message:
                                    'Request body must be a valid JSON object',
                            });
                            return;
                        }

                        /**
                         * Security check to prevent prototype pollution attacks.
                         * Recursively scans object for dangerous keys that could modify prototypes.
                         */
                        const dangerousKeys = [
                            '__proto__',
                            'constructor',
                            'prototype',
                        ];
                        const checkForDangerousKeys = (obj: any): boolean => {
                            if (typeof obj !== 'object' || obj === null)
                                return false;

                            for (const key of Object.keys(obj)) {
                                if (dangerousKeys.includes(key)) return true;
                                if (
                                    typeof obj[key] === 'object' &&
                                    checkForDangerousKeys(obj[key])
                                ) {
                                    return true;
                                }
                            }
                            return false;
                        };

                        if (checkForDangerousKeys(data)) {
                            res.status(400).json({
                                error: 'Security violation',
                                message: 'Dangerous object keys detected',
                            });
                            return;
                        }

                        // Apply beforeUpdate hook
                        if (config.PUT?.hooks?.beforeUpdate) {
                            data = await config.PUT.hooks.beforeUpdate(
                                sanitizedId,
                                data,
                                req
                            );
                        }

                        const result = await collection.put(sanitizedId, data);

                        // Apply afterUpdate hook
                        let finalResult = result;
                        if (config.PUT?.hooks?.afterUpdate) {
                            finalResult = await config.PUT.hooks.afterUpdate(
                                result,
                                req
                            );
                        }

                        res.json(finalResult);
                    } catch (error: any) {
                        // Handle validation errors from Zod
                        if (error.name === 'ZodError') {
                            res.status(400).json({
                                error: 'Validation failed',
                                details: error.errors.map((err: any) => ({
                                    field: err.path.join('.'),
                                    message: err.message,
                                })),
                            });
                            return;
                        }

                        // Handle SkibbaDB-specific errors
                        if (
                            error.message &&
                            error.message.includes('Document validation failed')
                        ) {
                            res.status(400).json({
                                error: 'Validation failed',
                                message: 'Document validation failed',
                            });
                            return;
                        }

                        if (
                            error.message &&
                            error.message.includes(
                                'Document with id already exists'
                            )
                        ) {
                            res.status(409).json({
                                error: 'Conflict',
                                message: 'Document with id already exists',
                            });
                            return;
                        }

                        // Handle unique constraint violations
                        if (
                            error.message &&
                            error.message.includes('UNIQUE constraint failed')
                        ) {
                            const field =
                                error.message.match(
                                    /UNIQUE constraint failed: \w+\.(\w+)/
                                )?.[1] || 'field';
                            res.status(409).json({
                                error: 'Constraint violation',
                                message: `${field} already exists`,
                            });
                            return;
                        }

                        // Handle other database errors
                        if (
                            error.message &&
                            (error.message.includes('NOT NULL') ||
                                error.message.includes('constraint'))
                        ) {
                            res.status(400).json({
                                error: 'Database constraint violation',
                                message: error.message,
                            });
                            return;
                        }

                        next(error);
                    }
                }
            );
        }

        // DELETE /:id - Delete item
        if (config.DELETE) {
            const middleware = applyMethodMiddleware(config.DELETE);
            router.delete(
                '/:id',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        const id = req.params.id;

                        // Validate ID parameter
                        if (!id || typeof id !== 'string' || id.length > 100) {
                            res.status(400).json({
                                error: 'Invalid ID parameter',
                                message:
                                    'ID parameter is required and must be a valid string',
                            });
                            return;
                        }

                        // Sanitize the ID parameter
                        const sanitizedId = sanitizeInput(id);

                        // Apply beforeDelete hook
                        let shouldDelete = true;
                        if (config.DELETE?.hooks?.beforeDelete) {
                            shouldDelete =
                                await config.DELETE.hooks.beforeDelete(
                                    sanitizedId,
                                    req
                                );
                        }

                        if (shouldDelete) {
                            await collection.delete(sanitizedId);
                        }

                        // Apply afterDelete hook
                        if (config.DELETE?.hooks?.afterDelete) {
                            await config.DELETE.hooks.afterDelete(
                                sanitizedId,
                                req
                            );
                        }

                        res.status(204).send();
                    } catch (error) {
                        next(error);
                    }
                }
            );
        }

        // Mount the router
        app.use(basePath, router);
    };

    return app as unknown as SkibbaExpressApp;
}

// Default export for convenience
export default createSkibbaExpress;
