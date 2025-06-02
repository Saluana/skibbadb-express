import express, {
    type Request,
    type Response,
    type RequestHandler,
    type NextFunction,
} from 'express';
import { Database, Collection } from 'skibbadb';
import type { z } from 'zod';
import { sanitizeInput } from './middleware/security.js';

export interface MethodHooks {
    // GET hooks
    beforeQuery?: (query: any, req: Request) => Promise<any>;
    afterQuery?: (results: any[], req: Request) => Promise<any[]>;

    // POST hooks
    beforeCreate?: (data: any, req: Request) => Promise<any>;
    afterCreate?: (result: any, req: Request) => Promise<any>;

    // PUT hooks
    beforeUpdate?: (id: string, data: any, req: Request) => Promise<any>;
    afterUpdate?: (result: any, req: Request) => Promise<any>;

    // DELETE hooks
    beforeDelete?: (id: string, req: Request) => Promise<boolean>; // return false to cancel
    afterDelete?: (id: string, req: Request) => Promise<void>;
}

export interface MethodConfig {
    middleware?: RequestHandler[];
    hooks?: MethodHooks;
}

export interface CollectionConfig {
    GET?: MethodConfig;
    POST?: MethodConfig;
    PUT?: MethodConfig;
    DELETE?: MethodConfig;
    basePath?: string;
    middleware?: RequestHandler[]; // Global middleware for this collection
}

export interface SkibbaExpressApp extends express.Application {
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
    validateInputSafety,
    validateFieldType,
    securityMiddleware,
    rateLimitMiddleware,
    strictRateLimitMiddleware,
    helmetMiddleware,
    additionalSecurityHeaders,
    validateUserInput
} from './middleware/security.js';

// Re-export types for convenience
export type { SanitizationConfig } from './middleware/security.js';

export function createSkibbaExpress(
    app: express.Application,
    database: Database
): SkibbaExpressApp {
    // Default middleware with error handling
    app.use(
        express.json({
            verify: (req, res, buf) => {
                try {
                    JSON.parse(buf.toString());
                } catch (e) {
                    (res as any).locals.jsonError = true;
                }
            },
        })
    );
    app.use(express.urlencoded({ extended: true }));

    // JSON parsing error handler
    app.use((req: Request, res: Response, next: NextFunction) => {
        if ((res as any).locals.jsonError) {
            res.status(400).json({
                error: 'Invalid JSON',
                message: 'Request body contains invalid JSON',
            });
            return;
        }
        next();
    });

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

        // GET /:id - Get single item
        if (config.GET) {
            const middleware = config.GET.middleware || [];
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
                            .where('id' as any)
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
                        // Helper to validate field names against schema
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

                        // Parse pagination parameters
                        const page = req.query.page
                            ? parseInt(req.query.page as string)
                            : undefined;
                        const limit = req.query.limit
                            ? parseInt(req.query.limit as string)
                            : undefined;
                        const offset = req.query.offset
                            ? parseInt(req.query.offset as string)
                            : undefined;

                        // Validate pagination parameters
                        if (page !== undefined && (isNaN(page) || page < 1)) {
                            res.status(400).json({
                                error: 'Invalid pagination parameter',
                                message:
                                    'Page must be a positive integer starting from 1',
                            });
                            return;
                        }

                        if (
                            limit !== undefined &&
                            (isNaN(limit) || limit < 1 || limit > 1000)
                        ) {
                            res.status(400).json({
                                error: 'Invalid pagination parameter',
                                message:
                                    'Limit must be a positive integer between 1 and 1000',
                            });
                            return;
                        }

                        if (
                            offset !== undefined &&
                            (isNaN(offset) || offset < 0)
                        ) {
                            res.status(400).json({
                                error: 'Invalid pagination parameter',
                                message:
                                    'Offset must be a non-negative integer',
                            });
                            return;
                        }

                        // Parse sorting parameters
                        const orderBy = req.query.orderBy as string;
                        const sortDirection =
                            (req.query.sort as string) || 'asc';

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
                        for (const [key, value] of Object.entries(req.query)) {
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
                        for (const [key, value] of Object.entries(req.query)) {
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
                                    query = query.where(key).eq(value);
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
                                req.query
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
                                        countQuery = countQuery
                                            .where(key)
                                            .eq(value);
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
            const middleware = config.POST.middleware || [];
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

                        // Check for suspicious payloads (large objects, deep nesting)
                        const dataString = JSON.stringify(data);
                        if (dataString.length > 10000) {
                            // 10KB limit
                            res.status(413).json({
                                error: 'Payload too large',
                                message: 'Request body exceeds size limit',
                            });
                            return;
                        }

                        // Prevent prototype pollution by checking for dangerous keys
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
            const middleware = config.PUT.middleware || [];
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

                        // Check for suspicious payloads
                        const dataString = JSON.stringify(data);
                        if (dataString.length > 10000) {
                            // 10KB limit
                            res.status(413).json({
                                error: 'Payload too large',
                                message: 'Request body exceeds size limit',
                            });
                            return;
                        }

                        // Prevent prototype pollution
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
            const middleware = config.DELETE.middleware || [];
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
