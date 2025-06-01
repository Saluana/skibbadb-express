import express, {
    type Request,
    type Response,
    type RequestHandler,
    type NextFunction,
} from 'express';
import { Database, Collection } from 'skibbadb';
import { z } from 'zod';
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

export function createSkibbaExpress(database: Database): SkibbaExpressApp {
    const app = express();

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

            // GET / - Get all items (with pagination)
            router.get(
                '/',
                ...middleware,
                async (req: Request, res: Response, next: NextFunction) => {
                    try {
                        let query = collection.query();

                        // Apply beforeQuery hook
                        if (config.GET?.hooks?.beforeQuery) {
                            query = await config.GET.hooks.beforeQuery(
                                query,
                                req
                            );
                        }

                        const results = await query.toArray();

                        // Apply afterQuery hook
                        let finalResults = results;
                        if (config.GET?.hooks?.afterQuery) {
                            finalResults = await config.GET.hooks.afterQuery(
                                results,
                                req
                            );
                        }

                        res.json(finalResults);
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
