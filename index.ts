/* ---------------------------------------------------------------------------
   Imports & re‑exports
--------------------------------------------------------------------------- */
import express, {
    type Request,
    type Response,
    type RequestHandler,
    type NextFunction,
} from 'express';
import { Database, Collection } from 'skibbadb';
import { z } from 'zod'; // Ensure z is imported
import {
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
import rateLimit from 'express-rate-limit';

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
};
export type { SanitizationConfig } from './middleware/security.js';

/* ---------------------------------------------------------------------------
   Public typing (unchanged)
--------------------------------------------------------------------------- */
export interface MethodHooks {
    beforeQuery?: (query: any, req: Request) => Promise<any>;
    afterQuery?: (results: any[], req: Request) => Promise<any[]>;

    beforeCreate?: (data: any, req: Request) => Promise<any>;
    afterCreate?: (result: any, req: Request) => Promise<any>;

    beforeUpdate?: (id: string, data: any, req: Request) => Promise<any>;
    afterUpdate?: (result: any, req: Request) => Promise<any>;

    beforeDelete?: (id: string, req: Request) => Promise<boolean>;
    afterDelete?: (id: string, req: Request) => Promise<void>;
}

export interface MethodConfig {
    middleware?: RequestHandler[];
    hooks?: MethodHooks;
    rateLimitOptions?: { windowMs?: number; max?: number };
    uploadLimitOptions?: { jsonLimit?: string; urlEncodedLimit?: string };
}

export interface CollectionConfig {
    GET?: MethodConfig;
    POST?: MethodConfig;
    PUT?: MethodConfig;
    DELETE?: MethodConfig;
    basePath?: string;
    middleware?: RequestHandler[];
    rateLimitOptions?: { windowMs?: number; max?: number; strict?: boolean };
    uploadLimitOptions?: { jsonLimit?: string; urlEncodedLimit?: string };
}

export interface SkibbaExpressApp extends express.Application {
    useCollection<T extends z.ZodType<any, z.ZodTypeDef, any>>(
        collection: Collection<T>,
        config?: CollectionConfig
    ): void;
}

export type { Database, Collection } from 'skibbadb';
export type { Request, Response, RequestHandler, NextFunction } from 'express';

/* ---------------------------------------------------------------------------
   Internal constants & helpers
--------------------------------------------------------------------------- */
const KB = 1024,
    MB = KB * 1024,
    GB = MB * 1024;
const parseSizeFast = (s: string | undefined, def = 50 * KB) => {
    if (!s) return def;
    const [, num, unit] = /^(\d+(?:\.\d+)?)(kb|mb|gb)?$/i.exec(s.trim()) ?? [];
    if (!num) return def;
    const n = parseFloat(num);
    switch ((unit ?? 'b').toLowerCase()) {
        case 'gb':
            return n * GB;
        case 'mb':
            return n * MB;
        case 'kb':
            return n * KB;
        default:
            return n;
    }
};

const DANGEROUS_KEY_RX = /^(?:__proto__|constructor|prototype)$/;
const hasDangerousKeys = (o: any): boolean => {
    if (!o || typeof o !== 'object') return false;
    for (const k of Object.keys(o)) if (DANGEROUS_KEY_RX.test(k)) return true;
    /* deep scan only if shallow pass OK */
    const stack = [o];
    while (stack.length) {
        const cur = stack.pop();
        if (cur && typeof cur === 'object')
            for (const k of Object.keys(cur)) {
                if (DANGEROUS_KEY_RX.test(k)) return true;
                if (cur[k] && typeof cur[k] === 'object') stack.push(cur[k]);
            }
    }
    return false;
};

const toUInt = (
    raw: string | undefined,
    name: string,
    min: number,
    max = Number.MAX_SAFE_INTEGER
): number | undefined => {
    if (raw === undefined || raw === '') return;
    if (!/^\d+$/.test(raw.trim())) throw new Error(`${name} must be integer`);
    const n = parseInt(raw, 10);
    if (n < min || n > max) throw new Error(`${name} out of range`);
    return n;
};

/* ---------------------------------------------------------------------------
   Rate‑limit / size‑guard factory helpers
--------------------------------------------------------------------------- */
const buildRateLimiter = (o: CollectionConfig['rateLimitOptions'] = {}) =>
    rateLimit({
        windowMs: o.windowMs ?? 15 * 60_000,
        max: o.max ?? 100,
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
            return;
        },
    });

const buildStrictRateLimiter = (o: CollectionConfig['rateLimitOptions'] = {}) =>
    rateLimit({
        windowMs: o.windowMs ?? 15 * 60_000,
        max: o.max ?? 30,
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => req.method === 'GET',
        message: {
            error: 'Too many requests',
            message:
                'Write operation rate limit exceeded. Please try again later.',
        },
        handler: (req, res) => {
            console.warn(`🚨 Write‑rate limit exceeded for ${req.ip}`);
            res.status(429).json({
                error: 'Too many requests',
                message:
                    'Write operation rate limit exceeded. Please try again later.',
            });
            return;
        },
    });

const buildUploadGuard = (o: CollectionConfig['uploadLimitOptions'] = {}) => {
    const jsonMax = parseSizeFast(o.jsonLimit);
    const urlMax = parseSizeFast(o.urlEncodedLimit);
    return ((req: Request, res: Response, next: NextFunction) => {
        const len = Number(req.headers['content-length'] ?? 0);
        if (!len) return next();
        const ct = req.headers['content-type'] ?? '';
        if (
            (ct.includes('application/json') && len > jsonMax) ||
            (ct.includes('application/x-www-form-urlencoded') && len > urlMax)
        ) {
            res.status(413).json({
                error: 'Payload too large',
                message: 'Request body exceeds size limit',
            });
            return;
        }
        next();
    }) as RequestHandler;
};

/* ---------------------------------------------------------------------------
   createSkibbaExpress
--------------------------------------------------------------------------- */
export function createSkibbaExpress(
    app: express.Application,
    _db: Database,
    global?: {
        uploadLimitOptions?: { jsonLimit?: string; urlEncodedLimit?: string };
    }
): SkibbaExpressApp {
    app.use(
        express.json({ limit: global?.uploadLimitOptions?.jsonLimit ?? '50kb' })
    );
    app.use(
        express.urlencoded({
            extended: true,
            limit: global?.uploadLimitOptions?.urlEncodedLimit ?? '50kb',
        })
    );

    app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
        if (err instanceof SyntaxError && 'body' in err) {
            res.status(400).json({
                error: 'Invalid JSON',
                message: 'Malformed JSON body',
            });
            return;
        }
        if (err?.type === 'entity.too.large') {
            res.status(413).json({
                error: 'Payload too large',
                message: 'Body exceeds limit',
            });
            return;
        }
        next(err);
    });

    (app as any).useCollection = function <
        T extends z.ZodType<any, z.ZodTypeDef, any>
    >(collection: Collection<T>, cfg: CollectionConfig = {}) {
        const base =
            cfg.basePath ?? `/${(collection as any).collectionSchema.name}`;
        const router = express.Router();

        /* schema keys (cached one‑time) */
        const schemaShape = (() => {
            const s = (collection as any).collectionSchema.schema;
            if ('shape' in s) return Object.keys(s.shape);
            if (s._def?.shape) return Object.keys(s._def.shape);
            if (typeof s._def?.shape === 'function')
                return Object.keys(s._def.shape());
            return [];
        })();
        const validField = new Set(schemaShape);
        const isValidField = (f: string) =>
            f.includes('.') || validField.has(f);

        if (cfg.middleware) router.use(...cfg.middleware);
        router.use(buildUploadGuard(cfg.uploadLimitOptions));
        if (cfg.rateLimitOptions) {
            router.use(buildRateLimiter(cfg.rateLimitOptions));
            if (cfg.rateLimitOptions.strict)
                router.use(buildStrictRateLimiter(cfg.rateLimitOptions));
        }

        router.param('id', (req, res, next, id) => {
            if (typeof id !== 'string' || id.length > 100) {
                res.status(400).json({
                    error: 'Invalid ID',
                    message: 'Bad ID',
                });
                return;
            }
            req.params.id = sanitizeInput(id);
            next();
        });

        const methodMW = (m?: MethodConfig): RequestHandler[] =>
            m
                ? [
                      ...(m.uploadLimitOptions
                          ? [buildUploadGuard(m.uploadLimitOptions)]
                          : []),
                      ...(m.rateLimitOptions
                          ? [buildRateLimiter(m.rateLimitOptions)]
                          : []),
                      ...(m.middleware ?? []),
                  ]
                : [];

        /* =========================================================== GET /:id */
        if (cfg.GET) {
            router.get('/:id', ...methodMW(cfg.GET), async (req, res, next) => {
                try {
                    let q = collection.where('id' as any).eq(req.params.id);
                    if (cfg.GET!.hooks?.beforeQuery)
                        q = await cfg.GET!.hooks.beforeQuery(q, req);
                    const doc = await q.first();
                    if (!doc) {
                        res.status(404).json({ error: 'Not found' });
                        return;
                    }
                    const out = cfg.GET!.hooks?.afterQuery
                        ? await cfg.GET!.hooks.afterQuery([doc], req)
                        : [doc];
                    res.json(out[0]);
                    return;
                } catch (e) {
                    next(e);
                }
            });
        }

        /* =========================================================== GET list */
        if (cfg.GET) {
            router.get('/', ...methodMW(cfg.GET), async (req, res, next) => {
                try {
                    const qParams = req.query as Record<string, any>;
                    /* fast primitive extractions */

                    let page: number | undefined,
                        limit: number | undefined,
                        offset: number | undefined;
                    try {
                        page = toUInt(qParams.page as string, 'Page', 1);
                        limit = toUInt(
                            qParams.limit as string,
                            'Limit',
                            1,
                            1000
                        );
                        offset = toUInt(qParams.offset as string, 'Offset', 0);
                    } catch (err: any) {
                        res.status(400).json({
                            error: 'Invalid pagination parameter',
                            message: err.message,
                        });
                        return;
                    }
                    const needMeta = page !== undefined && limit !== undefined;

                    const orderBy = qParams.orderBy as string | undefined;
                    const sortDir = (
                        (qParams.sort as string) ?? 'asc'
                    ).toLowerCase();

                    if (orderBy && !['asc', 'desc'].includes(sortDir)) {
                        res.status(400).json({
                            error: 'Invalid sort parameter',
                            message:
                                'Sort direction must be either "asc" or "desc"',
                        });
                        return;
                    }
                    if (orderBy && !isValidField(orderBy)) {
                        res.status(400).json({
                            error: 'Invalid sort parameter',
                            message: `Unknown field ${orderBy}`,
                        });
                        return;
                    }

                    const selectParam = qParams.select as string | undefined;
                    let selectFields: string[] | undefined;

                    if (selectParam) {
                        let parsedJson: any;
                        try {
                            parsedJson = JSON.parse(selectParam);
                        } catch (e) {
                            res.status(400).json({
                                error: 'Invalid select parameter',
                                message: 'Invalid JSON format for select parameter.',
                            });
                            return;
                        }

                        const selectSchema = z.array(z.string().min(1)).min(1); // min(1) on array ensures not empty
                        const validationResult = selectSchema.safeParse(parsedJson);

                        if (!validationResult.success) {
                            res.status(400).json({
                                error: 'Invalid select parameter format',
                                details: validationResult.error.flatten(),
                            });
                            return;
                        }

                        // Now validationResult.data is the validated array of non-empty strings
                        selectFields = validationResult.data.map(f => f.trim()); // Trim after validation

                        for (const field of selectFields) {
                            // The individual string format (non-empty) is already validated by Zod.
                            // We still need to check if the field name is valid against the schema.
                            if (!isValidField(field)) { // field is already trimmed
                                res.status(400).json({
                                    error: 'Invalid select parameter',
                                    message: `Unknown field '${field}' in select parameter.`,
                                });
                                return;
                            }
                        }
                    }

                    /* build predicate list once with optimizations */
                    type Pred = (q: any) => any;
                    const preds: Pred[] = [];
                    const reserved = new Set([
                        'page',
                        'limit',
                        'offset',
                        'orderBy',
                        'sort',
                        'select',
                    ]);

                    for (const [rawKey, value] of Object.entries(qParams)) {
                        if (
                            reserved.has(rawKey) ||
                            value === '' ||
                            value === undefined
                        )
                            continue;

                        // Determine suffix and field
                        const suffixes = [
                            '_gt',
                            '_gte',
                            '_lt',
                            '_lte',
                            '_like',
                            '_in',
                            '_contains',
                        ];
                        const suf = suffixes.find((s) => rawKey.endsWith(s));
                        const field = suf
                            ? rawKey.slice(0, -suf.length)
                            : rawKey;

                        if (!isValidField(field)) {
                            res.status(400).json({
                                error: 'Invalid filter parameter',
                                message: `Invalid field ${field}`,
                            });
                            return;
                        }

                        // Quick win #2: Store normalized value once
                        const vNorm =
                            value === 'true'
                                ? true
                                : value === 'false'
                                ? false
                                : !isNaN(Number(value as string))
                                ? Number(value)
                                : value;

                        // Quick win #1: Memoize converted array for _in
                        if (suf === '_in') {
                            let inArr: any[];

                            if (Array.isArray(value)) {
                                inArr = value;
                            } else if (
                                typeof value === 'string' &&
                                value.startsWith('[') &&
                                value.endsWith(']')
                            ) {
                                // Parse JSON array string like '["admin", "user"]'
                                try {
                                    inArr = JSON.parse(value);
                                    if (!Array.isArray(inArr)) {
                                        inArr = [value]; // fallback if JSON parsing doesn't return array
                                    }
                                } catch (e) {
                                    inArr = [value]; // fallback if JSON parsing fails
                                }
                            } else {
                                inArr = [value];
                            }

                            // Normalize each value in the array once
                            const normalizedArr = inArr.map((v) =>
                                v === 'true'
                                    ? true
                                    : v === 'false'
                                    ? false
                                    : !isNaN(Number(v))
                                    ? Number(v)
                                    : v
                            );

                            // Check if the field is an array type in the schema
                            // We need to check the actual schema shape to determine if this is an array field
                            let isArrayField = false;
                            try {
                                const s = (collection as any).collectionSchema
                                    .schema;
                                if ('shape' in s && s.shape[field]) {
                                    const fieldSchema = s.shape[field];
                                    // Check for ZodArray or ZodDefault wrapping a ZodArray
                                    isArrayField =
                                        fieldSchema._def?.typeName ===
                                            'ZodArray' ||
                                        (fieldSchema._def?.typeName ===
                                            'ZodDefault' &&
                                            fieldSchema._def?.innerType?._def
                                                ?.typeName === 'ZodArray');
                                } else if (
                                    s._def?.shape &&
                                    s._def.shape[field]
                                ) {
                                    const fieldSchema = s._def.shape[field];
                                    // Check for ZodArray or ZodDefault wrapping a ZodArray
                                    isArrayField =
                                        fieldSchema._def?.typeName ===
                                            'ZodArray' ||
                                        (fieldSchema._def?.typeName ===
                                            'ZodDefault' &&
                                            fieldSchema._def?.innerType?._def
                                                ?.typeName === 'ZodArray');
                                } else if (
                                    typeof s._def?.shape === 'function'
                                ) {
                                    const shapeObj = s._def.shape();
                                    if (shapeObj[field]) {
                                        const fieldSchema = shapeObj[field];
                                        // Check for ZodArray or ZodDefault wrapping a ZodArray
                                        isArrayField =
                                            fieldSchema._def?.typeName ===
                                                'ZodArray' ||
                                            (fieldSchema._def?.typeName ===
                                                'ZodDefault' &&
                                                fieldSchema._def?.innerType
                                                    ?._def?.typeName ===
                                                    'ZodArray');
                                    }
                                }
                            } catch (e) {
                                // Fallback: assume it's an array field if the field name suggests it
                                isArrayField =
                                    field === 'roles' ||
                                    field.includes('array') ||
                                    field.endsWith('s');
                            }

                            if (isArrayField) {
                                // For array fields, we need to check if the array contains ALL of the values (AND logic)
                                // Use arrayContains method which works perfectly for this use case
                                normalizedArr.forEach((val) => {
                                    preds.push((q) =>
                                        q.where(field).arrayContains(val)
                                    );
                                });
                            } else {
                                // For scalar fields, use normal .in() operation
                                preds.push((q) =>
                                    q.where(field).in(normalizedArr)
                                );
                            }
                        } else if (suf === '_contains') {
                            // _contains operator for array fields - use arrayContains method
                            // Use the original string value, not the normalized one
                            preds.push((q) =>
                                q.where(field).arrayContains(value)
                            );
                        } else if (suf === '_gt') {
                            preds.push((q) => q.where(field).gt(vNorm));
                        } else if (suf === '_gte') {
                            preds.push((q) => q.where(field).gte(vNorm));
                        } else if (suf === '_lt') {
                            preds.push((q) => q.where(field).lt(vNorm));
                        } else if (suf === '_lte') {
                            preds.push((q) => q.where(field).lte(vNorm));
                        } else if (suf === '_like') {
                            preds.push((q) => q.where(field).like(vNorm));
                        } else {
                            // Equality filter
                            preds.push((q) => q.where(field).eq(vNorm));
                        }
                    }

                    // Quick win #4: Build predicates once and reuse
                    const buildQuery = (baseQuery: any) => {
                        let q = baseQuery;
                        preds.forEach((p) => (q = p(q)));
                        return q;
                    };

                    /* apply predicates */
                    let rowQ = buildQuery(collection.query());
                    let countQ: any;
                    if (needMeta) {
                        countQ = buildQuery(collection.query());
                    }

                    if (orderBy)
                        rowQ = rowQ.orderBy(orderBy, sortDir as 'asc' | 'desc');

                    if (selectFields && selectFields.length > 0) {
                        rowQ = rowQ.select(selectFields);
                    }

                    if (page && limit) rowQ = rowQ.page(page, limit);
                    else {
                        if (limit) rowQ = rowQ.limit(limit);
                        if (offset) rowQ = rowQ.offset(offset);
                    }

                    if (cfg.GET!.hooks?.beforeQuery)
                        rowQ = await cfg.GET!.hooks.beforeQuery(rowQ, req);

                    // Quick win #3: Skip limit(fetchLim) when needMeta is false
                    const rows = await (needMeta
                        ? rowQ.limit(limit! + 1).toArray()
                        : rowQ.toArray());
                    const slicedRows = needMeta ? rows.slice(0, limit) : rows;

                    /* post‑hook */
                    const finalRows = cfg.GET!.hooks?.afterQuery
                        ? await cfg.GET!.hooks.afterQuery(slicedRows, req)
                        : slicedRows;

                    if (needMeta) {
                        let totalCount: number;
                        if (
                            rows.length <= limit! &&
                            page === 1 &&
                            offset === undefined
                        ) {
                            /* fast path – we already have full set */
                            totalCount = rows.length;
                        } else {
                            /* use pre-built count query */
                            totalCount = await countQ.executeCount();
                        }
                        const totalPages = Math.ceil(totalCount / limit!);
                        res.json({
                            data: finalRows,
                            pagination: {
                                page,
                                limit,
                                totalCount,
                                totalPages,
                                hasNextPage: page! < totalPages,
                                hasPreviousPage: page! > 1,
                            },
                        });
                        return;
                    }
                    res.json(finalRows);
                    return;
                } catch (e) {
                    next(e);
                }
            });
        }

        /* =========================================================== POST */
        if (cfg.POST) {
            router.post('/', ...methodMW(cfg.POST), async (req, res, next) => {
                try {
                    let data = req.body;
                    if (
                        !data ||
                        typeof data !== 'object' ||
                        Array.isArray(data)
                    ) {
                        res.status(400).json({
                            error: 'Invalid request body',
                            message: 'Request body must be a valid JSON object',
                        });
                        return;
                    }
                    if (hasDangerousKeys(data)) {
                        res.status(400).json({
                            error: 'Security violation',
                            message: 'Dangerous object keys',
                        });
                        return;
                    }
                    if (cfg.POST!.hooks?.beforeCreate)
                        data = await cfg.POST!.hooks.beforeCreate(data, req);
                    let doc = await collection.insert(data);
                    if (cfg.POST!.hooks?.afterCreate)
                        doc = await cfg.POST!.hooks.afterCreate(doc, req);
                    res.status(201).json(doc);
                    return;
                } catch (e: any) {
                    handleDbErrors(e, res) || next(e);
                }
            });
        }

        /* =========================================================== PUT */
        if (cfg.PUT) {
            router.put('/:id', ...methodMW(cfg.PUT), async (req, res, next) => {
                try {
                    let data = req.body;
                    if (
                        !data ||
                        typeof data !== 'object' ||
                        Array.isArray(data)
                    ) {
                        res.status(400).json({
                            error: 'Invalid request body',
                            message: 'Request body must be a valid JSON object',
                        });
                        return;
                    }
                    if (hasDangerousKeys(data)) {
                        res.status(400).json({
                            error: 'Security violation',
                            message: 'Dangerous object keys',
                        });
                        return;
                    }
                    if (cfg.PUT!.hooks?.beforeUpdate)
                        data = await cfg.PUT!.hooks.beforeUpdate(
                            req.params.id,
                            data,
                            req
                        );
                    let doc = await collection.put(req.params.id, data);
                    if (cfg.PUT!.hooks?.afterUpdate)
                        doc = await cfg.PUT!.hooks.afterUpdate(doc, req);
                    res.json(doc);
                    return;
                } catch (e: any) {
                    handleDbErrors(e, res) || next(e);
                }
            });
        }

        /* =========================================================== DELETE */
        if (cfg.DELETE) {
            router.delete(
                '/:id',
                ...methodMW(cfg.DELETE),
                async (req, res, next) => {
                    try {
                        let ok = true;
                        if (cfg.DELETE!.hooks?.beforeDelete)
                            ok = await cfg.DELETE!.hooks.beforeDelete(
                                req.params.id,
                                req
                            );
                        if (ok) await collection.delete(req.params.id);
                        if (cfg.DELETE!.hooks?.afterDelete)
                            await cfg.DELETE!.hooks.afterDelete(
                                req.params.id,
                                req
                            );
                        res.status(204).send();
                        return;
                    } catch (e) {
                        next(e);
                    }
                }
            );
        }

        app.use(base, router);
    };

    return app as unknown as SkibbaExpressApp;
}

/* ---------------------------------------------------------------------------
   DB‑error → HTTP helper
--------------------------------------------------------------------------- */
const handleDbErrors = (err: any, res: Response) => {
    const msg = err.message ?? '';
    if (err.name === 'ZodError') {
        res.status(400).json({
            error: 'Validation failed',
            details: err.errors,
        });
        return true;
    }
    if (msg.includes('UNIQUE constraint failed')) {
        const field =
            /UNIQUE constraint failed: \w+\.(\w+)/.exec(msg)?.[1] ?? 'field';
        res.status(409).json({
            error: 'Constraint violation',
            message: `${field} already exists`,
        });
        return true;
    }
    if (msg.includes('Document validation failed')) {
        res.status(400).json({
            error: 'Validation failed',
            message: 'Document validation failed',
        });
        return true;
    }
    if (msg.includes('NOT NULL') || msg.includes('constraint')) {
        res.status(400).json({
            error: 'Database constraint violation',
            message: msg,
        });
        return true;
    }
    return false;
};

export default createSkibbaExpress;
