import { type Request, type Response, type NextFunction } from 'express';

export const loggingMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const start = Date.now();
    const timestamp = new Date().toISOString();

    console.log(`[${timestamp}] ${req.method} ${req.path} - Started`);

    // Log request body for POST/PUT requests
    if ((req.method === 'POST' || req.method === 'PUT') && req.body) {
        console.log(
            `[${timestamp}] Request body:`,
            JSON.stringify(req.body, null, 2)
        );
    }

    // Override res.json to log response
    const originalJson = res.json;
    res.json = function (body) {
        const duration = Date.now() - start;
        console.log(
            `[${timestamp}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`
        );

        if (res.statusCode >= 400) {
            console.log(
                `[${timestamp}] Error response:`,
                JSON.stringify(body, null, 2)
            );
        }

        return originalJson.call(this, body);
    };

    next();
};

export const requestIdMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const requestId =
        req.headers['x-request-id'] || Math.random().toString(36).substr(2, 9);

    // Add request ID to request object
    (req as any).requestId = requestId;

    // Add request ID to response headers
    res.setHeader('X-Request-ID', requestId);

    next();
};
