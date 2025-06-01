import { type Request, type Response, type NextFunction } from 'express';

// Extend Express Request type to include user
declare global {
    namespace Express {
        interface Request {
            user?: {
                id: string;
                email: string;
                isAdmin: boolean;
            };
        }
    }
}

export const authMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Authorization required' });
        return;
    }

    const token = authHeader.slice(7);

    // In a real app, you'd verify the JWT token here
    // For demo purposes, we'll decode a simple format: "user:id:email:isAdmin"
    try {
        const [prefix, id, email, isAdmin] = token.split(':');

        if (prefix !== 'user') {
            throw new Error('Invalid token format');
        }

        req.user = {
            id,
            email,
            isAdmin: isAdmin === 'true',
        };

        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
        return;
    }
};

export const requireAuth = authMiddleware;

export const requireAdmin = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    if (!req.user?.isAdmin) {
        res.status(403).json({ error: 'Admin access required' });
        return;
    }
    next();
};

export const ownershipMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    // This would typically check if the user owns the resource
    // For demo purposes, we'll just check if user exists
    if (!req.user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
    }

    // In a real app, you'd verify ownership here
    // e.g., check if req.user.id matches the resource's authorId

    next();
};
