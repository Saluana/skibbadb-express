import { type Request, type Response, type NextFunction } from 'express';

export const validatePost = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const { title, content } = req.body;

    const errors: string[] = [];

    if (!title || typeof title !== 'string' || title.trim().length === 0) {
        errors.push('Title is required and must be a non-empty string');
    }

    if (title && title.length > 200) {
        errors.push('Title must be less than 200 characters');
    }

    if (content && typeof content !== 'string') {
        errors.push('Content must be a string');
    }

    if (errors.length > 0) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors,
        });
    }

    next();
};

export const validateComment = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const { content } = req.body;

    const errors: string[] = [];

    if (
        !content ||
        typeof content !== 'string' ||
        content.trim().length === 0
    ) {
        errors.push('Content is required and must be a non-empty string');
    }

    if (content && content.length > 1000) {
        errors.push('Content must be less than 1000 characters');
    }

    if (errors.length > 0) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors,
        });
    }

    next();
};

export const validateTodo = (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const { title, description } = req.body;

    const errors: string[] = [];

    if (!title || typeof title !== 'string' || title.trim().length === 0) {
        errors.push('Title is required and must be a non-empty string');
    }

    if (title && title.length > 100) {
        errors.push('Title must be less than 100 characters');
    }

    if (description && typeof description !== 'string') {
        errors.push('Description must be a string');
    }

    if (description && description.length > 500) {
        errors.push('Description must be less than 500 characters');
    }

    if (errors.length > 0) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors,
        });
    }

    next();
};
