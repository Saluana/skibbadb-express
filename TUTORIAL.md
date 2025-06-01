# SkibbaDB Express Tutorial

A comprehensive guide to building secure REST APIs with SkibbaDB Express - a powerful wrapper that combines SkibbaDB with Express.js middleware, hooks, and enterprise-grade security features.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Basic Usage](#basic-usage)
6. [Advanced Features](#advanced-features)
7. [Security Implementation](#security-implementation)
8. [Middleware Configuration](#middleware-configuration)
9. [Hooks System](#hooks-system)
10. [Error Handling](#error-handling)
11. [Testing](#testing)
12. [Best Practices](#best-practices)
13. [Troubleshooting](#troubleshooting)

## Introduction

SkibbaDB Express is a secure, feature-rich REST API framework that wraps SkibbaDB (a lightweight TypeScript database) with Express.js routing, comprehensive security middleware, and flexible hooks system. It provides:

-   **Automatic REST API generation** from SkibbaDB collections
-   **Enterprise-grade security** (XSS, SQL injection, CSRF protection)
-   **Flexible middleware system** with per-method configuration
-   **Powerful hooks system** for custom business logic
-   **Built-in input validation** with Zod schema integration
-   **Rate limiting and DDoS protection**
-   **Comprehensive error handling**

## Installation

### Prerequisites

-   Node.js 18+ or Bun
-   TypeScript knowledge
-   Basic Express.js familiarity

### Setup

```bash
# Using npm
npm install skibbadb express zod
npm install -D @types/express typescript

# Using bun (recommended)
bun add skibbadb express zod
bun add -d @types/express typescript

# Install security dependencies
npm install helmet express-rate-limit dompurify jsdom
npm install -D @types/dompurify
```

### Project Structure

```
your-project/
├── src/
│   ├── index.ts              # Main application
│   ├── collections/          # Database collections
│   ├── middleware/           # Custom middleware
│   │   ├── security.ts       # Security middleware
│   │   └── auth.ts          # Authentication
│   └── routes/              # Additional routes
├── tests/                   # Test files
├── package.json
└── tsconfig.json
```

## Quick Start

Here's a minimal example to get you started:

```typescript
import express from 'express';
import { Database } from 'skibbadb';
import { createSkibbaExpress } from 'skibbadb-express';
import { z } from 'zod';

// Create Express app and database
const app = express();
const db = new Database({ path: 'myapp.db' });

// Define a schema using Zod
const userSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    createdAt: z.string(),
});

// Create a collection
const users = db.collection('users', userSchema);

// Create SkibbaDB Express instance
const skibba = createSkibbaExpress(app, db);

// Register the collection (automatically creates REST endpoints)
skibba.useCollection(users, {
    basePath: '/api/users',
});

// Start the server
app.listen(3000, () => {
    console.log('🚀 Server running on http://localhost:3000');
});
```

This creates the following endpoints:

-   `GET /api/users` - List all users
-   `GET /api/users/:id` - Get user by ID
-   `POST /api/users` - Create new user
-   `PUT /api/users/:id` - Update user
-   `DELETE /api/users/:id` - Delete user

## Core Concepts

### Collections

Collections are the foundation of SkibbaDB Express. Each collection represents a data model with:

```typescript
const productSchema = z.object({
    id: z.string(),
    name: z.string(),
    price: z.number().positive(),
    category: z.string(),
    description: z.string().optional(),
    inStock: z.boolean().default(true),
    createdAt: z.string(),
    updatedAt: z.string().optional(),
});

const products = db.collection('products', productSchema, {
    constrainedFields: {
        name: { unique: true, nullable: false },
        price: { nullable: false },
        category: { nullable: false },
    },
});
```

### Method Configuration

Each HTTP method can have its own configuration:

```typescript
interface MethodConfig {
    middleware?: RequestHandler[]; // Custom middleware
    hooks?: MethodHooks; // Business logic hooks
}
```

### Collection Configuration

```typescript
interface CollectionConfig {
    GET?: MethodConfig; // GET method config
    POST?: MethodConfig; // POST method config
    PUT?: MethodConfig; // PUT method config
    DELETE?: MethodConfig; // DELETE method config
    basePath?: string; // Custom base path
    middleware?: RequestHandler[]; // Global middleware
}
```

## Basic Usage

### Creating Collections with Constraints

```typescript
const userSchema = z.object({
    id: z.string(),
    username: z.string().min(3).max(50),
    email: z.string().email(),
    password: z.string().min(8), // Will be hashed
    role: z.enum(['user', 'admin']).default('user'),
    profile: z.object({
        firstName: z.string(),
        lastName: z.string(),
        avatar: z.string().url().optional(),
    }),
    preferences: z.record(z.any()).default({}),
    isActive: z.boolean().default(true),
    createdAt: z.string(),
    updatedAt: z.string().optional(),
});

const users = db.collection('users', userSchema, {
    constrainedFields: {
        username: { unique: true, nullable: false },
        email: { unique: true, nullable: false },
        password: { nullable: false },
    },
});
```

### Basic Collection Registration

```typescript
// Simple registration with default settings
skibba.useCollection(users);

// Custom base path
skibba.useCollection(users, {
    basePath: '/api/v1/users',
});

// Method-specific configuration
skibba.useCollection(users, {
    GET: {
        middleware: [authMiddleware, rateLimitMiddleware],
    },
    POST: {
        middleware: [authMiddleware, validationMiddleware],
    },
    PUT: {
        middleware: [authMiddleware, ownershipMiddleware],
    },
    DELETE: {
        middleware: [authMiddleware, adminMiddleware],
    },
});
```

### Working with Endpoints

Once registered, your collection automatically gets REST endpoints:

#### GET Requests

```bash
# Get all users (with pagination)
GET /api/users?page=1&limit=10&sort=createdAt&order=desc

# Search users
GET /api/users?search=john&fields=username,email

# Filter users
GET /api/users?role=admin&isActive=true

# Get single user
GET /api/users/user-123
```

#### POST Requests

```bash
# Create new user
POST /api/users
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "securePassword123",
    "profile": {
        "firstName": "John",
        "lastName": "Doe"
    }
}
```

#### PUT Requests

```bash
# Update user
PUT /api/users/user-123
Content-Type: application/json

{
    "profile": {
        "firstName": "John",
        "lastName": "Smith"
    },
    "preferences": {
        "theme": "dark",
        "notifications": true
    }
}
```

#### DELETE Requests

```bash
# Delete user
DELETE /api/users/user-123
```

## Advanced Features

### Relationship Handling

```typescript
// Posts collection with user relationship
const postSchema = z.object({
    id: z.string(),
    title: z.string(),
    content: z.string(),
    authorId: z.string(), // Foreign key
    tags: z.array(z.string()).default([]),
    publishedAt: z.string().optional(),
    createdAt: z.string(),
});

const posts = db.collection('posts', postSchema);

skibba.useCollection(posts, {
    GET: {
        hooks: {
            afterQuery: async (results, req) => {
                // Populate author information
                for (const post of results) {
                    const author = await users
                        .where('id')
                        .eq(post.authorId)
                        .first();
                    if (author) {
                        (post as any).author = {
                            id: author.id,
                            username: author.username,
                            profile: author.profile,
                        };
                    }
                }
                return results;
            },
        },
    },
    basePath: '/api/posts',
});
```

### Complex Validation

```typescript
const orderSchema = z.object({
    id: z.string(),
    customerId: z.string(),
    items: z
        .array(
            z.object({
                productId: z.string(),
                quantity: z.number().positive(),
                price: z.number().positive(),
            })
        )
        .min(1),
    totalAmount: z.number().positive(),
    status: z.enum([
        'pending',
        'processing',
        'shipped',
        'delivered',
        'cancelled',
    ]),
    shippingAddress: z.object({
        street: z.string(),
        city: z.string(),
        state: z.string(),
        zipCode: z.string(),
        country: z.string(),
    }),
    createdAt: z.string(),
});

const orders = db.collection('orders', orderSchema);

skibba.useCollection(orders, {
    POST: {
        hooks: {
            beforeCreate: async (data, req) => {
                // Calculate total amount
                let totalAmount = 0;

                for (const item of data.items) {
                    const product = await products
                        .where('id')
                        .eq(item.productId)
                        .first();
                    if (!product) {
                        throw new Error(`Product ${item.productId} not found`);
                    }
                    if (!product.inStock) {
                        throw new Error(
                            `Product ${product.name} is out of stock`
                        );
                    }
                    totalAmount += product.price * item.quantity;
                }

                return {
                    ...data,
                    totalAmount,
                    status: 'pending',
                    createdAt: new Date().toISOString(),
                };
            },
        },
    },
});
```

## Security Implementation

SkibbaDB Express includes comprehensive security features out of the box.

### Security Middleware

```typescript
import {
    securityMiddleware,
    rateLimitMiddleware,
    strictRateLimitMiddleware,
    helmetMiddleware,
    additionalSecurityHeaders,
    validateUserInput,
} from './middleware/security.js';

// Apply global security
app.use(helmetMiddleware);
app.use(additionalSecurityHeaders);

// Collection-specific security
skibba.useCollection(users, {
    GET: {
        middleware: [rateLimitMiddleware], // 100 requests per 15 minutes
    },
    POST: {
        middleware: [
            securityMiddleware, // XSS, SQL injection protection
            strictRateLimitMiddleware, // 5 requests per 15 minutes
            validateUserInput, // Input validation
        ],
    },
    PUT: {
        middleware: [
            securityMiddleware,
            strictRateLimitMiddleware,
            validateUserInput,
        ],
    },
    DELETE: {
        middleware: [strictRateLimitMiddleware],
    },
});
```

### XSS Protection

Automatic XSS sanitization using DOMPurify:

```typescript
// Input: "<script>alert('xss')</script>Hello"
// Output: "Hello" (script tags removed)

// The security middleware automatically sanitizes:
// - Request body
// - Query parameters
// - URL parameters
```

### SQL Injection Protection

Comprehensive SQL injection pattern detection:

```typescript
// Blocked patterns include:
// - UNION SELECT attacks
// - Boolean-based injection
// - Time-based injection
// - Comment-based injection
// - Hex encoding attempts
```

### Input Validation

```typescript
// Custom validation middleware example
export const validateUserInput: RequestHandler = (req, res, next) => {
    const { body } = req;

    // Check for suspicious patterns
    const suspiciousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /expression\s*\(/i,
    ];

    const bodyStr = JSON.stringify(body);
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(bodyStr)) {
            res.status(400).json({
                error: 'Invalid input detected',
                message: 'Request contains potentially malicious content',
            });
            return;
        }
    }

    next();
};
```

### Rate Limiting

```typescript
// Standard rate limiting (100 requests per 15 minutes)
export const rateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Strict rate limiting for sensitive operations (5 requests per 15 minutes)
export const strictRateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        error: 'Too many requests',
        message: 'Strict rate limit exceeded. Please try again later.',
    },
});
```

## Middleware Configuration

### Authentication Middleware

```typescript
// middleware/auth.ts
export const authMiddleware: RequestHandler = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');

        if (!token) {
            res.status(401).json({ error: 'Authentication required' });
            return;
        }

        // Verify JWT token (example)
        const decoded = jwt.verify(token, process.env.JWT_SECRET!);
        req.user = decoded as any;

        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

export const adminMiddleware: RequestHandler = (req, res, next) => {
    if (!req.user?.isAdmin) {
        res.status(403).json({ error: 'Admin access required' });
        return;
    }
    next();
};

export const ownershipMiddleware: RequestHandler = async (req, res, next) => {
    const userId = req.params.id;
    const currentUserId = req.user?.id;

    if (userId !== currentUserId && !req.user?.isAdmin) {
        res.status(403).json({ error: 'Access denied' });
        return;
    }

    next();
};
```

### Logging Middleware

```typescript
// middleware/logging.ts
export const loggingMiddleware: RequestHandler = (req, res, next) => {
    const start = Date.now();
    const { method, url, ip } = req;

    res.on('finish', () => {
        const duration = Date.now() - start;
        const { statusCode } = res;

        console.log(`${method} ${url} ${statusCode} ${duration}ms - ${ip}`);

        // Log to external service if needed
        if (statusCode >= 400) {
            // Log errors
        }
    });

    next();
};
```

### Validation Middleware

```typescript
// middleware/validation.ts
export const createValidationMiddleware = (schema: z.ZodSchema) => {
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            req.body = schema.parse(req.body);
            next();
        } catch (error) {
            if (error instanceof z.ZodError) {
                res.status(400).json({
                    error: 'Validation failed',
                    details: error.errors,
                });
                return;
            }
            next(error);
        }
    };
};

// Usage
const createUserSchema = z.object({
    username: z.string().min(3).max(50),
    email: z.string().email(),
    password: z.string().min(8),
});

skibba.useCollection(users, {
    POST: {
        middleware: [
            authMiddleware,
            createValidationMiddleware(createUserSchema),
            securityMiddleware,
        ],
    },
});
```

## Hooks System

Hooks allow you to inject custom business logic at various points in the request lifecycle.

### Before Hooks

Execute logic before database operations:

```typescript
skibba.useCollection(users, {
    POST: {
        hooks: {
            beforeCreate: async (data, req) => {
                // Hash password before storing
                if (data.password) {
                    data.password = await bcrypt.hash(data.password, 12);
                }

                // Generate ID
                data.id = crypto.randomUUID();

                // Set timestamps
                data.createdAt = new Date().toISOString();

                // Validate business rules
                const existingUser = await users
                    .where('email')
                    .eq(data.email)
                    .first();
                if (existingUser) {
                    throw new Error('Email already exists');
                }

                return data;
            },
        },
    },

    PUT: {
        hooks: {
            beforeUpdate: async (id, data, req) => {
                // Hash password if being updated
                if (data.password) {
                    data.password = await bcrypt.hash(data.password, 12);
                }

                // Update timestamp
                data.updatedAt = new Date().toISOString();

                // Prevent email changes for demo
                delete data.email;

                return data;
            },
        },
    },

    DELETE: {
        hooks: {
            beforeDelete: async (id, req) => {
                // Check if user can be deleted
                const user = await users.where('id').eq(id).first();
                if (user?.role === 'admin' && !req.user?.isSuperAdmin) {
                    throw new Error('Cannot delete admin user');
                }

                // Check for related data
                const userPosts = await posts.where('authorId').eq(id).count();
                if (userPosts > 0) {
                    throw new Error('Cannot delete user with existing posts');
                }

                return true; // Proceed with deletion
            },
        },
    },
});
```

### After Hooks

Execute logic after database operations:

```typescript
skibba.useCollection(users, {
    GET: {
        hooks: {
            afterQuery: async (results, req) => {
                // Hide sensitive data
                return results.map((user) => ({
                    ...user,
                    password: undefined, // Remove password from response
                    email:
                        req.user?.id === user.id || req.user?.isAdmin
                            ? user.email
                            : undefined, // Hide email unless own profile or admin
                }));
            },
        },
    },

    POST: {
        hooks: {
            afterCreate: async (result, req) => {
                // Send welcome email
                await sendWelcomeEmail(result.email, result.profile.firstName);

                // Log user creation
                console.log(
                    `New user created: ${result.username} (${result.email})`
                );

                // Create user profile in external service
                await externalService.createProfile(result);

                // Remove password from response
                return { ...result, password: undefined };
            },
        },
    },

    DELETE: {
        hooks: {
            afterDelete: async (id, req) => {
                // Clean up related data
                await userSessions.where('userId').eq(id).delete();
                await userPreferences.where('userId').eq(id).delete();

                // Notify external services
                await externalService.deleteProfile(id);

                console.log(`User deleted: ${id}`);
            },
        },
    },
});
```

### Query Modification Hooks

Modify queries before execution:

```typescript
skibba.useCollection(posts, {
    GET: {
        hooks: {
            beforeQuery: async (query, req) => {
                // Apply user-specific filters
                if (!req.user?.isAdmin) {
                    // Non-admin users can only see published posts or their own
                    query = query.where((q) =>
                        q
                            .where('publishedAt')
                            .isNotNull()
                            .or()
                            .where('authorId')
                            .eq(req.user.id)
                    );
                }

                return query;
            },

            afterQuery: async (results, req) => {
                // Add computed fields
                for (const post of results) {
                    // Add reading time estimate
                    const wordCount = post.content.split(' ').length;
                    (post as any).readingTime = Math.ceil(wordCount / 200);

                    // Add like count
                    (post as any).likeCount = await likes
                        .where('postId')
                        .eq(post.id)
                        .count();

                    // Check if current user liked the post
                    if (req.user) {
                        const userLike = await likes
                            .where('postId')
                            .eq(post.id)
                            .where('userId')
                            .eq(req.user.id)
                            .first();
                        (post as any).isLikedByUser = !!userLike;
                    }
                }

                return results;
            },
        },
    },
});
```

## Error Handling

SkibbaDB Express includes comprehensive error handling:

### Global Error Handler

```typescript
// Add this after all routes
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('Error:', error);

    // Validation errors
    if (error instanceof z.ZodError) {
        res.status(400).json({
            error: 'Validation failed',
            details: error.errors,
        });
        return;
    }

    // Database errors
    if (error.message.includes('UNIQUE constraint failed')) {
        res.status(409).json({
            error: 'Conflict',
            message: 'Resource already exists',
        });
        return;
    }

    // Custom business logic errors
    if (error.message.includes('Email already exists')) {
        res.status(409).json({
            error: 'Email already registered',
            message: 'Please use a different email address',
        });
        return;
    }

    // Default error response
    res.status(500).json({
        error: 'Internal server error',
        message:
            process.env.NODE_ENV === 'development'
                ? error.message
                : 'Something went wrong',
    });
});
```

### Custom Error Classes

```typescript
// utils/errors.ts
export class ValidationError extends Error {
    constructor(message: string, public field?: string) {
        super(message);
        this.name = 'ValidationError';
    }
}

export class NotFoundError extends Error {
    constructor(resource: string) {
        super(`${resource} not found`);
        this.name = 'NotFoundError';
    }
}

export class UnauthorizedError extends Error {
    constructor(message: string = 'Unauthorized') {
        super(message);
        this.name = 'UnauthorizedError';
    }
}

// Usage in hooks
beforeCreate: async (data, req) => {
    const existingUser = await users.where('email').eq(data.email).first();
    if (existingUser) {
        throw new ValidationError('Email already exists', 'email');
    }
    return data;
};
```

## Testing

### Security Tests

```typescript
// tests/security.test.ts
import request from 'supertest';
import { app } from '../src/app';

describe('Security Tests', () => {
    describe('XSS Protection', () => {
        test('should sanitize XSS in request body', async () => {
            const maliciousData = {
                name: '<script>alert("xss")</script>John',
                bio: '<img src="x" onerror="alert(1)">',
            };

            const response = await request(app)
                .post('/api/users')
                .send(maliciousData)
                .expect(201);

            expect(response.body.name).toBe('John');
            expect(response.body.bio).toBe('');
        });
    });

    describe('SQL Injection Protection', () => {
        test('should block SQL injection attempts', async () => {
            const sqlInjection = "'; DROP TABLE users; --";

            await request(app).get(`/api/users/${sqlInjection}`).expect(400);
        });
    });

    describe('Rate Limiting', () => {
        test('should enforce rate limits', async () => {
            // Make 6 requests (limit is 5)
            for (let i = 0; i < 6; i++) {
                const response = await request(app)
                    .post('/api/users')
                    .send({ name: `User ${i}` });

                if (i < 5) {
                    expect(response.status).not.toBe(429);
                } else {
                    expect(response.status).toBe(429);
                }
            }
        });
    });
});
```

### Integration Tests

```typescript
// tests/api.test.ts
describe('Users API', () => {
    let userId: string;

    test('should create user', async () => {
        const userData = {
            username: 'testuser',
            email: 'test@example.com',
            password: 'password123',
            profile: {
                firstName: 'Test',
                lastName: 'User',
            },
        };

        const response = await request(app)
            .post('/api/users')
            .send(userData)
            .expect(201);

        expect(response.body.username).toBe(userData.username);
        expect(response.body.password).toBeUndefined();
        userId = response.body.id;
    });

    test('should get user by id', async () => {
        const response = await request(app)
            .get(`/api/users/${userId}`)
            .expect(200);

        expect(response.body.id).toBe(userId);
    });

    test('should update user', async () => {
        const updateData = {
            profile: { firstName: 'Updated' },
        };

        const response = await request(app)
            .put(`/api/users/${userId}`)
            .send(updateData)
            .expect(200);

        expect(response.body.profile.firstName).toBe('Updated');
    });

    test('should delete user', async () => {
        await request(app).delete(`/api/users/${userId}`).expect(204);

        await request(app).get(`/api/users/${userId}`).expect(404);
    });
});
```

## Best Practices

### 1. Schema Design

```typescript
// Good: Comprehensive schema with validation
const userSchema = z.object({
    id: z.string(),
    username: z
        .string()
        .min(3, 'Username must be at least 3 characters')
        .max(50, 'Username must not exceed 50 characters')
        .regex(
            /^[a-zA-Z0-9_]+$/,
            'Username can only contain letters, numbers, and underscores'
        ),
    email: z
        .string()
        .email('Invalid email format')
        .max(255, 'Email must not exceed 255 characters'),
    password: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
            'Password must contain uppercase, lowercase, and number'
        ),
    role: z.enum(['user', 'admin', 'moderator']).default('user'),
    isActive: z.boolean().default(true),
    lastLoginAt: z.string().optional(),
    createdAt: z.string(),
    updatedAt: z.string().optional(),
});

// Bad: Minimal validation
const badUserSchema = z.object({
    name: z.string(),
    email: z.string(),
});
```

### 2. Security Configuration

```typescript
// Good: Layered security
skibba.useCollection(users, {
    GET: {
        middleware: [
            authMiddleware, // Authentication
            rateLimitMiddleware, // Rate limiting
            loggingMiddleware, // Audit logging
        ],
    },
    POST: {
        middleware: [
            securityMiddleware, // XSS, SQL injection protection
            strictRateLimitMiddleware, // Strict rate limiting for writes
            validateUserInput, // Input validation
            authMiddleware, // Authentication
        ],
        hooks: {
            beforeCreate: async (data, req) => {
                // Sanitize and validate
                // Hash passwords
                // Generate IDs
                // Set timestamps
                return data;
            },
        },
    },
});

// Bad: No security
skibba.useCollection(users); // Vulnerable to attacks
```

### 3. Error Handling

```typescript
// Good: Specific error handling
beforeCreate: async (data, req) => {
    try {
        // Validate business rules
        const existingUser = await users.where('email').eq(data.email).first();
        if (existingUser) {
            throw new ValidationError('Email already registered', 'email');
        }

        // Process data
        data.password = await bcrypt.hash(data.password, 12);
        data.id = crypto.randomUUID();
        data.createdAt = new Date().toISOString();

        return data;
    } catch (error) {
        if (error instanceof ValidationError) {
            throw error; // Re-throw known errors
        }

        // Log unexpected errors
        console.error('Unexpected error in beforeCreate:', error);
        throw new Error('Failed to create user');
    }
};

// Bad: Generic error handling
beforeCreate: async (data, req) => {
    // Do something...
    return data; // No error handling
};
```

### 4. Performance Optimization

```typescript
// Good: Efficient queries and caching
afterQuery: async (results, req) => {
    // Batch load related data
    const userIds = results.map((post) => post.authorId);
    const authors = await users.where('id').in(userIds).find();
    const authorsMap = new Map(authors.map((author) => [author.id, author]));

    // Efficiently add author data
    for (const post of results) {
        const author = authorsMap.get(post.authorId);
        if (author) {
            (post as any).author = {
                id: author.id,
                username: author.username,
                profile: author.profile,
            };
        }
    }

    return results;
};

// Bad: N+1 queries
afterQuery: async (results, req) => {
    for (const post of results) {
        // This creates N queries!
        const author = await users.where('id').eq(post.authorId).first();
        (post as any).author = author;
    }
    return results;
};
```

### 5. Environment Configuration

```typescript
// config/environment.ts
export const config = {
    port: process.env.PORT || 3000,
    database: {
        path: process.env.DB_PATH || './data/app.db',
    },
    auth: {
        jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
        jwtExpiration: process.env.JWT_EXPIRATION || '24h',
    },
    security: {
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutes
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100'),
        strictRateLimitMax: parseInt(process.env.STRICT_RATE_LIMIT_MAX || '5'),
    },
    email: {
        smtp: {
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || '587'),
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    },
};
```

## Troubleshooting

### Common Issues

#### 1. "Cannot read properties of undefined"

```typescript
// Problem: Accessing nested properties without null checks
afterQuery: async (results, req) => {
    return results.map((user) => ({
        ...user,
        fullName: user.profile.firstName + ' ' + user.profile.lastName, // Error if profile is null
    }));
};

// Solution: Use optional chaining and provide defaults
afterQuery: async (results, req) => {
    return results.map((user) => ({
        ...user,
        fullName:
            user.profile?.firstName && user.profile?.lastName
                ? `${user.profile.firstName} ${user.profile.lastName}`
                : user.username,
    }));
};
```

#### 2. "Rate limit exceeded"

```typescript
// Problem: Too aggressive rate limiting
export const rateLimitMiddleware = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 1, // Only 1 request per minute - too strict!
});

// Solution: Reasonable limits based on use case
export const rateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per 15 minutes
    skip: (req) => {
        // Skip rate limiting for GET requests from authenticated users
        return req.method === 'GET' && req.user?.isAuthenticated;
    },
});
```

#### 3. "Validation failed" errors

```typescript
// Problem: Schema mismatch
const userSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
});

// Client sends:
{
    "username": "john", // Should be "name"
    "email": "john@example.com"
}

// Solution: Use transform or refine
const userSchema = z.object({
    id: z.string().optional(),
    name: z.string(),
    username: z.string().optional(), // Allow both
    email: z.string().email(),
}).transform(data => ({
    ...data,
    name: data.name || data.username, // Use username as fallback
    id: data.id || crypto.randomUUID(),
}));
```

#### 4. Memory leaks in hooks

```typescript
// Problem: Not cleaning up resources
beforeCreate: async (data, req) => {
    const largeBuffer = Buffer.alloc(1024 * 1024); // 1MB buffer
    // Process data...
    return data; // Buffer not cleaned up
};

// Solution: Proper cleanup
beforeCreate: async (data, req) => {
    let largeBuffer: Buffer | null = null;
    try {
        largeBuffer = Buffer.alloc(1024 * 1024);
        // Process data...
        return data;
    } finally {
        if (largeBuffer) {
            largeBuffer = null; // Help GC
        }
    }
};
```

### Debugging Tips

#### Enable Debug Logging

```typescript
// Add to your main app file
if (process.env.NODE_ENV === 'development') {
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
        console.log('Headers:', req.headers);
        console.log('Body:', req.body);
        console.log('Query:', req.query);
        console.log('---');
        next();
    });
}
```

#### Test Security Middleware

```bash
# Test XSS protection
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(\"xss\")</script>John"}'

# Test SQL injection protection
curl -X GET "http://localhost:3000/api/users/'; DROP TABLE users; --"

# Test rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/users \
    -H "Content-Type: application/json" \
    -d '{"name": "User'$i'"}'
done
```

#### Monitor Performance

```typescript
// Add performance monitoring
app.use((req, res, next) => {
    const start = process.hrtime();

    res.on('finish', () => {
        const [seconds, nanoseconds] = process.hrtime(start);
        const duration = seconds * 1000 + nanoseconds / 1000000; // Convert to milliseconds

        if (duration > 1000) {
            // Log slow requests
            console.warn(
                `Slow request: ${req.method} ${req.url} - ${duration.toFixed(
                    2
                )}ms`
            );
        }
    });

    next();
});
```

## Advanced Examples

### Multi-tenant Application

```typescript
// Tenant-aware collections
const tenantSchema = z.object({
    id: z.string(),
    name: z.string(),
    domain: z.string(),
    settings: z.record(z.any()).default({}),
    isActive: z.boolean().default(true),
    createdAt: z.string(),
});

const tenants = db.collection('tenants', tenantSchema);

// Tenant middleware
const tenantMiddleware: RequestHandler = async (req, res, next) => {
    const domain = req.headers.host || req.get('X-Tenant-Domain');
    const tenant = await tenants.where('domain').eq(domain).first();

    if (!tenant || !tenant.isActive) {
        res.status(404).json({ error: 'Tenant not found' });
        return;
    }

    req.tenant = tenant;
    next();
};

// Tenant-specific user collection
skibba.useCollection(users, {
    middleware: [tenantMiddleware], // Apply to all methods
    GET: {
        hooks: {
            beforeQuery: async (query, req) => {
                // Filter by tenant
                return query.where('tenantId').eq(req.tenant.id);
            },
        },
    },
    POST: {
        hooks: {
            beforeCreate: async (data, req) => {
                data.tenantId = req.tenant.id;
                return data;
            },
        },
    },
});
```

### Real-time Updates with WebSockets

```typescript
import { Server as SocketServer } from 'socket.io';
import { createServer } from 'http';

const server = createServer(app);
const io = new SocketServer(server);

// Real-time hooks
skibba.useCollection(posts, {
    POST: {
        hooks: {
            afterCreate: async (result, req) => {
                // Broadcast new post to all connected clients
                io.emit('new-post', {
                    id: result.id,
                    title: result.title,
                    author: result.author,
                    createdAt: result.createdAt,
                });

                return result;
            },
        },
    },
    PUT: {
        hooks: {
            afterUpdate: async (result, req) => {
                // Notify specific post watchers
                io.to(`post-${result.id}`).emit('post-updated', result);
                return result;
            },
        },
    },
});

// WebSocket authentication
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        const user = jwt.verify(token, process.env.JWT_SECRET!);
        socket.user = user;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});
```

### File Upload Integration

```typescript
import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(
            null,
            file.fieldname +
                '-' +
                uniqueSuffix +
                path.extname(file.originalname)
        );
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(
            path.extname(file.originalname).toLowerCase()
        );
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    },
});

// Profile picture upload
app.post(
    '/api/users/:id/avatar',
    authMiddleware,
    ownershipMiddleware,
    upload.single('avatar'),
    async (req, res) => {
        try {
            const userId = req.params.id;
            const avatarUrl = `/uploads/${req.file?.filename}`;

            await users.where('id').eq(userId).update({
                'profile.avatar': avatarUrl,
                updatedAt: new Date().toISOString(),
            });

            res.json({ avatarUrl });
        } catch (error) {
            res.status(500).json({ error: 'Upload failed' });
        }
    }
);
```

This comprehensive tutorial covers all aspects of SkibbaDB Express, from basic usage to advanced security implementations. The framework provides a robust foundation for building secure, scalable REST APIs with minimal boilerplate code while maintaining maximum flexibility through its middleware and hooks system.
