import { createSkibbaExpress } from './index.js';
import { Database } from 'skibbadb';
import {
    securityMiddleware,
    rateLimitMiddleware,
    strictRateLimitMiddleware,
    helmetMiddleware,
    additionalSecurityHeaders,
    validateUserInput,
} from './middleware/security.js';
import { z } from 'zod';
import express from 'express';

const app = express();

// Simple example showing the basic usage
const db = new Database({ path: 'example.db' });

// Define a simple users collection schema
const usersSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    role: z.string().default('user'),
    createdAt: z.string(),
});

// Define a simple users collection
const users = db.collection('users', usersSchema, {
    constrainedFields: {
        email: { unique: true, nullable: false },
        name: { nullable: false },
        role: { nullable: false },
    },
});

const skibba = createSkibbaExpress(app, db);

// Apply global security middleware (helmet for headers, rate limiting)
app.use(helmetMiddleware);
app.use(additionalSecurityHeaders);

// Configure the users collection with different middleware per method
skibba.useCollection(users, {
    GET: {
        middleware: [rateLimitMiddleware],
        hooks: {},
    },

    POST: {
        middleware: [
            securityMiddleware(),
            strictRateLimitMiddleware,
            validateUserInput,
        ],
        hooks: {
            beforeCreate: async (data, req) => ({
                ...data,
                createdAt: new Date().toISOString(),
            }),
            afterCreate: async (result, req) => {
                console.log(
                    `👤 New user created: ${result.name} (${result.email})`
                );
                return result;
            },
        },
    },

    PUT: {
        middleware: [
            securityMiddleware(),
            strictRateLimitMiddleware,
            validateUserInput,
        ],
        hooks: {
            beforeUpdate: async (id, data, req) => ({
                ...data,
                updatedAt: new Date().toISOString(),
            }),
        },
    },

    DELETE: {
        middleware: [strictRateLimitMiddleware],
    },

    basePath: '/api/users',
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        database: 'connected',
    });
    return;
});

// Root endpoint with API documentation
app.get('/', (req, res) => {
    res.json({
        message: 'SkibbaDB Express Integration Example',
        version: '1.0.0',
        endpoints: {
            'GET /health': 'Health check',
            'GET /api/users': 'List users',
            'GET /api/users/:id': 'Get user by ID',
            'POST /api/users': 'Create user (admin only)',
            'PUT /api/users/:id': 'Update user (admin only)',
            'DELETE /api/users/:id': 'Delete user (admin only)',
        },
    });
    return;
});

// Error handling
app.use((error: any, req: any, res: any, next: any) => {
    console.error('Error:', error.message);
    res.status(500).json({
        error: 'Internal server error',
        message: error.message,
    });
    return;
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(
        `🚀 SkibbaDB Express Example running on http://localhost:${PORT}`
    );
    console.log('');
    console.log('📖 Try these examples:');
    console.log('  npm run example:blog     - Blog with posts and comments');
    console.log('  npm run example:todo     - Todo list application');
    console.log('  npm run example:advanced - Advanced features demo');
    console.log('');
    console.log('💡 Visit http://localhost:3000 for API documentation');
});

export { app, db };
