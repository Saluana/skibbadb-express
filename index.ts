import { createSkibbaExpress } from './skibba-express.js';
import { Database } from 'skibbadb';
import { authMiddleware, requireAdmin } from './middleware/auth';
import { loggingMiddleware } from './middleware/logging';
import {
    securityMiddleware,
    rateLimitMiddleware,
    strictRateLimitMiddleware,
    helmetMiddleware,
    additionalSecurityHeaders,
    validateUserInput,
} from './middleware/security';
import { z } from 'zod';

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

const app = createSkibbaExpress(db);

// Apply global security middleware (helmet for headers, rate limiting)
app.use(helmetMiddleware);
app.use(additionalSecurityHeaders);
app.use(rateLimitMiddleware);

// Configure the users collection with different middleware per method
app.useCollection(users, {
    GET: {
        middleware: [loggingMiddleware],
        hooks: {
            afterQuery: async (results, req) => {
                // Hide sensitive data for non-admin users
                if (!req.user?.isAdmin) {
                    return results.map((user) => ({
                        id: user.id,
                        name: user.name,
                        role: user.role,
                    }));
                }
                return results;
            },
        },
    },

    POST: {
        middleware: [
            securityMiddleware,
            strictRateLimitMiddleware,
            authMiddleware,
            requireAdmin,
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
            securityMiddleware,
            strictRateLimitMiddleware,
            authMiddleware,
            requireAdmin,
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
        middleware: [strictRateLimitMiddleware, authMiddleware, requireAdmin],
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
        authentication: {
            format: 'Bearer user:id:email:isAdmin',
            example: 'Bearer user:1:admin@example.com:true',
        },
        examples: {
            'Basic Blog': 'npm run example:blog',
            'Todo App': 'npm run example:todo',
            'Advanced Features': 'npm run example:advanced',
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
