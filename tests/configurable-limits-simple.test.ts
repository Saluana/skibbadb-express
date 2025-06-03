import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { Database } from 'skibbadb';
import { z } from 'zod';
import createSkibbaExpress, { securityMiddleware } from '../index.js';

// Test schema
const TestUserSchema = z.object({
    id: z.string().optional(),
    name: z.string(),
    email: z.string().email(),
    data: z.string().optional(),
});

describe('Configurable Limits - Core Features', () => {
    let app: express.Application;
    let database: Database;
    let server: any;

    beforeAll(async () => {
        // Create test database
        database = new Database({ path: ':memory:' });
        
        // Test app with custom global limits
        app = express();
        const skibba = createSkibbaExpress(app, database, {
            uploadLimitOptions: {
                jsonLimit: '100kb', // Larger than default 50kb
                urlEncodedLimit: '100kb',
            },
        });

        // Collection with security middleware and custom size limits
        const secureUsers = database.collection('secure_users', TestUserSchema);
        skibba.useCollection(secureUsers, {
            basePath: '/api/secure-users',
            middleware: [
                securityMiddleware({
                    maxBodySize: 30000, // 30KB custom limit
                    maxQuerySize: 5000, // 5KB custom limit
                }),
            ],
            GET: {},
            POST: {},
        });

        // Collection with default limits for comparison
        const defaultUsers = database.collection('default_users', TestUserSchema);
        skibba.useCollection(defaultUsers, {
            basePath: '/api/default-users',
            GET: {},
            POST: {},
        });

        server = app.listen(0);
    });

    afterAll(async () => {
        if (server) {
            server.close();
        }
    });

    describe('Global Upload Limits Configuration', () => {
        it('should accept payloads within global custom limits (100kb)', async () => {
            // Create a payload just under 100kb
            const largeData = 'x'.repeat(90000); // ~90KB
            
            const response = await request(app)
                .post('/api/default-users')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    data: largeData,
                });

            expect(response.status).toBe(201);
            expect(response.body.name).toBe('Test User');
        });

        it('should reject payloads exceeding global custom limits (100kb)', async () => {
            // Create a payload larger than 100kb
            const largeData = 'x'.repeat(110000); // ~110KB
            
            const response = await request(app)
                .post('/api/default-users')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    data: largeData,
                });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Payload too large');
        });
    });

    describe('Custom Security Middleware Limits', () => {
        it('should accept payloads within custom security limits (30kb)', async () => {
            const mediumData = 'x'.repeat(25000); // ~25KB (within custom 30KB limit)
            
            const response = await request(app)
                .post('/api/secure-users')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    data: mediumData,
                });

            expect(response.status).toBe(201);
            expect(response.body.name).toBe('Test User');
        });

        it('should reject payloads exceeding custom security limits (30kb)', async () => {
            const largeData = 'x'.repeat(35000); // ~35KB (exceeds custom 30KB limit)
            
            const response = await request(app)
                .post('/api/secure-users')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    data: largeData,
                });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Request too large');
            expect(response.body.message).toBe('Request body exceeds size limit');
        });
    });

    describe('Security Middleware Backward Compatibility', () => {
        it('should work with securityMiddleware() called without options', async () => {
            // This tests that the middleware works when called with no parameters
            const testApp = express();
            testApp.use(express.json());
            
            testApp.post('/test', securityMiddleware(), (req, res) => {
                res.json({ success: true });
            });

            const response = await request(testApp)
                .post('/test')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                });

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
        });

        it('should use default limits when no options provided', async () => {
            const testApp = express();
            testApp.use(express.json());
            
            testApp.post('/test', securityMiddleware(), (req, res) => {
                res.json({ success: true });
            });

            // Create payload larger than default 50KB limit
            const largeData = 'x'.repeat(55000); // ~55KB
            
            const response = await request(testApp)
                .post('/test')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    data: largeData,
                });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Request too large');
        });
    });

    describe('Configuration Priority Demonstration', () => {
        it('should demonstrate size limit differences between collections', async () => {
            // Test that default collection uses global 100kb limit
            const data90kb = 'x'.repeat(90000); // ~90KB
            
            const defaultResponse = await request(app)
                .post('/api/default-users')
                .send({
                    name: 'Default User',
                    email: 'default@example.com',
                    data: data90kb,
                });

            // Should succeed with default collection (100kb global limit)
            expect(defaultResponse.status).toBe(201);

            // Test that secure collection uses custom 30kb limit
            const secureResponse = await request(app)
                .post('/api/secure-users')
                .send({
                    name: 'Secure User',
                    email: 'secure@example.com',
                    data: data90kb,
                });

            // Should fail with secure collection (30kb custom limit)
            expect(secureResponse.status).toBe(413);
            expect(secureResponse.body.error).toBe('Request too large');
        });
    });
});