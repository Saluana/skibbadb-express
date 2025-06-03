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

describe('Configurable Limits and Rate Limiting', () => {
    let app: express.Application;
    let database: Database;
    let server: any;

    beforeAll(async () => {
        // Create test database
        database = new Database({ path: ':memory:' });
        const users = database.collection('test_users', TestUserSchema);

        // Test app with custom global limits
        app = express();
        const skibba = createSkibbaExpress(app, database, {
            uploadLimitOptions: {
                jsonLimit: '100kb', // Larger than default 50kb
                urlEncodedLimit: '100kb',
            },
        });

        // Collection with custom rate limits
        skibba.useCollection(users, {
            basePath: '/api/users',
            rateLimitOptions: {
                windowMs: 100, // 100ms for testing (shorter window)
                max: 10, // More lenient limit for testing
                strict: true, // Enable strict limits for write operations
            },
            uploadLimitOptions: {
                jsonLimit: '200kb', // Even larger for this collection
                urlEncodedLimit: '200kb',
            },
            GET: {
                rateLimitOptions: {
                    max: 10, // Higher limit for GET requests
                },
            },
            POST: {
                rateLimitOptions: {
                    max: 5, // More lenient limit for POST requests in testing
                },
                uploadLimitOptions: {
                    jsonLimit: '50kb', // Smaller limit for POST
                },
            },
        });

        // Collection with default limits for comparison
        const defaultUsers = database.collection(
            'default_users',
            TestUserSchema
        );
        skibba.useCollection(defaultUsers, {
            basePath: '/api/default-users',
            GET: {},
            POST: {},
        });

        // Collection with security middleware using custom size limits
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

        server = app.listen(0);
    });

    afterAll(async () => {
        if (server) {
            server.close();
        }
    });

    describe('Upload Size Limits', () => {
        it('should accept large payloads within global custom limits', async () => {
            // Create a payload just under 100kb
            const largeData = 'x'.repeat(90000); // ~90KB

            const response = await request(app).put('/api/users/test-id').send({
                name: 'Test User',
                email: 'test@example.com',
                data: largeData,
            });

            expect(response.status).not.toBe(413); // Should not be "Payload too large"
        });

        it('should reject payloads exceeding collection-specific limits', async () => {
            // Create a payload larger than POST method limit (50kb) but smaller than collection limit (200kb)
            const largeData = 'x'.repeat(60000); // ~60KB

            const response = await request(app).post('/api/users').send({
                name: 'Test User',
                email: 'test@example.com',
                data: largeData,
            });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Payload too large');
        });

        it('should use default 50kb limit for collections without custom limits', async () => {
            // Create a payload larger than default 50kb
            const largeData = 'x'.repeat(60000); // ~60KB

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

        it('should enforce custom security middleware size limits', async () => {
            // Create a payload larger than custom security limit (30KB)
            const largeData = 'x'.repeat(35000); // ~35KB

            const response = await request(app).post('/api/secure-users').send({
                name: 'Test User',
                email: 'test@example.com',
                data: largeData,
            });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Request too large');
        });
    });

    describe('Rate Limiting', () => {
        it('should enforce collection-level rate limits', async () => {
            // Make requests quickly to trigger rate limit (max 3 per second)
            const promises = Array.from({ length: 5 }, () =>
                request(app).get('/api/users')
            );

            const responses = await Promise.all(promises);

            // Some requests should be rate limited
            const rateLimitedResponses = responses.filter(
                (r) => r.status === 429
            );
            expect(rateLimitedResponses.length).toBeGreaterThan(0);

            if (rateLimitedResponses.length > 0) {
                expect(rateLimitedResponses[0].body.error).toBe(
                    'Too many requests'
                );
                expect(rateLimitedResponses[0].body.message).toContain(
                    'Rate limit exceeded'
                );
            }
        });

        it('should apply method-specific rate limits', async () => {
            // Wait for rate limit to reset
            await new Promise((resolve) => setTimeout(resolve, 1100));

            // Make POST requests quickly (max 2 per second for POST)
            const promises = Array.from({ length: 4 }, () =>
                request(app).post('/api/users').send({
                    name: 'Test User',
                    email: 'test@example.com',
                })
            );

            const responses = await Promise.all(promises);

            // Should have rate limited responses due to POST limit of 2
            const rateLimitedResponses = responses.filter(
                (r) => r.status === 429
            );
            expect(rateLimitedResponses.length).toBeGreaterThan(0);
        });

        it('should allow higher limits for GET requests', async () => {
            // Wait for rate limit to reset
            await new Promise((resolve) => setTimeout(resolve, 1100));

            // Make GET requests (max 10 per second for GET)
            const promises = Array.from({ length: 8 }, () =>
                request(app).get('/api/users')
            );

            const responses = await Promise.all(promises);

            // Most GET requests should succeed due to higher limit
            const successfulResponses = responses.filter(
                (r) => r.status === 200 || r.status === 404
            );
            expect(successfulResponses.length).toBeGreaterThanOrEqual(6);
        });

        it('should not rate limit collections without custom limits', async () => {
            // Default rate limiting should be much more lenient
            const promises = Array.from({ length: 5 }, () =>
                request(app).get('/api/default-users')
            );

            const responses = await Promise.all(promises);

            // Should not be rate limited with default settings
            const rateLimitedResponses = responses.filter(
                (r) => r.status === 429
            );
            expect(rateLimitedResponses.length).toBe(0);
        });
    });

    describe('Configuration Precedence', () => {
        it('should prioritize method-specific limits over collection limits', async () => {
            // POST method has 50kb limit, collection has 200kb limit
            // Method limit should take precedence
            const largeData = 'x'.repeat(60000); // ~60KB (exceeds method, within collection)

            const response = await request(app).post('/api/users').send({
                name: 'Test User',
                email: 'test@example.com',
                data: largeData,
            });

            expect(response.status).toBe(413);
        });

        it('should prioritize collection limits over global limits when no method override', async () => {
            // Collection has 200kb, global has 100kb, GET has no override
            // Collection limit should apply for GET
            const largeData = 'x'.repeat(150000); // ~150KB (exceeds global, within collection)

            // First create a user to GET
            await request(app).post('/api/users').send({
                name: 'Test User',
                email: 'test@example.com',
            });

            // GET request with large query should use collection limit
            const response = await request(app)
                .get('/api/users')
                .query({ largeParam: largeData });

            // This might still fail due to URL length limits, but shouldn't be 413 from our middleware
            expect(response.status).not.toBe(413);
        });
    });

    describe('Security Middleware Configuration', () => {
        it('should accept custom maxBodySize parameter', async () => {
            const mediumData = 'x'.repeat(25000); // ~25KB (within custom 30KB limit)

            const response = await request(app).post('/api/secure-users').send({
                name: 'Test User',
                email: 'test@example.com',
                data: mediumData,
            });

            expect(response.status).not.toBe(413);
        });

        it('should reject payloads exceeding custom maxBodySize', async () => {
            const largeData = 'x'.repeat(35000); // ~35KB (exceeds custom 30KB limit)

            const response = await request(app).post('/api/secure-users').send({
                name: 'Test User',
                email: 'test@example.com',
                data: largeData,
            });

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('Request too large');
            expect(response.body.message).toBe(
                'Request body exceeds size limit'
            );
        });
    });

    describe('Backward Compatibility', () => {
        it('should work with collections that have no custom configuration', async () => {
            const response = await request(app)
                .post('/api/default-users')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                });

            // Should work with default settings
            expect(response.status).toBe(201);
            expect(response.body.name).toBe('Test User');
        });

        it('should work with securityMiddleware() called without options', async () => {
            // This tests that the middleware works when called with no parameters
            const testApp = express();
            testApp.use(express.json());

            testApp.post('/test', securityMiddleware(), (req, res) => {
                res.json({ success: true });
            });

            const response = await request(testApp).post('/test').send({
                name: 'Test User',
                email: 'test@example.com',
            });

            expect(response.status).toBe(200);
            expect(response.body.success).toBe(true);
        });
    });
});
