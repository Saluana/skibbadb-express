import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { Database } from 'skibbadb';
import { z } from 'zod';
import createSkibbaExpress from '../index.js';

// Test schema
const TestUserSchema = z.object({
    id: z.string().optional(),
    name: z.string(),
    email: z.string().email(),
});

describe('Rate Limiting Configuration', () => {
    let app: express.Application;
    let database: Database;
    let server: any;

    beforeAll(async () => {
        // Create test database
        database = new Database({ path: ':memory:' });
        
        app = express();
        const skibba = createSkibbaExpress(app, database);

        // Collection with custom rate limits for testing
        const testUsers = database.collection('test_users', TestUserSchema);
        skibba.useCollection(testUsers, {
            basePath: '/api/test-users',
            rateLimitOptions: {
                windowMs: 2000, // 2 seconds for testing
                max: 3,         // Only 3 requests per 2 seconds
            },
            GET: {},
            POST: {},
        });

        // Collection with method-specific rate limits
        const methodUsers = database.collection('method_users', TestUserSchema);
        skibba.useCollection(methodUsers, {
            basePath: '/api/method-users',
            GET: {
                rateLimitOptions: {
                    windowMs: 1000, // 1 second
                    max: 5,         // 5 GET requests per second
                }
            },
            POST: {
                rateLimitOptions: {
                    windowMs: 1000, // 1 second
                    max: 2,         // 2 POST requests per second
                }
            },
        });

        // Collection without custom rate limits for comparison
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

    describe('Collection-Level Rate Limiting', () => {
        it('should enforce custom collection rate limits', async () => {
            // Make requests quickly to trigger rate limit (max 3 per 2 seconds)
            const promises = Array.from({ length: 5 }, () => 
                request(app).get('/api/test-users')
            );
            
            const responses = await Promise.all(promises);
            
            // Some requests should be rate limited
            const rateLimitedResponses = responses.filter(r => r.status === 429);
            expect(rateLimitedResponses.length).toBeGreaterThan(0);
            
            if (rateLimitedResponses.length > 0) {
                expect(rateLimitedResponses[0].body.error).toBe('Too many requests');
                expect(rateLimitedResponses[0].body.message).toContain('Rate limit exceeded');
            }
        });

        it('should reset rate limits after window expires', async () => {
            // Wait for rate limit window to reset (2 seconds)
            await new Promise(resolve => setTimeout(resolve, 2100));
            
            // Should be able to make requests again
            const response = await request(app).get('/api/test-users');
            expect(response.status).not.toBe(429);
        });
    });

    describe('Method-Specific Rate Limiting', () => {
        it('should apply different limits for different HTTP methods', async () => {
            // Wait for any previous rate limits to reset
            await new Promise(resolve => setTimeout(resolve, 1100));
            
            // Test POST rate limit (max 2 per second)
            const postPromises = Array.from({ length: 4 }, () => 
                request(app)
                    .post('/api/method-users')
                    .send({
                        name: 'Test User',
                        email: 'test@example.com'
                    })
            );
            
            const postResponses = await Promise.all(postPromises);
            
            // Should have rate limited POST responses
            const postRateLimited = postResponses.filter(r => r.status === 429);
            expect(postRateLimited.length).toBeGreaterThan(0);
            
            // Wait for rate limit to reset
            await new Promise(resolve => setTimeout(resolve, 1100));
            
            // Test GET rate limit (max 5 per second) - should be more lenient
            const getPromises = Array.from({ length: 4 }, () => 
                request(app).get('/api/method-users')
            );
            
            const getResponses = await Promise.all(getPromises);
            
            // GET requests should mostly succeed due to higher limit
            const getRateLimited = getResponses.filter(r => r.status === 429);
            expect(getRateLimited.length).toBeLessThan(postRateLimited.length);
        });
    });

    describe('Default Rate Limiting Behavior', () => {
        it('should not rate limit collections without custom configuration', async () => {
            // Default rate limiting should be much more lenient
            const promises = Array.from({ length: 10 }, () => 
                request(app).get('/api/default-users')
            );
            
            const responses = await Promise.all(promises);
            
            // Should not be rate limited with default settings
            const rateLimitedResponses = responses.filter(r => r.status === 429);
            expect(rateLimitedResponses.length).toBe(0);
        });
    });

    describe('Rate Limit Headers', () => {
        it('should include standard rate limit headers', async () => {
            // Wait for any rate limits to reset
            await new Promise(resolve => setTimeout(resolve, 2100));
            
            const response = await request(app).get('/api/test-users');
            
            // Should include rate limit headers
            expect(response.headers['ratelimit-limit']).toBeDefined();
            expect(response.headers['ratelimit-remaining']).toBeDefined();
            expect(response.headers['ratelimit-reset']).toBeDefined();
        });
    });
});