// Test file for pagination and filtering functionality
import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { Database } from 'skibbadb';
import { createSkibbaExpress } from '../index.js';
import { z } from 'zod';

describe('Pagination and Filtering Tests', () => {
    let app: express.Application;
    let db: Database;

    beforeEach(async () => {
        app = express();
        db = new Database();
        const skibba = createSkibbaExpress(app, db);

        // Create test schema
        const userSchema = z.object({
            id: z.string(),
            name: z.string(),
            email: z.string().email(),
            age: z.number().int().positive(),
            role: z.enum(['user', 'admin', 'moderator']).default('user'),
            isActive: z.boolean().default(true),
        });

        const users = db.collection('users', userSchema);

        // Register collection
        skibba.useCollection(users, {
            GET: {},
            POST: {},
            PUT: {},
            DELETE: {},
            basePath: '/api/users',
        });

        // Create test data
        const testUsers = [
            {
                name: 'Alice Johnson',
                email: 'alice@example.com',
                age: 25,
                role: 'admin',
                isActive: true,
            },
            {
                name: 'Bob Smith',
                email: 'bob@example.com',
                age: 30,
                role: 'user',
                isActive: true,
            },
            {
                name: 'Charlie Brown',
                email: 'charlie@example.com',
                age: 35,
                role: 'moderator',
                isActive: false,
            },
            {
                name: 'Diana Prince',
                email: 'diana@example.com',
                age: 28,
                role: 'admin',
                isActive: true,
            },
            {
                name: 'Eve Wilson',
                email: 'eve@example.com',
                age: 22,
                role: 'user',
                isActive: true,
            },
            {
                name: 'Frank Miller',
                email: 'frank@example.com',
                age: 40,
                role: 'user',
                isActive: false,
            },
            {
                name: 'Grace Davis',
                email: 'grace@example.com',
                age: 33,
                role: 'moderator',
                isActive: true,
            },
            {
                name: 'Henry Taylor',
                email: 'henry@example.com',
                age: 27,
                role: 'admin',
                isActive: true,
            },
        ];

        for (const user of testUsers) {
            await request(app).post('/api/users').send(user);
        }
    });

    afterEach(async () => {
        await db.close();
    });

    describe('Pagination', () => {
        test('should support page-based pagination', async () => {
            const response = await request(app)
                .get('/api/users?page=1&limit=3')
                .expect(200);

            expect(response.body).toHaveProperty('data');
            expect(response.body).toHaveProperty('pagination');
            expect(response.body.data).toHaveLength(3);
            expect(response.body.pagination).toEqual({
                page: 1,
                limit: 3,
                totalCount: 8,
                totalPages: 3,
                hasNextPage: true,
                hasPreviousPage: false,
            });
        });

        test('should support offset-based pagination', async () => {
            const response = await request(app)
                .get('/api/users?limit=3&offset=2')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body).toHaveLength(3);
        });

        test('should validate pagination parameters', async () => {
            // Invalid page
            await request(app).get('/api/users?page=0&limit=10').expect(400);

            // Invalid limit
            await request(app).get('/api/users?page=1&limit=1001').expect(400);

            // Invalid offset
            await request(app).get('/api/users?offset=-1').expect(400);
        });
    });

    describe('Filtering', () => {
        test('should filter by equality', async () => {
            const response = await request(app)
                .get('/api/users?role=admin')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBe(3); // Alice, Diana, Henry
            response.body.forEach((user: any) => {
                expect(user.role).toBe('admin');
            });
        });

        test('should filter by multiple conditions', async () => {
            const response = await request(app)
                .get('/api/users?role=admin&isActive=true')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(user.role).toBe('admin');
                expect(user.isActive).toBe(true);
            });
        });

        test('should filter by greater than', async () => {
            const response = await request(app)
                .get('/api/users?age_gt=30')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(user.age).toBeGreaterThan(30);
            });
        });

        test('should filter by greater than or equal', async () => {
            const response = await request(app)
                .get('/api/users?age_gte=30')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(user.age).toBeGreaterThanOrEqual(30);
            });
        });

        test('should filter by less than', async () => {
            const response = await request(app)
                .get('/api/users?age_lt=30')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(user.age).toBeLessThan(30);
            });
        });

        test('should filter by less than or equal', async () => {
            const response = await request(app)
                .get('/api/users?age_lte=30')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(user.age).toBeLessThanOrEqual(30);
            });
        });

        test('should filter by text search (like)', async () => {
            const response = await request(app)
                .get('/api/users?name_like=%Alice%')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBe(1);
            expect(response.body[0].name).toBe('Alice Johnson');
        });

        test('should filter by array values (in)', async () => {
            const response = await request(app)
                .get('/api/users?role_in=admin&role_in=moderator')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            response.body.forEach((user: any) => {
                expect(['admin', 'moderator']).toContain(user.role);
            });
        });

        test('should handle invalid filter fields', async () => {
            await request(app)
                .get('/api/users?nonexistentField=value')
                .expect(400);
        });
    });

    describe('Sorting', () => {
        test('should sort by field ascending', async () => {
            const response = await request(app)
                .get('/api/users?orderBy=age&sort=asc')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);

            for (let i = 1; i < response.body.length; i++) {
                expect(response.body[i].age).toBeGreaterThanOrEqual(
                    response.body[i - 1].age
                );
            }
        });

        test('should sort by field descending', async () => {
            const response = await request(app)
                .get('/api/users?orderBy=age&sort=desc')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);

            for (let i = 1; i < response.body.length; i++) {
                expect(response.body[i].age).toBeLessThanOrEqual(
                    response.body[i - 1].age
                );
            }
        });

        test('should handle invalid sort direction', async () => {
            await request(app)
                .get('/api/users?orderBy=age&sort=invalid')
                .expect(400);
        });

        test('should handle invalid sort field', async () => {
            await request(app)
                .get('/api/users?orderBy=nonexistentField')
                .expect(400);
        });
    });

    describe('Combined Features', () => {
        test('should combine pagination, filtering, and sorting', async () => {
            const response = await request(app)
                .get(
                    '/api/users?page=1&limit=3&isActive=true&age_gte=25&orderBy=age&sort=asc'
                )
                .expect(200);

            expect(response.body).toHaveProperty('data');
            expect(response.body).toHaveProperty('pagination');
            expect(response.body.data).toHaveLength(3);

            // Check filtering: all should be active and age >= 25
            response.body.data.forEach((user: any) => {
                expect(user.isActive).toBe(true);
                expect(user.age).toBeGreaterThanOrEqual(25);
            });

            // Check sorting: should be in ascending age order
            for (let i = 1; i < response.body.data.length; i++) {
                expect(response.body.data[i].age).toBeGreaterThanOrEqual(
                    response.body.data[i - 1].age
                );
            }

            // Check pagination metadata reflects filtering
            expect(response.body.pagination.totalCount).toBeLessThan(8); // Less than total users due to filtering
        });

        test('should work with complex filters and pagination', async () => {
            const response = await request(app)
                .get(
                    '/api/users?page=1&limit=2&role_in=admin&role_in=user&age_gt=25&name_like=%i%'
                )
                .expect(200);

            expect(response.body).toHaveProperty('data');
            expect(response.body).toHaveProperty('pagination');

            response.body.data.forEach((user: any) => {
                expect(['admin', 'user']).toContain(user.role);
                expect(user.age).toBeGreaterThan(25);
                expect(user.name.toLowerCase()).toContain('i');
            });
        });
    });
});
