import { Database } from 'skibbadb';
import { createSkibbaExpress } from '../index.js';
import { z } from 'zod';
import express from 'express';
import request from 'supertest';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('SkibbaDB Express Integration', () => {
    let app: express.Application;
    let db: Database;
    let skibbaApp: any;
    let server: any;

    const userSchema = z.object({
        _id: z.string(),
        name: z.string(),
        email: z.string().email(),
        role: z.string().default('user'),
        age: z.number().optional(),
        isActive: z.boolean().default(true),
        createdAt: z.string(),
        updatedAt: z.string().optional(),
    });

    const postSchema = z.object({
        _id: z.string(),
        title: z.string(),
        content: z.string(),
        authorId: z.string(),
        tags: z.array(z.string()).default([]),
        publishedAt: z.string().optional(),
        viewCount: z.number().default(0),
        isPublished: z.boolean().default(false),
    });

    beforeEach(async () => {
        // Create fresh app and database for each test
        app = express();
        db = new Database({ path: ':memory:' });
        skibbaApp = createSkibbaExpress(app, db);

        // Setup test collections
        const users = db.collection('users', userSchema, {
            constrainedFields: {
                email: { unique: true, nullable: false },
                name: { nullable: false },
            },
        });

        const posts = db.collection('posts', postSchema, {
            constrainedFields: {
                title: { nullable: false },
                content: { nullable: false },
                authorId: { nullable: false },
            },
        });

        // Configure collections with hooks and middleware
        skibbaApp.useCollection(users, {
            GET: {
                hooks: {
                    beforeQuery: async (query, req) => {
                        console.log('beforeQuery hook executed');
                        return query;
                    },
                    afterQuery: async (results, req) => {
                        console.log('afterQuery hook executed');
                        return results;
                    },
                },
            },
            POST: {
                hooks: {
                    beforeCreate: async (data, req) => {
                        return {
                            ...data,
                            createdAt: new Date().toISOString(),
                        };
                    },
                    afterCreate: async (result, req) => {
                        console.log(`User created: ${result.name}`);
                        return result;
                    },
                },
            },
            PUT: {
                hooks: {
                    beforeUpdate: async (_id, data, req) => {
                        return {
                            ...data,
                            updatedAt: new Date().toISOString(),
                        };
                    },
                    afterUpdate: async (result, req) => {
                        console.log(`User updated: ${result._id}`);
                        return result;
                    },
                },
            },
            DELETE: {
                hooks: {
                    beforeDelete: async (_id, req) => {
                        console.log(`Attempting to delete user: ${_id}`);
                        return true; // Allow deletion
                    },
                    afterDelete: async (_id, req) => {
                        console.log(`User deleted: ${_id}`);
                    },
                },
            },
            basePath: '/api/users',
        });

        skibbaApp.useCollection(posts, {
            GET: {},
            POST: {
                hooks: {
                    beforeCreate: async (data, req) => {
                        return {
                            ...data,
                            publishedAt: data.isPublished ? new Date().toISOString() : undefined,
                        };
                    },
                },
            },
            PUT: {},
            DELETE: {},
            basePath: '/api/posts',
        });

        // Add health check endpoint
        app.get('/health', (req, res) => {
            res.json({ status: 'ok', timestamp: new Date().toISOString() });
        });

        // Error handler
        app.use((error: any, req: any, res: any, next: any) => {
            console.error('Test error:', error.message);
            res.status(500).json({
                error: 'Internal server error',
                message: error.message,
            });
        });
    });

    afterEach(async () => {
        if (server) {
            server.close();
        }
    });

    describe('Basic CRUD Operations', () => {
        it('should create a new user', async () => {
            const userData = {
                _id: 'user1',
                name: 'John Doe',
                email: 'john@example.com',
                role: 'admin',
                age: 30,
                isActive: true,
            };

            const response = await request(app)
                .post('/api/users')
                .send(userData)
                .expect(201);

            expect(response.body).toMatchObject({
                _id: 'user1',
                name: 'John Doe',
                email: 'john@example.com',
                role: 'admin',
                age: 30,
                isActive: true,
            });
            expect(response.body.createdAt).toBeDefined();
        });

        it('should get a user by ID', async () => {
            // First create a user
            const userData = {
                _id: 'user2',
                name: 'Jane Smith',
                email: 'jane@example.com',
                age: 25,
            };

            await request(app)
                .post('/api/users')
                .send(userData)
                .expect(201);

            // Then fetch it
            const response = await request(app)
                .get('/api/users/user2')
                .expect(200);

            expect(response.body).toMatchObject({
                _id: 'user2',
                name: 'Jane Smith',
                email: 'jane@example.com',
                age: 25,
            });
        });

        it('should get all users', async () => {
            // Create multiple users
            const users = [
                { _id: 'user3', name: 'Alice', email: 'alice@example.com', age: 28 },
                { _id: 'user4', name: 'Bob', email: 'bob@example.com', age: 32 },
                { _id: 'user5', name: 'Charlie', email: 'charlie@example.com', age: 24 },
            ];

            for (const user of users) {
                await request(app)
                    .post('/api/users')
                    .send(user)
                    .expect(201);
            }

            const response = await request(app)
                .get('/api/users')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBe(3);
        });

        it('should update a user', async () => {
            // Create a user
            const userData = {
                _id: 'user6',
                name: 'David',
                email: 'david@example.com',
                age: 35,
            };

            await request(app)
                .post('/api/users')
                .send(userData)
                .expect(201);

            // Update the user
            const updateData = {
                name: 'David Updated',
                age: 36,
                role: 'moderator',
            };

            const response = await request(app)
                .put('/api/users/user6')
                .send(updateData)
                .expect(200);

            expect(response.body).toMatchObject({
                _id: 'user6',
                name: 'David Updated',
                email: 'david@example.com',
                age: 36,
                role: 'moderator',
            });
            expect(response.body.updatedAt).toBeDefined();
        });

        it('should delete a user', async () => {
            // Create a user
            const userData = {
                _id: 'user7',
                name: 'Eve',
                email: 'eve@example.com',
            };

            await request(app)
                .post('/api/users')
                .send(userData)
                .expect(201);

            // Delete the user
            await request(app)
                .delete('/api/users/user7')
                .expect(204);

            // Verify it's gone
            await request(app)
                .get('/api/users/user7')
                .expect(404);
        });
    });

    describe('Pagination and Filtering', () => {
        beforeEach(async () => {
            // Create test data
            const users = [
                { _id: 'u1', name: 'Alice', email: 'alice@test.com', age: 25, role: 'user', isActive: true },
                { _id: 'u2', name: 'Bob', email: 'bob@test.com', age: 30, role: 'admin', isActive: true },
                { _id: 'u3', name: 'Charlie', email: 'charlie@test.com', age: 35, role: 'user', isActive: false },
                { _id: 'u4', name: 'David', email: 'david@test.com', age: 28, role: 'moderator', isActive: true },
                { _id: 'u5', name: 'Eve', email: 'eve@test.com', age: 22, role: 'user', isActive: true },
            ];

            for (const user of users) {
                await request(app)
                    .post('/api/users')
                    .send(user)
                    .expect(201);
            }
        });

        it('should paginate users', async () => {
            const response = await request(app)
                .get('/api/users?page=1&limit=2')
                .expect(200);

            expect(response.body.data).toBeDefined();
            expect(response.body.data.length).toBe(2);
            expect(response.body.pagination).toMatchObject({
                page: 1,
                limit: 2,
                totalCount: 5,
                totalPages: 3,
                hasNextPage: true,
                hasPreviousPage: false,
            });
        });

        it('should filter users by role', async () => {
            const response = await request(app)
                .get('/api/users?role=user')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBe(3);
            expect(response.body.every((user: any) => user.role === 'user')).toBe(true);
        });

        it('should filter users by age range', async () => {
            const response = await request(app)
                .get('/api/users?age_gte=25&age_lte=30')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.every((user: any) => user.age >= 25 && user.age <= 30)).toBe(true);
        });

        it('should filter users by boolean field', async () => {
            const response = await request(app)
                .get('/api/users?isActive=true')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.every((user: any) => user.isActive === true)).toBe(true);
        });

        it('should sort users', async () => {
            const response = await request(app)
                .get('/api/users?orderBy=age&sort=desc')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body[0].age).toBeGreaterThanOrEqual(response.body[1].age);
        });

        it('should combine filtering, sorting, and pagination', async () => {
            const response = await request(app)
                .get('/api/users?role=user&orderBy=age&sort=asc&page=1&limit=2')
                .expect(200);

            expect(response.body.data).toBeDefined();
            expect(response.body.data.length).toBe(2);
            expect(response.body.data.every((user: any) => user.role === 'user')).toBe(true);
            expect(response.body.pagination.totalCount).toBe(3);
        });
    });

    describe('Multiple Collections', () => {
        it('should handle multiple collections independently', async () => {
            // Create a user
            const user = {
                _id: 'author1',
                name: 'Author One',
                email: 'author@example.com',
            };

            await request(app)
                .post('/api/users')
                .send(user)
                .expect(201);

            // Create a post
            const post = {
                _id: 'post1',
                title: 'My First Post',
                content: 'This is the content of my first post.',
                authorId: 'author1',
                tags: ['technology', 'programming'],
                isPublished: true,
            };

            const postResponse = await request(app)
                .post('/api/posts')
                .send(post)
                .expect(201);

            expect(postResponse.body).toMatchObject({
                _id: 'post1',
                title: 'My First Post',
                content: 'This is the content of my first post.',
                authorId: 'author1',
                tags: ['technology', 'programming'],
                isPublished: true,
            });
            expect(postResponse.body.publishedAt).toBeDefined();

            // Fetch both collections
            const usersResponse = await request(app)
                .get('/api/users')
                .expect(200);

            const postsResponse = await request(app)
                .get('/api/posts')
                .expect(200);

            expect(usersResponse.body.length).toBe(1);
            expect(postsResponse.body.length).toBe(1);
        });
    });

    describe('Error Handling', () => {
        it('should handle validation errors', async () => {
            const invalidUser = {
                _id: 'invalid',
                name: '', // Empty name should fail validation
                email: 'not-an-email', // Invalid email
            };

            const response = await request(app)
                .post('/api/users')
                .send(invalidUser)
                .expect(400);

            expect(response.body.error).toBe('Validation failed');
            expect(response.body.message).toBe('Document validation failed');
        });

        it('should handle duplicate unique field errors', async () => {
            const user1 = {
                _id: 'user_dup1',
                name: 'User One',
                email: 'duplicate@example.com',
            };

            const user2 = {
                _id: 'user_dup2',
                name: 'User Two',
                email: 'duplicate@example.com', // Same email
            };

            await request(app)
                .post('/api/users')
                .send(user1)
                .expect(201);

            const response = await request(app)
                .post('/api/users')
                .send(user2)
                .expect(400);

            expect(response.body.error).toBe('Database constraint violation');
            expect(response.body.message).toBe('Document violates unique constraint on field: email');
        });

        it('should handle not found errors', async () => {
            const response = await request(app)
                .get('/api/users/nonexistent')
                .expect(404);

            expect(response.body.error).toBe('Not found');
        });

        it('should handle invalid filter parameters', async () => {
            const response = await request(app)
                .get('/api/users?invalidField=value')
                .expect(400);

            expect(response.body.error).toBe('Invalid filter parameter');
        });

        it('should handle invalid pagination parameters', async () => {
            const response = await request(app)
                .get('/api/users?page=invalid')
                .expect(400);

            expect(response.body.error).toBe('Invalid pagination parameter');
        });

        it('should handle invalid sort parameters', async () => {
            const response = await request(app)
                .get('/api/users?orderBy=invalidField')
                .expect(400);

            expect(response.body.error).toBe('Invalid sort parameter');
        });
    });

    describe('Request Body Validation', () => {
        it('should reject malformed JSON', async () => {
            const response = await request(app)
                .post('/api/users')
                .set('Content-Type', 'application/json')
                .send('{ invalid json }')
                .expect(400);

            expect(response.body.error).toBe('Invalid JSON');
        });

        it('should reject non-object request bodies', async () => {
            const response = await request(app)
                .post('/api/users')
                .send('just a string')
                .expect(400);

            expect(response.body.error).toBe('Validation failed');
            expect(response.body.message).toBe('Document validation failed');
        });

        it('should reject array request bodies', async () => {
            const response = await request(app)
                .post('/api/users')
                .send([{ _id: 'test', name: 'Test' }])
                .expect(400);

            expect(response.body.error).toBe('Invalid request body');
        });
    });

    describe('Health Check', () => {
        it('should return health status', async () => {
            const response = await request(app)
                .get('/health')
                .expect(200);

            expect(response.body).toMatchObject({
                status: 'ok',
            });
            expect(response.body.timestamp).toBeDefined();
        });
    });

    describe('Hooks Integration', () => {
        it('should execute all lifecycle hooks in correct order', async () => {
            const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

            // Create user (tests beforeCreate and afterCreate hooks)
            const userData = {
                _id: 'hook_test',
                name: 'Hook Test User',
                email: 'hooktest@example.com',
            };

            const createResponse = await request(app)
                .post('/api/users')
                .send(userData)
                .expect(201);

            expect(createResponse.body.createdAt).toBeDefined();

            // Update user (tests beforeUpdate and afterUpdate hooks)
            const updateData = { name: 'Updated Hook Test User' };

            const updateResponse = await request(app)
                .put('/api/users/hook_test')
                .send(updateData)
                .expect(200);

            expect(updateResponse.body.updatedAt).toBeDefined();

            // Get user (tests beforeQuery and afterQuery hooks)
            await request(app)
                .get('/api/users/hook_test')
                .expect(200);

            // Delete user (tests beforeDelete and afterDelete hooks)
            await request(app)
                .delete('/api/users/hook_test')
                .expect(204);

            expect(consoleSpy).toHaveBeenCalledWith('User created: Hook Test User');
            expect(consoleSpy).toHaveBeenCalledWith('User updated: hook_test');
            expect(consoleSpy).toHaveBeenCalledWith('beforeQuery hook executed');
            expect(consoleSpy).toHaveBeenCalledWith('afterQuery hook executed');
            expect(consoleSpy).toHaveBeenCalledWith('Attempting to delete user: hook_test');
            expect(consoleSpy).toHaveBeenCalledWith('User deleted: hook_test');

            consoleSpy.mockRestore();
        });
    });
});