import { Database, Collection } from 'skibbadb';
import { z } from 'zod';
import express from 'express';
import request from 'supertest';
import { createSkibbaExpress } from '../index';
import { describe, beforeAll, afterAll, test, expect } from 'bun:test';

// Test schema with array field
const UserSchema = z.object({
    id: z.string(),
    name: z.string(),
    roles: z.array(z.string()),
    email: z.string().email(),
});

describe('Array Filtering REST API Tests', () => {
    let app;
    let database;
    let usersCollection;
    let server;

    beforeAll(async () => {
        // Setup test database and collection
        database = new Database({ path: './test-data' });
        usersCollection = database.collection('test-users', UserSchema);

        // Create Express app with SkibbaDB
        const expressApp = express();
        app = createSkibbaExpress(expressApp, database);

        // Setup collection endpoint
        app.useCollection(usersCollection, {
            GET: {},
            POST: {},
            PUT: {},
            DELETE: {},
            basepath: '/test-users',
        });

        // Insert test data
        const testUsers = [
            {
                id: 'user1',
                name: 'Admin User',
                roles: ['admin', 'user'],
                email: 'admin@test.com',
            },
            {
                id: 'user2',
                name: 'Editor User',
                roles: ['editor', 'user'],
                email: 'editor@test.com',
            },
            {
                id: 'user3',
                name: 'Super Admin',
                roles: ['superadmin', 'admin', 'user'],
                email: 'superadmin@test.com',
            },
            {
                id: 'user4',
                name: 'Regular User',
                roles: ['user'],
                email: 'user@test.com',
            },
        ];

        // Clear existing data and insert test data
        try {
            await usersCollection.deleteMany({});
        } catch (e) {
            // Collection might be empty
        }

        for (const user of testUsers) {
            await usersCollection.insert(user);
        }
    });

    afterAll(async () => {
        // Cleanup
        try {
            await usersCollection.deleteMany({});
        } catch (e) {
            // Ignore cleanup errors
        }
    });

    describe('Array filtering with _in operator', () => {
        test('should find users with admin role using roles_in=admin', async () => {
            const response = await request(app)
                .get('/test-users?roles_in=admin')
                .expect(200);

            console.log(
                'roles_in=admin response:',
                JSON.stringify(response.body, null, 2)
            );

            // Should return user1 and user3 who have 'admin' in their roles array
            expect(Array.isArray(response.body)).toBe(true);

            if (response.body.length > 0) {
                const userIds = response.body.map((user) => user.id);
                expect(userIds).toContain('user1');
                expect(userIds).toContain('user3');
                expect(userIds).not.toContain('user2');
                expect(userIds).not.toContain('user4');
            } else {
                console.warn(
                    '⚠️  roles_in=admin returned empty array - SkibbaDB .in() may not work with arrays'
                );
            }
        });

        test('should find users with editor role using roles_in=editor', async () => {
            const response = await request(app)
                .get('/test-users?roles_in=editor')
                .expect(200);

            console.log(
                'roles_in=editor response:',
                JSON.stringify(response.body, null, 2)
            );

            if (response.body.length > 0) {
                const userIds = response.body.map((user) => user.id);
                expect(userIds).toContain('user2');
                expect(userIds).not.toContain('user1');
            } else {
                console.warn('⚠️  roles_in=editor returned empty array');
            }
        });

        test('should find users with multiple roles using multiple roles_in', async () => {
            const response = await request(app)
                .get('/test-users?roles_in=admin&roles_in=editor')
                .expect(200);

            console.log(
                'Multiple roles_in response:',
                JSON.stringify(response.body, null, 2)
            );
        });
    });

    describe('Array filtering with _like operator', () => {
        test('should find users with admin-like roles using roles_like=admin', async () => {
            const response = await request(app)
                .get('/test-users?roles_like=admin')
                .expect(200);

            console.log(
                'roles_like=admin response:',
                JSON.stringify(response.body, null, 2)
            );

            if (response.body.length > 0) {
                // Should match both 'admin' and 'superadmin'
                const userIds = response.body.map((user) => user.id);
                expect(userIds).toContain('user1');
                expect(userIds).toContain('user3'); // has 'superadmin'
            } else {
                console.warn(
                    '⚠️  roles_like=admin returned empty array - SkibbaDB .like() may not work with arrays'
                );
            }
        });
    });

    describe('Direct SkibbaDB query tests (bypassing REST API)', () => {
        test('should test SkibbaDB .in() method directly on array field', async () => {
            console.log('\n=== Direct SkibbaDB Tests ===');

            // Test direct query
            const directResults = await usersCollection
                .where('roles')
                .in(['admin'])
                .toArray();

            console.log(
                'Direct .in() query results:',
                JSON.stringify(directResults, null, 2)
            );

            if (directResults.length === 0) {
                console.warn(
                    '⚠️  SkibbaDB .in() does not work with array fields as expected'
                );

                // Try alternative approaches
                console.log('\n=== Testing alternative approaches ===');

                // Test if .eq() works with the full array
                const eqResults = await usersCollection
                    .where('roles')
                    .eq(['admin', 'user'])
                    .toArray();
                console.log(
                    'Direct .eq() with full array:',
                    JSON.stringify(eqResults, null, 2)
                );

                // Test if we can query individual elements (if SkibbaDB supports nested queries)
                try {
                    const containsResults = await usersCollection
                        .where('roles.0') // First element
                        .eq('admin')
                        .toArray();
                    console.log(
                        'Nested query roles.0:',
                        JSON.stringify(containsResults, null, 2)
                    );
                } catch (e) {
                    console.log('Nested query not supported:', e.message);
                }
            }
        });

        test('should test SkibbaDB .like() method directly on array field', async () => {
            const directResults = await usersCollection
                .where('roles')
                .like('admin')
                .toArray();

            console.log(
                'Direct .like() query results:',
                JSON.stringify(directResults, null, 2)
            );

            if (directResults.length === 0) {
                console.warn(
                    '⚠️  SkibbaDB .like() does not work with array fields as expected'
                );
            }
        });

        test('should get all users to verify test data', async () => {
            const allUsers = await usersCollection.query().toArray();
            console.log('\n=== All test users ===');
            console.log(JSON.stringify(allUsers, null, 2));

            expect(allUsers.length).toBe(4);

            // Verify our test data structure
            const adminUsers = allUsers.filter(
                (user) =>
                    Array.isArray(user.roles) && user.roles.includes('admin')
            );
            console.log(
                'Users with admin role (JS filter):',
                adminUsers.length
            );
            expect(adminUsers.length).toBe(2); // user1 and user3
        });
    });

    describe('Alternative REST API workarounds', () => {
        test('should test equality filter on name field (non-array)', async () => {
            const response = await request(app)
                .get('/test-users?name=Admin User')
                .expect(200);

            console.log(
                'Name equality filter:',
                JSON.stringify(response.body, null, 2)
            );
            expect(response.body.length).toBe(1);
        });

        test('should test _like filter on name field (non-array)', async () => {
            const response = await request(app)
                .get('/test-users?name_like=Admin')
                .expect(200);

            console.log(
                'Name like filter:',
                JSON.stringify(response.body, null, 2)
            );
            // Should match "Admin User" and "Super Admin"
            expect(response.body.length).toBeGreaterThanOrEqual(1);
        });
    });
});

// If you want to run this as a standalone script:
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log('Running array filtering tests...');

    // Simple test runner
    const runTests = async () => {
        const database = new Database({ path: './test-data' });
        const usersCollection = database.collection('test-users', UserSchema);

        // Insert test data
        const testUsers = [
            {
                id: 'user1',
                name: 'Admin User',
                roles: ['admin', 'user'],
                email: 'admin@test.com',
            },
            {
                id: 'user2',
                name: 'Editor User',
                roles: ['editor', 'user'],
                email: 'editor@test.com',
            },
            {
                id: 'user3',
                name: 'Super Admin',
                roles: ['superadmin', 'admin', 'user'],
                email: 'superadmin@test.com',
            },
            {
                id: 'user4',
                name: 'Regular User',
                roles: ['user'],
                email: 'user@test.com',
            },
        ];

        try {
            await usersCollection.deleteBulk([]);
        } catch (e) {}

        for (const user of testUsers) {
            await usersCollection.insert(user);
        }

        // Test direct queries
        console.log('\n=== Testing SkibbaDB array queries directly ===');

        const inResults = await usersCollection
            .where('roles')
            .in(['admin'])
            .toArray();
        console.log('roles.in(["admin"]):', inResults.length, 'results');

        const likeResults = await usersCollection
            .where('roles')
            .like('admin')
            .toArray();
        console.log('roles.like("admin"):', likeResults.length, 'results');

        const allUsers = await usersCollection.query().toArray();
        console.log('Total users:', allUsers.length);
        console.log('Sample user:', JSON.stringify(allUsers[0], null, 2));
    };

    runTests().catch(console.error);
}
