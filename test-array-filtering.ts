import { Database, Collection } from 'skibbadb';
import { z } from 'zod';
import express from 'express';
import request from 'supertest';
import { createSkibbaExpress } from './index';

// Test schema matching your data structure
const UserSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    age: z.number(),
    createdAt: z.string(),
    updatedAt: z.string(),
    isActive: z.boolean(),
    roles: z.array(z.string()),
});

async function testArrayFiltering() {
    console.log('🔍 Testing Array Filtering Issue...\n');

    // Setup test database and collection
    const database = new Database({ path: './test-data-debug' });
    const usersCollection = database.collection('users', UserSchema);

    // Create test data similar to your real data
    const testUsers = [
        {
            id: 'test-1',
            name: 'Test User 1',
            email: 'test1@example.com',
            age: 25,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            isActive: true,
            roles: [],
        },
        {
            id: 'test-2',
            name: 'Test User 2',
            email: 'test2@example.com',
            age: 30,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            isActive: true,
            roles: ['admin'],
        },
        {
            id: 'test-3',
            name: 'Test User 3',
            email: 'test3@example.com',
            age: 28,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            isActive: true,
            roles: ['admin', 'user'],
        },
    ];

    // Clear and insert test data
    try {
        const existing = await usersCollection.query().toArray();
        for (const user of existing) {
            await usersCollection.delete(user.id);
        }
    } catch (e: any) {
        console.log('Cleanup skip:', e.message);
    }

    for (const user of testUsers) {
        await usersCollection.insert(user);
    }

    console.log('✅ Test data inserted\n');

    // Test direct SkibbaDB queries first
    console.log('=== DIRECT SKIBBADB TESTS ===');

    try {
        // Test 1: All users
        const allUsers = await usersCollection.query().toArray();
        console.log(
            'All users:',
            allUsers.map((u) => ({ id: u.id, roles: u.roles }))
        );

        // Test 2: Try .in() with array
        console.log('\n🧪 Testing .in() with array value...');
        const inResults = await usersCollection
            .where('roles')
            .in(['admin'])
            .toArray();
        console.log(
            'Result of .where("roles").in(["admin"]):',
            inResults.map((u) => ({ id: u.id, roles: u.roles }))
        );

        // Test 3: Try .in() with single value
        console.log('\n🧪 Testing .in() with single value...');
        const inSingleResults = await usersCollection
            .where('roles')
            .in('admin')
            .toArray();
        console.log(
            'Result of .where("roles").in("admin"):',
            inSingleResults.map((u) => ({ id: u.id, roles: u.roles }))
        );

        // Test 4: Check if SkibbaDB has arrayContains or contains method
        console.log('\n🧪 Testing if arrayContains method exists...');
        try {
            const containsResults = await usersCollection
                .where('roles')
                .contains('admin')
                .toArray();
            console.log(
                'Result of .where("roles").contains("admin"):',
                containsResults.map((u) => ({ id: u.id, roles: u.roles }))
            );
        } catch (e: any) {
            console.log('❌ .contains() method not available:', e.message);
        }

        // Test 5: Check if SkibbaDB has arrayContains method
        try {
            const arrayContainsResults = await usersCollection
                .where('roles')
                .arrayContains('admin')
                .toArray();
            console.log(
                'Result of .where("roles").arrayContains("admin"):',
                arrayContainsResults.map((u) => ({ id: u.id, roles: u.roles }))
            );
        } catch (e: any) {
            console.log('❌ .arrayContains() method not available:', e.message);
        }

        // Test 6: Try equality check with exact array
        console.log('\n🧪 Testing equality with exact array...');
        const eqResults = await usersCollection
            .where('roles')
            .eq(['admin'])
            .toArray();
        console.log(
            'Result of .where("roles").eq(["admin"]):',
            eqResults.map((u) => ({ id: u.id, roles: u.roles }))
        );

        // Test 7: Let's also examine the query builder and see what methods are available
        console.log('\n🧪 Examining query builder methods...');
        const queryBuilder = usersCollection.where('roles');
        console.log(
            'Available methods on query builder:',
            Object.getOwnPropertyNames(Object.getPrototypeOf(queryBuilder))
        );
    } catch (e: any) {
        console.error('❌ Direct query error:', e);
    }

    // Test REST API
    console.log('\n=== REST API TESTS ===');

    const expressApp = express();
    const app = createSkibbaExpress(expressApp, database);

    app.useCollection(usersCollection, {
        GET: {},
        basePath: '/users',
    });

    // Test different query variations
    const testQueries = [
        'roles_in=admin',
        'roles_in=["admin"]',
        'roles=admin',
        'roles_contains=admin',
        'roles_like=admin',
    ];

    for (const query of testQueries) {
        try {
            console.log(`\n🧪 Testing: /users?${query}`);
            const response = await request(app)
                .get(`/users?${query}`)
                .expect(200);

            console.log(
                `Result (${response.body.length} items):`,
                response.body.map((u: any) => ({ id: u.id, roles: u.roles }))
            );
        } catch (e: any) {
            console.error(`❌ Query "${query}" error:`, e.message);
        }
    }

    // Let's also test with other fields to confirm filtering works
    console.log('\n=== TESTING OTHER FIELD FILTERS ===');

    try {
        console.log('\n🧪 Testing name filter...');
        const nameResponse = await request(app)
            .get('/users?name=Test User 2')
            .expect(200);

        console.log(
            'Name filter result:',
            nameResponse.body.map((u: any) => ({ id: u.id, name: u.name }))
        );

        console.log('\n🧪 Testing age_gt filter...');
        const ageResponse = await request(app)
            .get('/users?age_gt=26')
            .expect(200);

        console.log(
            'Age > 26 filter result:',
            ageResponse.body.map((u: any) => ({ id: u.id, age: u.age }))
        );
    } catch (e: any) {
        console.error('❌ Other filter test error:', e);
    }

    // Cleanup
    try {
        const existing = await usersCollection.query().toArray();
        for (const user of existing) {
            await usersCollection.delete(user.id);
        }
    } catch (e: any) {
        console.log('Cleanup error:', e.message);
    }

    console.log('\n🏁 Test completed');
}

// Run the test
testArrayFiltering().catch(console.error);
