// filepath: /Users/brendon/Documents/BRENDON PORTFOLIO 2025/skibbadb-express/tests/rest_select.test.ts

import request from 'supertest';
import express from 'express';
import { createDB, Collection } from 'skibbadb';
import { z } from 'zod';
import { createSkibbaExpress } from '../index';
import {
    describe,
    beforeAll,
    afterAll,
    beforeEach,
    test,
    expect,
} from 'vitest';

describe('REST API Select Functionality - Comprehensive Tests', () => {
    let app: any;
    let database: any;
    let peopleCollection: Collection<any>;
    let companiesCollection: Collection<any>;
    let ordersCollection: Collection<any>;

    // Define comprehensive schemas for testing nested selections
    const PersonSchema = z.object({
        _id: z.string(),
        name: z.string(),
        email: z.string(),
        age: z.number().optional(),
        profile: z
            .object({
                bio: z.string().optional(),
                avatar: z.string().optional(),
                preferences: z
                    .object({
                        theme: z.string().optional(),
                        notifications: z
                            .object({
                                email: z.boolean().optional(),
                                push: z.boolean().optional(),
                                sms: z.boolean().optional(),
                            })
                            .optional(),
                        privacy: z
                            .object({
                                showEmail: z.boolean().optional(),
                                showAge: z.boolean().optional(),
                            })
                            .optional(),
                    })
                    .optional(),
                social: z
                    .object({
                        twitter: z.string().optional(),
                        linkedin: z.string().optional(),
                        github: z.string().optional(),
                    })
                    .optional(),
            })
            .optional(),
        address: z
            .object({
                street: z.string(),
                city: z.string(),
                state: z.string().optional(),
                country: z.object({
                    code: z.string(),
                    name: z.string(),
                    region: z.object({
                        code: z.string(),
                        name: z.string(),
                        continent: z.object({
                            code: z.string(),
                            name: z.string(),
                        }),
                    }),
                }),
                postal: z.string().optional(),
                coordinates: z
                    .object({
                        lat: z.number(),
                        lng: z.number(),
                    })
                    .optional(),
            })
            .optional(),
        tags: z.array(z.string()).optional(),
        metadata: z.record(z.any()).optional(),
        createdAt: z.string(),
        updatedAt: z.string().optional(),
    });

    const CompanySchema = z.object({
        _id: z.string(),
        name: z.string(),
        industry: z.string(),
        employees: z.number(),
        founded: z.number(),
        headquarters: z.object({
            address: z.object({
                street: z.string(),
                city: z.string(),
                country: z.object({
                    code: z.string(),
                    name: z.string(),
                }),
            }),
            contact: z.object({
                phone: z.string(),
                email: z.string(),
                website: z.string().optional(),
            }),
        }),
        departments: z
            .array(
                z.object({
                    name: z.string(),
                    budget: z.number(),
                    head: z.object({
                        name: z.string(),
                        email: z.string(),
                    }),
                })
            )
            .optional(),
    });

    const OrderSchema = z.object({
        _id: z.string(),
        customerId: z.string(),
        items: z.array(
            z.object({
                id: z.string(),
                name: z.string(),
                price: z.number(),
                quantity: z.number(),
                specifications: z
                    .object({
                        weight: z.number().optional(),
                        dimensions: z
                            .object({
                                length: z.number(),
                                width: z.number(),
                                height: z.number(),
                            })
                            .optional(),
                    })
                    .optional(),
            })
        ),
        shipping: z.object({
            address: z.object({
                street: z.string(),
                city: z.string(),
                country: z.string(),
            }),
            method: z.string(),
            cost: z.number(),
        }),
        total: z.number(),
        status: z.string(),
        createdAt: z.string(),
    });

    beforeAll(async () => {
        // Initialize database and collections
        database = createDB({ path: './test_rest_select_db' });

        peopleCollection = database.collection('people', PersonSchema);
        companiesCollection = database.collection('companies', CompanySchema);
        ordersCollection = database.collection('orders', OrderSchema);

        // Initialize Express app
        const expressApp = express();
        app = createSkibbaExpress(expressApp, database);

        // Setup collection endpoints
        app.useCollection(peopleCollection, {
            GET: {},
            POST: {},
            PUT: {},
            DELETE: {},
            basePath: '/people',
        });

        app.useCollection(companiesCollection, {
            GET: {},
            POST: {},
            DELETE: {},
            basePath: '/companies',
        });

        app.useCollection(ordersCollection, {
            GET: {},
            POST: {},
            DELETE: {},
            basePath: '/orders',
        });

        // Insert comprehensive test data
        await setupTestData();
    });

    beforeEach(async () => {
        // Ensure clean state for each test
        await setupTestData();
    });

    afterAll(async () => {
        // Cleanup all test data
        await cleanupTestData();
    });

    async function setupTestData() {
        // Clean existing data first
        await cleanupTestData();

        // Insert test people with nested data
        const testPeople = [
            {
                _id: 'person1',
                name: 'Alice Johnson',
                email: 'alice@example.com',
                age: 30,
                profile: {
                    bio: 'Software developer with 8 years experience',
                    avatar: 'https://example.com/alice.jpg',
                    preferences: {
                        theme: 'dark',
                        notifications: {
                            email: true,
                            push: false,
                            sms: true,
                        },
                        privacy: {
                            showEmail: false,
                            showAge: true,
                        },
                    },
                    social: {
                        twitter: '@alicejohnson',
                        linkedin: 'alice-johnson',
                        github: 'alicej',
                    },
                },
                address: {
                    street: '123 Main St',
                    city: 'New York',
                    state: 'NY',
                    country: {
                        code: 'US',
                        name: 'United States',
                        region: {
                            code: 'NA',
                            name: 'North America',
                            continent: {
                                code: 'AM',
                                name: 'Americas',
                            },
                        },
                    },
                    postal: '10001',
                    coordinates: {
                        lat: 40.7128,
                        lng: -74.006,
                    },
                },
                tags: ['developer', 'javascript', 'react'],
                metadata: {
                    source: 'manual',
                    verified: true,
                    score: 95,
                },
                createdAt: '2024-01-15T10:00:00Z',
                updatedAt: '2024-01-16T15:30:00Z',
            },
            {
                _id: 'person2',
                name: 'Bob Smith',
                email: 'bob@example.com',
                age: 25,
                profile: {
                    bio: 'Product manager and UX enthusiast',
                    preferences: {
                        theme: 'light',
                        notifications: {
                            email: true,
                            push: true,
                            sms: false,
                        },
                    },
                    social: {
                        linkedin: 'bob-smith-pm',
                    },
                },
                address: {
                    street: '456 Oak Ave',
                    city: 'San Francisco',
                    state: 'CA',
                    country: {
                        code: 'US',
                        name: 'United States',
                        region: {
                            code: 'NA',
                            name: 'North America',
                            continent: {
                                code: 'AM',
                                name: 'Americas',
                            },
                        },
                    },
                    postal: '94102',
                },
                tags: ['product', 'ux', 'strategy'],
                createdAt: '2024-01-10T09:00:00Z',
            },
            {
                _id: 'person3',
                name: 'Carol Davis',
                email: 'carol@example.com',
                profile: {
                    bio: 'Marketing specialist',
                    preferences: {
                        notifications: {
                            email: false,
                            push: false,
                            sms: false,
                        },
                    },
                },
                address: {
                    street: '789 Pine St',
                    city: 'London',
                    country: {
                        code: 'GB',
                        name: 'United Kingdom',
                        region: {
                            code: 'EU',
                            name: 'Europe',
                            continent: {
                                code: 'EU',
                                name: 'Europe',
                            },
                        },
                    },
                    postal: 'SW1A 1AA',
                },
                tags: ['marketing', 'digital'],
                createdAt: '2024-01-05T14:00:00Z',
            },
        ];

        const testCompanies = [
            {
                _id: 'company1',
                name: 'Tech Innovations Inc',
                industry: 'Technology',
                employees: 150,
                founded: 2015,
                headquarters: {
                    address: {
                        street: '100 Tech Plaza',
                        city: 'San Francisco',
                        country: {
                            code: 'US',
                            name: 'United States',
                        },
                    },
                    contact: {
                        phone: '+1-555-0100',
                        email: 'info@techinnovations.com',
                        website: 'https://techinnovations.com',
                    },
                },
                departments: [
                    {
                        name: 'Engineering',
                        budget: 2500000,
                        head: {
                            name: 'Jane Doe',
                            email: 'jane.doe@techinnovations.com',
                        },
                    },
                    {
                        name: 'Marketing',
                        budget: 800000,
                        head: {
                            name: 'John Smith',
                            email: 'john.smith@techinnovations.com',
                        },
                    },
                ],
            },
            {
                _id: 'company2',
                name: 'Global Solutions Ltd',
                industry: 'Consulting',
                employees: 75,
                founded: 2010,
                headquarters: {
                    address: {
                        street: '50 Business Center',
                        city: 'London',
                        country: {
                            code: 'GB',
                            name: 'United Kingdom',
                        },
                    },
                    contact: {
                        phone: '+44-20-7946-0958',
                        email: 'contact@globalsolutions.co.uk',
                    },
                },
            },
        ];

        const testOrders = [
            {
                _id: 'order1',
                customerId: 'person1',
                items: [
                    {
                        id: 'item1',
                        name: 'Laptop',
                        price: 1299.99,
                        quantity: 1,
                        specifications: {
                            weight: 2.1,
                            dimensions: {
                                length: 35.7,
                                width: 24.7,
                                height: 1.95,
                            },
                        },
                    },
                    {
                        id: 'item2',
                        name: 'Mouse',
                        price: 49.99,
                        quantity: 2,
                        specifications: {
                            weight: 0.08,
                        },
                    },
                ],
                shipping: {
                    address: {
                        street: '123 Main St',
                        city: 'New York',
                        country: 'US',
                    },
                    method: 'express',
                    cost: 15.99,
                },
                total: 1415.96,
                status: 'shipped',
                createdAt: '2024-01-20T10:00:00Z',
            },
        ];

        // Insert all test data
        for (const person of testPeople) {
            await peopleCollection.insert(person);
        }
        for (const company of testCompanies) {
            await companiesCollection.insert(company);
        }
        for (const order of testOrders) {
            await ordersCollection.insert(order);
        }
    }

    async function cleanupTestData() {
        try {
            const collections = [
                peopleCollection,
                companiesCollection,
                ordersCollection,
            ];
            for (const collection of collections) {
                const items = await collection.query().toArray();
                for (const item of items) {
                    await collection.delete((item as any)._id);
                }
            }
        } catch (e) {
            // Ignore cleanup errors
        }
    }

    describe('Basic Field Selection', () => {
        test('should select single field using array syntax', async () => {
            const response = await request(app)
                .get("/people?select=['name']")
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('_id'); // ID should always be included
            expect(person).not.toHaveProperty('email');
            expect(person).not.toHaveProperty('age');
            expect(person).not.toHaveProperty('profile');
        });

        test('should select multiple fields using array syntax', async () => {
            const response = await request(app)
                .get("/people?select=['name','email','age']")
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('email');
            expect(person).toHaveProperty('age');
            expect(person).not.toHaveProperty('profile');
            expect(person).not.toHaveProperty('address');
        });

        test('should select fields using JSON array syntax', async () => {
            const response = await request(app)
                .get('/people?select=["name","email"]')
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('email');
            expect(person).not.toHaveProperty('age');
        });

        test('should select fields using comma-separated syntax', async () => {
            const response = await request(app)
                .get('/people?select=name,email')
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('email');
            expect(person).not.toHaveProperty('age');
        });

        test('should select fields for individual record by ID', async () => {
            const response = await request(app)
                .get("/people/person1?select=['name','email']")
                .expect(200);

            expect(response.body).toHaveProperty('name', 'Alice Johnson');
            expect(response.body).toHaveProperty('email', 'alice@example.com');
            expect(response.body).not.toHaveProperty('age');
            expect(response.body).not.toHaveProperty('profile');
        });
    });

    describe('Nested Field Selection', () => {
        test('should select nested fields at second level', async () => {
            const response = await request(app)
                .get("/people?select=['name','profile.bio','profile.avatar']")
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            expect(person.profile).toHaveProperty('bio');
            expect(person.profile).toHaveProperty('avatar');
            expect(person.profile).not.toHaveProperty('preferences');
            expect(person).not.toHaveProperty('email');
        });

        test('should select nested fields at third level', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','profile.preferences.theme','profile.preferences.notifications.email']"
                )
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            expect(person.profile.preferences).toHaveProperty('theme');
            expect(person.profile.preferences.notifications).toHaveProperty(
                'email'
            );
            expect(person.profile.preferences.notifications).not.toHaveProperty(
                'push'
            );
            expect(person.profile.preferences).not.toHaveProperty('privacy');
        });

        test('should select deeply nested fields (4-5 levels)', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','address.country.region.continent.name','address.coordinates.lat']"
                )
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            expect(person.address.country.region.continent).toHaveProperty(
                'name',
                'Americas'
            );
            expect(person.address.coordinates).toHaveProperty('lat');
            expect(person.address.coordinates).not.toHaveProperty('lng');
            expect(person.address.country).not.toHaveProperty('code');
        });

        test('should select mixed nested and top-level fields', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','email','profile.bio','address.city','address.country.name']"
                )
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('email');
            expect(person.profile).toHaveProperty('bio');
            expect(person.address).toHaveProperty('city');
            expect(person.address.country).toHaveProperty('name');
            expect(person.address).not.toHaveProperty('street');
            expect(person.profile).not.toHaveProperty('preferences');
        });
    });

    describe('Array and Complex Data Type Selection', () => {
        test('should select array fields', async () => {
            const response = await request(app)
                .get("/people?select=['name','tags']")
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('tags');
            expect(Array.isArray(person.tags)).toBe(true);
            expect(person.tags).toContain('developer');
            expect(person).not.toHaveProperty('email');
        });

        test('should select nested arrays with complex objects', async () => {
            const response = await request(app)
                .get(
                    "/orders?select=['customerId','items.name','items.price','items.specifications.weight']"
                )
                .expect(200);

            const order = response.body[0];
            expect(order).toHaveProperty('customerId');
            expect(Array.isArray(order.items)).toBe(true);
            expect(order.items[0]).toHaveProperty('name');
            expect(order.items[0]).toHaveProperty('price');
            expect(order.items[0].specifications).toHaveProperty('weight');
            expect(order.items[0]).not.toHaveProperty('id');
            expect(order.items[0]).not.toHaveProperty('quantity');
        });

        test('should select deeply nested arrays', async () => {
            const response = await request(app)
                .get(
                    "/companies?select=['name','departments.name','departments.head.email']"
                )
                .expect(200);

            const company = response.body.find((c) => c._id === 'company1');
            expect(company).toHaveProperty('name');
            expect(Array.isArray(company.departments)).toBe(true);
            expect(company.departments[0]).toHaveProperty('name');
            expect(company.departments[0].head).toHaveProperty('email');
            expect(company.departments[0]).not.toHaveProperty('budget');
            expect(company.departments[0].head).not.toHaveProperty('name');
        });

        test('should select metadata and dynamic fields', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','metadata.verified','metadata.score']"
                )
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            expect(person.metadata).toHaveProperty('verified');
            expect(person.metadata).toHaveProperty('score');
            expect(person.metadata).not.toHaveProperty('source');
        });
    });

    describe('Select with Other Query Parameters', () => {
        test('should combine select with filtering', async () => {
            const response = await request(app)
                .get("/people?select=['name','age']&age_gte=25")
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                expect(person).toHaveProperty('age');
                expect(person.age).toBeGreaterThanOrEqual(25);
                expect(person).not.toHaveProperty('email');
            }
        });

        test('should combine select with sorting', async () => {
            const response = await request(app)
                .get("/people?select=['name','age']&sort=age&order=desc")
                .expect(200);

            expect(response.body.length).toBeGreaterThan(1);
            expect(response.body[0]).toHaveProperty('name');
            expect(response.body[0]).toHaveProperty('age');

            // Verify sorting
            for (let i = 1; i < response.body.length; i++) {
                if (response.body[i - 1].age && response.body[i].age) {
                    expect(response.body[i - 1].age).toBeGreaterThanOrEqual(
                        response.body[i].age
                    );
                }
            }
        });

        test('should combine select with pagination', async () => {
            const response = await request(app)
                .get("/people?select=['name','email']&limit=2&offset=0")
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeLessThanOrEqual(2);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                expect(person).toHaveProperty('email');
                expect(person).not.toHaveProperty('age');
            }
        });

        test('should combine select with complex nested filtering', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','address.city','profile.preferences.theme']&address.country.code=US"
                )
                .expect(200);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                expect(person.address).toHaveProperty('city');
                if (person.profile?.preferences) {
                    expect(person.profile.preferences).toHaveProperty('theme');
                }
                expect(person).not.toHaveProperty('email');
            }
        });
    });

    describe('Error Handling and Edge Cases', () => {
        test('should handle invalid field names gracefully', async () => {
            const response = await request(app)
                .get("/people?select=['name','nonexistentField']")
                .expect(200); // Should still return 200 but ignore invalid fields

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).not.toHaveProperty('nonexistentField');
        });

        test('should handle empty select parameter', async () => {
            const response = await request(app)
                .get('/people?select=[]')
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('_id'); // ID should always be present
            // Other fields may or may not be present depending on implementation
        });

        test('should handle malformed select syntax', async () => {
            const response = await request(app)
                .get('/people?select=[invalid')
                .expect(200); // Should gracefully handle and maybe return all fields

            expect(Array.isArray(response.body)).toBe(true);
        });

        test('should handle URL-encoded select parameters', async () => {
            const selectParam = encodeURIComponent("['name','profile.bio']");
            const response = await request(app)
                .get(`/people?select=${selectParam}`)
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            if (person.profile) {
                expect(person.profile).toHaveProperty('bio');
            }
        });

        test('should handle deeply nested non-existent paths', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','profile.nonexistent.deeply.nested.field']"
                )
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            // Should not have the nested structure for non-existent fields
        });

        test('should handle special characters in field names', async () => {
            // This tests the robustness of the field parsing
            const response = await request(app)
                .get("/people?select=['name','profile.social.github']")
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(person).toHaveProperty('name');
            if (person.profile?.social) {
                expect(person.profile.social).toHaveProperty('github');
            }
        });
    });

    describe('Performance and Large Dataset Tests', () => {
        test('should handle select with many fields efficiently', async () => {
            const manyFields = [
                'name',
                'email',
                'age',
                'profile.bio',
                'profile.avatar',
                'profile.preferences.theme',
                'profile.preferences.notifications.email',
                'profile.social.twitter',
                'profile.social.linkedin',
                'address.street',
                'address.city',
                'address.country.name',
                'address.coordinates.lat',
                'address.coordinates.lng',
                'tags',
                'metadata.verified',
                'createdAt',
            ];

            const selectParam = JSON.stringify(manyFields);
            const response = await request(app)
                .get(`/people?select=${encodeURIComponent(selectParam)}`)
                .expect(200);

            const person = response.body[0];
            expect(person).toHaveProperty('name');
            expect(person).toHaveProperty('email');
            expect(person).toHaveProperty('age');
            // Verify some nested fields are present
            if (person.profile) {
                expect(person.profile).toHaveProperty('bio');
            }
        });

        test('should handle select on empty collections', async () => {
            // Test with a collection that has no data
            const response = await request(app)
                .get(
                    "/orders?select=['customerId','total']&customerId=nonexistent"
                )
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBe(0);
        });

        test('should handle complex nested selection on arrays with many items', async () => {
            // This tests performance with complex array selections
            const response = await request(app)
                .get(
                    "/orders?select=['items.name','items.specifications.dimensions.length','shipping.address.city']"
                )
                .expect(200);

            const order = response.body[0];
            expect(Array.isArray(order.items)).toBe(true);
            if (order.items.length > 0) {
                expect(order.items[0]).toHaveProperty('name');
                if (order.items[0].specifications?.dimensions) {
                    expect(
                        order.items[0].specifications.dimensions
                    ).toHaveProperty('length');
                }
            }
            expect(order.shipping.address).toHaveProperty('city');
        });
    });

    describe('Real-world Usage Patterns', () => {
        test('should support user profile API pattern', async () => {
            const response = await request(app)
                .get(
                    "/people/person1?select=['name','email','profile.avatar','profile.bio','profile.social']"
                )
                .expect(200);

            expect(response.body).toHaveProperty('name');
            expect(response.body).toHaveProperty('email');
            expect(response.body.profile).toHaveProperty('avatar');
            expect(response.body.profile).toHaveProperty('bio');
            expect(response.body.profile).toHaveProperty('social');
            expect(response.body).not.toHaveProperty('age');
            expect(response.body).not.toHaveProperty('address');
        });

        test('should support minimal contact info API pattern', async () => {
            const response = await request(app)
                .get("/people?select=['name','email','profile.avatar']")
                .expect(200);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                expect(person).toHaveProperty('email');
                
                // SkibbaDB creates empty profile objects when selecting nested fields that don't exist
                // Only check for avatar if the profile has content
                if (person.profile && Object.keys(person.profile).length > 0) {
                    expect(person.profile).toHaveProperty('avatar');
                    expect(person.profile).not.toHaveProperty('bio');
                }
                expect(person).not.toHaveProperty('address');
            }
        });

        test('should support geographic data API pattern', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','address.city','address.country.name','address.coordinates']"
                )
                .expect(200);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                if (person.address) {
                    expect(person.address).toHaveProperty('city');
                    expect(person.address.country).toHaveProperty('name');
                    // coordinates is optional
                }
                expect(person).not.toHaveProperty('email');
            }
        });

        test('should support company directory API pattern', async () => {
            const response = await request(app)
                .get(
                    "/companies?select=['name','industry','employees','headquarters.address.city','headquarters.contact.website']"
                )
                .expect(200);

            for (const company of response.body) {
                expect(company).toHaveProperty('name');
                expect(company).toHaveProperty('industry');
                expect(company).toHaveProperty('employees');
                expect(company.headquarters.address).toHaveProperty('city');
                // website is optional
                expect(company).not.toHaveProperty('founded');
            }
        });

        test('should support order summary API pattern', async () => {
            const response = await request(app)
                .get(
                    "/orders?select=['customerId','total','status','items.name','items.price','shipping.method']"
                )
                .expect(200);

            const order = response.body[0];
            expect(order).toHaveProperty('customerId');
            expect(order).toHaveProperty('total');
            expect(order).toHaveProperty('status');
            expect(Array.isArray(order.items)).toBe(true);
            if (order.items.length > 0) {
                expect(order.items[0]).toHaveProperty('name');
                expect(order.items[0]).toHaveProperty('price');
                expect(order.items[0]).not.toHaveProperty('id');
            }
            expect(order.shipping).toHaveProperty('method');
            expect(order.shipping).not.toHaveProperty('cost');
        });
    });

    describe('Integration with Field Validation', () => {
        test('should respect schema field types in selection', async () => {
            const response = await request(app)
                .get(
                    "/people?select=['name','age','profile.preferences.notifications.email']"
                )
                .expect(200);

            const person = response.body.find((p) => p._id === 'person1');
            expect(typeof person.name).toBe('string');
            expect(typeof person.age).toBe('number');
            if (person.profile?.preferences?.notifications) {
                expect(
                    typeof person.profile.preferences.notifications.email
                ).toBe('boolean');
            }
        });

        test('should handle optional fields correctly in selection', async () => {
            const response = await request(app)
                .get("/people?select=['name','age','profile.avatar']")
                .expect(200);

            for (const person of response.body) {
                expect(person).toHaveProperty('name');
                // age is optional, so some might not have it
                if (person.hasOwnProperty('age')) {
                    expect(typeof person.age).toBe('number');
                }
                // avatar is optional
                if (person.profile?.avatar) {
                    expect(typeof person.profile.avatar).toBe('string');
                }
            }
        });
    });
});
