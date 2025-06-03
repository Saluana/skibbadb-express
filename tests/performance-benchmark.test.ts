// Performance Benchmark Test: index.ts vs index.backup.ts
import { Database } from 'skibbadb';
import { createSkibbaExpress as createCurrentVersion } from '../index';
import { createSkibbaExpress as createBackupVersion } from '../index.backup';
import express from 'express';
import request from 'supertest';
import { z } from 'zod';
import { describe, it, beforeAll, afterAll } from 'vitest';

// Benchmark configuration
const BENCHMARK_CONFIG = {
    // Dataset sizes for testing (reduced for faster execution)
    SMALL_DATASET: 50,
    MEDIUM_DATASET: 200,
    LARGE_DATASET: 500,

    // Number of iterations for each test (reduced for faster execution)
    ITERATIONS: 5,

    // Warmup runs to stabilize performance
    WARMUP_RUNS: 2,

    // Test timeout (60 seconds)
    TIMEOUT: 60000,
};

// User schema for testing
const userSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    age: z.number().min(1).max(150),
    role: z.enum(['admin', 'user', 'moderator']),
    isActive: z.boolean(),
    department: z.string().optional(),
    salary: z.number().optional(),
    createdAt: z.string(),
    lastLogin: z.string().optional(),
});

// Benchmark result interface
interface BenchmarkResult {
    operation: string;
    currentVersion: {
        avgTime: number;
        minTime: number;
        maxTime: number;
        totalTime: number;
        memoryUsage: number;
    };
    backupVersion: {
        avgTime: number;
        minTime: number;
        maxTime: number;
        totalTime: number;
        memoryUsage: number;
    };
    performanceRatio: number; // current / backup (< 1 means current is faster)
    improvement: string; // percentage improvement
}

class PerformanceBenchmark {
    private currentApp: express.Application;
    private backupApp: express.Application;
    private currentDb: Database;
    private backupDb: Database;
    private results: BenchmarkResult[] = [];

    constructor() {
        this.currentApp = express();
        this.backupApp = express();
        this.currentDb = new Database({ path: ':memory:' });
        this.backupDb = new Database({ path: ':memory:' });
    }

    async setup() {
        console.log('🚀 Setting up Performance Benchmark...\n');

        // Setup current version
        const currentSkibba = createCurrentVersion(
            this.currentApp,
            this.currentDb
        );
        const currentUsers = this.currentDb.collection('users', userSchema, {
            constrainedFields: {
                email: { unique: true, nullable: false },
            },
        });
        currentSkibba.useCollection(currentUsers, {
            GET: { hooks: {} },
            POST: { hooks: {} },
            PUT: { hooks: {} },
            DELETE: { hooks: {} },
        });

        // Setup backup version
        const backupSkibba = createBackupVersion(this.backupApp, this.backupDb);
        const backupUsers = this.backupDb.collection('users', userSchema, {
            constrainedFields: {
                email: { unique: true, nullable: false },
            },
        });
        backupSkibba.useCollection(backupUsers, {
            GET: { hooks: {} },
            POST: { hooks: {} },
            PUT: { hooks: {} },
            DELETE: { hooks: {} },
        });

        console.log('✅ Benchmark setup complete\n');
    }

    // Generate test data
    generateUser(index: number) {
        const timestamp = Date.now();
        return {
            id: `user${index}-${timestamp}`,
            name: `User ${index}`,
            email: `user${index}-${timestamp}@test.com`,
            age: 20 + (index % 50), // Ages 20-69
            role: ['admin', 'user', 'moderator'][index % 3] as
                | 'admin'
                | 'user'
                | 'moderator',
            isActive: index % 4 !== 0, // 75% active
            department: ['Engineering', 'Sales', 'Marketing', 'HR'][index % 4],
            salary: 50000 + ((index * 1000) % 100000), // Salaries 50k-150k
            createdAt: new Date(Date.now() - index * 86400000).toISOString(), // Spread over time
            lastLogin:
                index % 5 !== 0
                    ? new Date(
                          Date.now() - (index % 30) * 86400000
                      ).toISOString()
                    : undefined,
        };
    }

    // Measure execution time and memory
    async measurePerformance(
        operation: () => Promise<any>,
        iterations: number = BENCHMARK_CONFIG.ITERATIONS
    ): Promise<{
        avgTime: number;
        minTime: number;
        maxTime: number;
        totalTime: number;
        memoryUsage: number;
    }> {
        const times: number[] = [];
        let totalTime = 0;
        const initialMemory = process.memoryUsage().heapUsed;

        // Warmup
        for (let i = 0; i < BENCHMARK_CONFIG.WARMUP_RUNS; i++) {
            await operation();
        }

        // Actual measurements
        for (let i = 0; i < iterations; i++) {
            const start = process.hrtime.bigint();
            await operation();
            const end = process.hrtime.bigint();
            const timeMs = Number(end - start) / 1_000_000;
            times.push(timeMs);
            totalTime += timeMs;
        }

        const finalMemory = process.memoryUsage().heapUsed;
        const memoryUsage = finalMemory - initialMemory;

        return {
            avgTime: totalTime / iterations,
            minTime: Math.min(...times),
            maxTime: Math.max(...times),
            totalTime,
            memoryUsage,
        };
    }

    // Benchmark basic CRUD operations
    async benchmarkCRUD() {
        console.log('📊 Benchmarking CRUD Operations...');

        const testUser = this.generateUser(1);

        // CREATE benchmark
        const createCurrent = await this.measurePerformance(async () => {
            const uniqueId = `create-current-${Date.now()}-${Math.random()}`;
            const uniqueUser = {
                ...testUser,
                id: uniqueId,
                email: `test-${uniqueId}@test.com`,
            };
            const response = await request(this.currentApp)
                .post('/users')
                .send(uniqueUser);

            if (response.status !== 201) {
                console.error('Current app CREATE failed:', {
                    status: response.status,
                    body: response.body,
                    testData: uniqueUser,
                });
                throw new Error(
                    `Expected 201, got ${response.status}: ${JSON.stringify(
                        response.body
                    )}`
                );
            }
        });

        const createBackup = await this.measurePerformance(async () => {
            const uniqueId = `create-backup-${Date.now()}-${Math.random()}`;
            const uniqueUser = {
                ...testUser,
                id: uniqueId,
                email: `test-${uniqueId}@test.com`,
            };
            await request(this.backupApp)
                .post('/users')
                .send(uniqueUser)
                .expect(201);
        });

        this.addResult('CREATE Operation', createCurrent, createBackup);

        // Setup data for READ/UPDATE/DELETE tests
        const readUser = {
            ...testUser,
            id: 'read-test-user',
            email: `read-test-user-${Date.now()}@test.com`,
        };
        await request(this.currentApp).post('/users').send(readUser);
        await request(this.backupApp)
            .post('/users')
            .send({
                ...readUser,
                email: `backup-read-test-user-${Date.now()}@test.com`,
            });

        // READ benchmark
        const readCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get('/users/read-test-user')
                .expect(200);
        });

        const readBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get('/users/read-test-user')
                .expect(200);
        });

        this.addResult('READ Operation', readCurrent, readBackup);

        // UPDATE benchmark
        const updateCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .put('/users/read-test-user')
                .send({ ...readUser, name: `Updated ${Date.now()}` })
                .expect(200);
        });

        const updateBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .put('/users/read-test-user')
                .send({ ...readUser, name: `Updated ${Date.now()}` })
                .expect(200);
        });

        this.addResult('UPDATE Operation', updateCurrent, updateBackup);
    }

    // Benchmark pagination with different dataset sizes
    async benchmarkPagination() {
        console.log('📊 Benchmarking Pagination...');

        // Create test datasets (only test with small dataset for speed)
        const size = BENCHMARK_CONFIG.SMALL_DATASET;
        console.log(`  Testing with ${size} records...`);

        // Setup data
        const users = Array.from({ length: size }, (_, i) => {
            const baseUser = this.generateUser(i);
            return {
                ...baseUser,
                id: `pagination-${size}-${i}`,
                email: `pagination-${size}-${i}@test.com`,
            };
        });

        // Insert data into both databases
        console.log(`    Inserting ${size} records into current app...`);
        for (const user of users) {
            await request(this.currentApp).post('/users').send(user);
        }

        console.log(`    Inserting ${size} records into backup app...`);
        for (const user of users) {
            await request(this.backupApp)
                .post('/users')
                .send({
                    ...user,
                    email: `backup-${user.email}`,
                });
        }

        // Test pagination without filters
        const paginationCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get('/users?page=2&limit=20')
                .expect(200);
        });

        const paginationBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get('/users?page=2&limit=20')
                .expect(200);
        });

        this.addResult(
            `Pagination (${size} records)`,
            paginationCurrent,
            paginationBackup
        );

        // Clear data for next test
        await this.clearData();
    }

    // Benchmark filtering operations
    async benchmarkFiltering() {
        console.log('📊 Benchmarking Filtering...');

        // Setup small dataset for speed
        const users = Array.from(
            { length: BENCHMARK_CONFIG.SMALL_DATASET },
            (_, i) => {
                const baseUser = this.generateUser(i);
                return {
                    ...baseUser,
                    id: `filtering-${i}`,
                    email: `filtering-${i}@test.com`,
                };
            }
        );

        console.log(
            `    Inserting ${BENCHMARK_CONFIG.SMALL_DATASET} records for filtering tests...`
        );
        for (const user of users) {
            await request(this.currentApp).post('/users').send(user);
            await request(this.backupApp)
                .post('/users')
                .send({
                    ...user,
                    email: `backup-${user.email}`,
                });
        }

        // Test equality filter
        const equalityCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp).get('/users?role=admin').expect(200);
        });

        const equalityBackup = await this.measurePerformance(async () => {
            await request(this.backupApp).get('/users?role=admin').expect(200);
        });

        this.addResult('Equality Filter', equalityCurrent, equalityBackup);

        // Test range filter
        const rangeCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get('/users?age_gte=25&age_lt=45')
                .expect(200);
        });

        const rangeBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get('/users?age_gte=25&age_lt=45')
                .expect(200);
        });

        this.addResult('Range Filter', rangeCurrent, rangeBackup);

        // Test LIKE filter
        const likeCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get('/users?name_like=%User 1%')
                .expect(200);
        });

        const likeBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get('/users?name_like=%User 1%')
                .expect(200);
        });

        this.addResult('LIKE Filter', likeCurrent, likeBackup);

        // Test IN filter
        const inCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get('/users?role_in=admin&role_in=moderator')
                .expect(200);
        });

        const inBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get('/users?role_in=admin&role_in=moderator')
                .expect(200);
        });

        this.addResult('IN Filter', inCurrent, inBackup);
    }

    // Benchmark complex queries
    async benchmarkComplexQueries() {
        console.log('📊 Benchmarking Complex Queries...');

        // Setup small dataset for speed
        const users = Array.from(
            { length: BENCHMARK_CONFIG.SMALL_DATASET },
            (_, i) => {
                const baseUser = this.generateUser(i);
                return {
                    ...baseUser,
                    id: `complex-${i}`,
                    email: `complex-${i}@test.com`,
                };
            }
        );

        console.log(
            `    Inserting ${BENCHMARK_CONFIG.SMALL_DATASET} records for complex query tests...`
        );
        for (const user of users) {
            await request(this.currentApp).post('/users').send(user);
            await request(this.backupApp)
                .post('/users')
                .send({
                    ...user,
                    email: `backup-${user.email}`,
                });
        }

        // Test complex query with filtering, sorting, and pagination
        const complexCurrent = await this.measurePerformance(async () => {
            await request(this.currentApp)
                .get(
                    '/users?role=user&age_gte=25&age_lt=50&isActive=true&orderBy=age&sort=desc&page=2&limit=20'
                )
                .expect(200);
        });

        const complexBackup = await this.measurePerformance(async () => {
            await request(this.backupApp)
                .get(
                    '/users?role=user&age_gte=25&age_lt=50&isActive=true&orderBy=age&sort=desc&page=2&limit=20'
                )
                .expect(200);
        });

        this.addResult(
            'Complex Query (Filter+Sort+Pagination)',
            complexCurrent,
            complexBackup
        );
    }

    // Helper to add benchmark results
    private addResult(
        operation: string,
        currentVersion: any,
        backupVersion: any
    ) {
        const performanceRatio = currentVersion.avgTime / backupVersion.avgTime;
        const improvement = ((1 - performanceRatio) * 100).toFixed(1);

        const result: BenchmarkResult = {
            operation,
            currentVersion,
            backupVersion,
            performanceRatio,
            improvement:
                performanceRatio < 1
                    ? `+${improvement}%`
                    : `-${Math.abs(Number(improvement))}%`,
        };

        this.results.push(result);
    }

    // Clear all data from both databases
    private async clearData() {
        // Note: Since we're using in-memory databases, we could recreate them
        // For now, we'll delete all users
        try {
            const currentUsers = await request(this.currentApp).get('/users');
            const backupUsers = await request(this.backupApp).get('/users');

            // Delete all users from current
            if (currentUsers.body && Array.isArray(currentUsers.body)) {
                for (const user of currentUsers.body) {
                    await request(this.currentApp).delete(`/users/${user.id}`);
                }
            }

            // Delete all users from backup
            if (backupUsers.body && Array.isArray(backupUsers.body)) {
                for (const user of backupUsers.body) {
                    await request(this.backupApp).delete(`/users/${user.id}`);
                }
            }
        } catch (error) {
            console.warn('Warning: Could not clear all data, continuing...');
        }
    }

    // Generate comprehensive benchmark report
    generateReport() {
        console.log('\n' + '='.repeat(80));
        console.log('🏆 PERFORMANCE BENCHMARK RESULTS');
        console.log('='.repeat(80));
        console.log(`📊 Current Implementation vs Backup Implementation`);
        console.log(`🔄 Iterations per test: ${BENCHMARK_CONFIG.ITERATIONS}`);
        console.log(`🌡️  Warmup runs: ${BENCHMARK_CONFIG.WARMUP_RUNS}`);
        console.log('='.repeat(80));

        let totalCurrentTime = 0;
        let totalBackupTime = 0;
        let currentWins = 0;
        let backupWins = 0;

        this.results.forEach((result, index) => {
            console.log(`\n${index + 1}. ${result.operation}`);
            console.log('   Current Implementation:');
            console.log(
                `     ⚡ Avg: ${result.currentVersion.avgTime.toFixed(2)}ms`
            );
            console.log(
                `     🏃 Min: ${result.currentVersion.minTime.toFixed(2)}ms`
            );
            console.log(
                `     🐌 Max: ${result.currentVersion.maxTime.toFixed(2)}ms`
            );
            console.log(
                `     💾 Memory: ${(
                    result.currentVersion.memoryUsage / 1024
                ).toFixed(2)}KB`
            );

            console.log('   Backup Implementation:');
            console.log(
                `     ⚡ Avg: ${result.backupVersion.avgTime.toFixed(2)}ms`
            );
            console.log(
                `     🏃 Min: ${result.backupVersion.minTime.toFixed(2)}ms`
            );
            console.log(
                `     🐌 Max: ${result.backupVersion.maxTime.toFixed(2)}ms`
            );
            console.log(
                `     💾 Memory: ${(
                    result.backupVersion.memoryUsage / 1024
                ).toFixed(2)}KB`
            );

            const winner = result.performanceRatio < 1 ? 'Current' : 'Backup';
            const winnerIcon = result.performanceRatio < 1 ? '🏆' : '🥈';

            console.log(
                `   ${winnerIcon} Winner: ${winner} (${result.improvement} faster)`
            );

            if (result.performanceRatio < 1) {
                currentWins++;
            } else {
                backupWins++;
            }

            totalCurrentTime += result.currentVersion.avgTime;
            totalBackupTime += result.backupVersion.avgTime;
        });

        // Overall summary
        console.log('\n' + '='.repeat(80));
        console.log('📈 OVERALL SUMMARY');
        console.log('='.repeat(80));
        console.log(
            `🏆 Current Implementation wins: ${currentWins}/${this.results.length}`
        );
        console.log(
            `🥈 Backup Implementation wins: ${backupWins}/${this.results.length}`
        );

        const overallRatio = totalCurrentTime / totalBackupTime;
        const overallImprovement = ((1 - overallRatio) * 100).toFixed(1);

        console.log(`⚡ Overall Performance Ratio: ${overallRatio.toFixed(3)}`);

        if (overallRatio < 1) {
            console.log(
                `🚀 Current Implementation is ${overallImprovement}% faster overall`
            );
        } else {
            console.log(
                `📉 Current Implementation is ${Math.abs(
                    Number(overallImprovement)
                )}% slower overall`
            );
        }

        console.log(
            `📊 Total execution time (Current): ${totalCurrentTime.toFixed(
                2
            )}ms`
        );
        console.log(
            `📊 Total execution time (Backup): ${totalBackupTime.toFixed(2)}ms`
        );
        console.log('='.repeat(80));

        // Performance insights
        console.log('\n💡 PERFORMANCE INSIGHTS:');

        const fastestOperations = this.results
            .filter((r) => r.performanceRatio < 1)
            .sort((a, b) => a.performanceRatio - b.performanceRatio)
            .slice(0, 3);

        const slowestOperations = this.results
            .filter((r) => r.performanceRatio >= 1)
            .sort((a, b) => b.performanceRatio - a.performanceRatio)
            .slice(0, 3);

        if (fastestOperations.length > 0) {
            console.log('\n🚀 Biggest improvements in current implementation:');
            fastestOperations.forEach((op, i) => {
                console.log(
                    `   ${i + 1}. ${op.operation}: ${op.improvement} faster`
                );
            });
        }

        if (slowestOperations.length > 0) {
            console.log('\n⚠️  Areas where current is slower:');
            slowestOperations.forEach((op, i) => {
                console.log(
                    `   ${i + 1}. ${op.operation}: ${op.improvement} slower`
                );
            });
        }

        console.log('\n='.repeat(80));
    }

    // Run full benchmark suite
    async runBenchmark() {
        await this.setup();

        try {
            await this.benchmarkCRUD();
            await this.clearData();

            await this.benchmarkPagination();

            await this.benchmarkFiltering();
            await this.clearData();

            await this.benchmarkComplexQueries();

            this.generateReport();
        } catch (error) {
            console.error('❌ Benchmark failed:', error);
            throw error;
        }
    }
}

// Main benchmark test
describe('Performance Benchmark: index.ts vs index.backup.ts', () => {
    it(
        'should run comprehensive performance comparison',
        async () => {
            const benchmark = new PerformanceBenchmark();
            await benchmark.runBenchmark();
        },
        BENCHMARK_CONFIG.TIMEOUT
    );
});
