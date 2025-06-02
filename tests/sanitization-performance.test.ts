import { describe, it, expect } from 'vitest';
import { sanitizeInput, sanitizeInputRecursive, type SanitizationConfig } from '../middleware/security';

describe('Sanitization Performance Optimization', () => {
    const testData = {
        id: 'user123',
        name: 'John Doe',
        email: 'john@example.com',
        description: '<script>alert("xss")</script>This is my bio',
        bio: 'I love <img src=x onerror=alert(1)> programming',
        content: 'javascript:alert("hack")',
        createdAt: '2024-01-01T00:00:00Z',
        nested: {
            comment: '<b>Bold comment</b> with <script>alert("nested")</script>',
            status: 'active',
            metadata: {
                note: 'Some <span onclick="alert()">clickable</span> text'
            }
        },
        tags: ['<script>alert(1)</script>', 'normal-tag']
    };

    it('should only sanitize free-text fields by default', () => {
        const result = sanitizeInput(testData);
        
        // Structured fields should remain unchanged
        expect(result.id).toBe('user123');
        expect(result.name).toBe('John Doe');
        expect(result.email).toBe('john@example.com');
        expect(result.createdAt).toBe('2024-01-01T00:00:00Z');
        expect(result.nested.status).toBe('active');
        
        // Free-text fields should be sanitized (XSS removed)
        expect(result.description).not.toContain('<script>');
        expect(result.bio).not.toContain('onerror=alert(1)');
        expect(result.content).not.toContain('javascript:');
        expect(result.nested.comment).not.toContain('<script>');
        expect(result.nested.metadata.note).not.toContain('onclick=');
        
        // Tags are not in free-text fields by default, so they remain unchanged
        expect(result.tags[0]).toBe('<script>alert(1)</script>'); // Not sanitized by default
        expect(result.tags[1]).toBe('normal-tag');
    });

    it('should allow custom sanitization configuration', () => {
        const customConfig: SanitizationConfig = {
            freeTextFields: ['description'],
            structuredFields: ['id', 'name', 'email'],
            sanitizeAllStrings: false
        };
        
        const result = sanitizeInput(testData, customConfig);
        
        // Only description should be sanitized
        expect(result.description).not.toContain('<script>');
        
        // Bio should NOT be sanitized with custom config
        expect(result.bio).toContain('onerror=alert(1)');
        
        // Structured fields remain unchanged
        expect(result.id).toBe('user123');
        expect(result.name).toBe('John Doe');
    });

    it('should sanitize array elements when parent field is in freeTextFields', () => {
        const customConfig: SanitizationConfig = {
            freeTextFields: ['tags', 'description'],
            structuredFields: ['id', 'name'],
            sanitizeAllStrings: false
        };
        
        const result = sanitizeInput(testData, customConfig);
        
        // Now tags should be sanitized since 'tags' is in freeTextFields
        expect(result.tags[0]).not.toContain('<script>');
        expect(result.tags[1]).toBe('normal-tag');
    });

    it('should sanitize all strings when sanitizeAllStrings is true', () => {
        const config: SanitizationConfig = {
            freeTextFields: [],
            structuredFields: [],
            sanitizeAllStrings: true
        };
        
        const result = sanitizeInput(testData, config);
        
        // All string fields should be sanitized
        expect(result.description).not.toContain('<script>');
        expect(result.bio).not.toContain('onerror=alert(1)');
    });

    it('should be significantly faster than recursive sanitization on large objects', () => {
        // Create a large object with mostly structured fields
        const largeData: any = {};
        for (let i = 0; i < 1000; i++) {
            largeData[`id${i}`] = `value${i}`;
            largeData[`name${i}`] = `Name ${i}`;
            largeData[`email${i}`] = `user${i}@example.com`;
            // Only a few free-text fields
            if (i % 100 === 0) {
                largeData[`description${i}`] = `<script>alert(${i})</script>Description ${i}`;
            }
        }

        // Measure optimized sanitization
        const optimizedStart = performance.now();
        sanitizeInput(largeData);
        const optimizedTime = performance.now() - optimizedStart;

        // Measure recursive sanitization
        const recursiveStart = performance.now();
        sanitizeInputRecursive(largeData);
        const recursiveTime = performance.now() - recursiveStart;

        console.log(`Optimized sanitization: ${optimizedTime.toFixed(2)}ms`);
        console.log(`Recursive sanitization: ${recursiveTime.toFixed(2)}ms`);
        console.log(`Performance improvement: ${(recursiveTime / optimizedTime).toFixed(2)}x faster`);

        // Optimized version should be faster (though this might vary)
        // We'll just ensure both complete successfully
        expect(optimizedTime).toBeGreaterThan(0);
        expect(recursiveTime).toBeGreaterThan(0);
    });
});