import express from 'express';
import { createDB } from 'skibbadb';
import { z } from 'zod';
import { describe, it, expect } from 'vitest';
import { createSkibbaExpress } from '../index';

describe('OpenAPI generation', () => {
    it('generates spec for registered collection', () => {
        const app = express();
        const db = createDB({ path: ':memory:' });
        const skibba = createSkibbaExpress(app, db);

        const schema = z.object({
            _id: z.string(),
            name: z.string(),
        });

        const coll = db.collection('people', schema);
        skibba.useCollection(coll, { GET: {}, POST: {}, PUT: {}, DELETE: {} });

        const spec = skibba.getOpenAPISpec();
        expect(spec.paths['/people']).toBeTruthy();
        expect(spec.paths['/people/{id}']).toBeTruthy();
        expect(spec.components.schemas['people']).toBeTruthy();
    });
});
