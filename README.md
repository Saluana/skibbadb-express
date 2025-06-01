# SkibbaDB Express

A powerful Express.js wrapper for SkibbaDB that automatically generates REST APIs with built-in security, validation, pagination, and filtering capabilities.

## Features

-   🚀 **Automatic REST API Generation** - Transform SkibbaDB collections into REST endpoints
-   🔒 **Built-in Security** - XSS protection, SQL injection prevention, input sanitization
-   📄 **Pagination Support** - Page-based and offset-based pagination
-   🔍 **Advanced Filtering** - Multiple filter operators and text search
-   📊 **Sorting** - Flexible sorting with multiple fields
-   🎣 **Hooks System** - Customize behavior with before/after hooks
-   ✅ **Automatic Validation** - Zod schema validation on all operations
-   🛡️ **Error Handling** - Comprehensive error responses with detailed messages

## Quick Start

### Installation

```bash
bun add skibbadb-express
# or
npm install skibbadb-express
```

### Basic Usage

```typescript
import express from 'express';
import { Database } from 'skibbadb';
import { createSkibbaExpress } from 'skibbadb-express';
import { z } from 'zod';

const app = express();
const db = new Database('sqlite:example.db');
const skibba = createSkibbaExpress(app, db);

// Define your schema
const userSchema = z.object({
    id: z.string(),
    name: z.string(),
    email: z.string().email(),
    age: z.number().int().positive(),
    role: z.enum(['user', 'admin']).default('user'),
});

const users = db.collection('users', userSchema);

// Register collection with REST endpoints
skibba.useCollection(users, {
    GET: {},
    POST: {},
    PUT: {},
    DELETE: {},
    basePath: '/api/users',
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
```

This automatically creates these endpoints:

-   `GET /api/users` - List users with pagination and filtering
-   `GET /api/users/:id` - Get user by ID
-   `POST /api/users` - Create new user
-   `PUT /api/users/:id` - Update user
-   `DELETE /api/users/:id` - Delete user

## Pagination and Filtering

### Pagination

```bash
# Page-based pagination
GET /api/users?page=1&limit=10

# Offset-based pagination
GET /api/users?limit=20&offset=40
```

### Filtering

```bash
# Equality filters
GET /api/users?role=admin&isActive=true

# Comparison filters
GET /api/users?age_gt=18&age_lt=65

# Text search
GET /api/users?name_like=%john%

# Array filters
GET /api/users?role_in=admin&role_in=moderator
```

### Sorting

```bash
# Sort ascending (default)
GET /api/users?orderBy=name

# Sort descending
GET /api/users?orderBy=age&sort=desc
```

### Combined Example

```bash
GET /api/users?page=2&limit=15&role=admin&age_gte=25&orderBy=name&sort=asc
```

See [PAGINATION_FILTERING_EXAMPLES.md](./PAGINATION_FILTERING_EXAMPLES.md) for more detailed examples.

## Documentation

-   [Complete Tutorial](./TUTORIAL.md) - Comprehensive guide with examples
-   [Pagination & Filtering Examples](./PAGINATION_FILTERING_EXAMPLES.md) - Detailed API usage examples
-   [Testing Guide](./tests/TESTING.md) - How to test your APIs

## Installation

```bash
bun install
```

## Development

```bash
# Run in development mode
bun run dev

# Run tests
bun test

# Run security tests
bun run test:security
```

This project was created using `bun init` in bun v1.1.38. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
