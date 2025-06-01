# Pagination and Filtering Examples

This document shows how to use the new pagination and filtering features with SkibbaDB Express.

## Basic Pagination

### Using page and limit

```bash
# Get page 1 with 10 items per page
GET /api/users?page=1&limit=10

# Get page 2 with 20 items per page
GET /api/users?page=2&limit=20
```

### Using limit and offset

```bash
# Get 10 items starting from the beginning
GET /api/users?limit=10

# Get 10 items starting from item 20 (skip first 20)
GET /api/users?limit=10&offset=20
```

## Filtering

### Equality filters

```bash
# Get users with specific role
GET /api/users?role=admin

# Get users with specific name
GET /api/users?name=John

# Multiple equality filters (AND)
GET /api/users?role=admin&isActive=true
```

### Comparison filters

```bash
# Get users older than 25
GET /api/users?age_gt=25

# Get users 18 and older
GET /api/users?age_gte=18

# Get users younger than 65
GET /api/users?age_lt=65

# Get users 64 and younger
GET /api/users?age_lte=64

# Combining comparisons
GET /api/users?age_gte=18&age_lt=65
```

### Text search filters

```bash
# Get users with names containing "john" (case-insensitive)
GET /api/users?name_like=%john%

# Get users with emails ending in "gmail.com"
GET /api/users?email_like=%gmail.com
```

### Array filters

```bash
# Get users with any of these roles
GET /api/users?role_in=admin&role_in=moderator

# Or using array syntax (if your client supports it)
GET /api/users?role_in[]=admin&role_in[]=moderator
```

## Sorting

```bash
# Sort by name ascending (default)
GET /api/users?orderBy=name

# Sort by name descending
GET /api/users?orderBy=name&sort=desc

# Sort by age descending
GET /api/users?orderBy=age&sort=desc
```

## Combined Examples

### Paginated filtered results

```bash
# Get page 2 of active admin users, 15 per page, sorted by name
GET /api/users?page=2&limit=15&role=admin&isActive=true&orderBy=name&sort=asc

# Get users aged 25-45, page 1 with 20 items, sorted by age
GET /api/users?page=1&limit=20&age_gte=25&age_lte=45&orderBy=age&sort=desc
```

### Search with pagination

```bash
# Search for users with "smith" in name, get first 10 results
GET /api/users?name_like=%smith%&limit=10

# Search for Gmail users, page 2 with 25 per page
GET /api/users?email_like=%gmail.com&page=2&limit=25
```

## Response Format

### Without pagination (regular array)

```json
[
    {
        "id": "1",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user"
    },
    {
        "id": "2",
        "name": "Jane Smith",
        "email": "jane@example.com",
        "role": "admin"
    }
]
```

### With pagination (when using page parameter)

```json
{
    "data": [
        {
            "id": "1",
            "name": "John Doe",
            "email": "john@example.com",
            "role": "user"
        }
    ],
    "pagination": {
        "page": 2,
        "limit": 10,
        "totalCount": 45,
        "totalPages": 5,
        "hasNextPage": true,
        "hasPreviousPage": true
    }
}
```

## Error Responses

### Invalid pagination parameters

```json
{
    "error": "Invalid pagination parameter",
    "message": "Page must be a positive integer starting from 1"
}
```

### Invalid filter field

```json
{
    "error": "Invalid filter parameter",
    "message": "Invalid filter for field \"nonexistentField\": Field 'nonexistentField' does not exist in schema"
}
```

### Invalid sort field

```json
{
    "error": "Invalid sort parameter",
    "message": "Invalid sort field \"invalidField\": Field 'invalidField' does not exist in schema"
}
```

## Supported Filter Operators

| Operator           | Description                | Example                      |
| ------------------ | -------------------------- | ---------------------------- |
| `field=value`      | Equality                   | `name=John`                  |
| `field_gt=value`   | Greater than               | `age_gt=25`                  |
| `field_gte=value`  | Greater than or equal      | `age_gte=18`                 |
| `field_lt=value`   | Less than                  | `age_lt=65`                  |
| `field_lte=value`  | Less than or equal         | `age_lte=64`                 |
| `field_like=value` | Text contains (SQL LIKE)   | `name_like=%john%`           |
| `field_in=value`   | In array (multiple values) | `role_in=admin&role_in=user` |

## Notes

-   **Pagination limits**: Maximum limit is 1000 items per page
-   **Filtering**: Automatically converts numeric strings to numbers for comparison operators
-   **Field validation**: Invalid field names will return error responses
-   **Nested fields**: Support for JSON field filtering like `metadata.category=sports`
-   **Case sensitivity**: Text searches using `_like` are case-insensitive
-   **URL encoding**: Remember to URL encode special characters in filter values
