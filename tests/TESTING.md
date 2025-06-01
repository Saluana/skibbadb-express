# Comprehensive API Testing Guide

This project includes an extensive test suite that uses Bun shell and curl commands to thoroughly test all API endpoints with comprehensive edge cases and security testing.

## Running the Tests

1. **Start the server:**

    ```bash
    bun run start
    # or
    bun run dev  # for development with auto-reload
    ```

2. **In another terminal, run the comprehensive test suite:**
    ```bash
    bun run test
    ```

## Comprehensive Test Coverage

The enhanced test file (`test.ts`) provides extensive coverage across 8 major testing sections:

### 🔍 Section 1: Basic Functionality Tests

-   Health check endpoint validation
-   API documentation endpoint testing
-   Server availability verification

### 🔒 Section 2: Authentication & Authorization Tests

-   **Invalid Authorization Headers**: Empty headers, malformed tokens, wrong auth types
-   **Token Validation**: Invalid formats, missing parts, wrong prefixes
-   **Permission Testing**: User vs admin access controls
-   **Auth Edge Cases**: Extra characters, encoding issues, null values

### 📊 Section 3: Data Validation & Edge Cases

-   **Input Validation**: Invalid emails, missing required fields, null values
-   **Security Testing**: XSS injection attempts, SQL injection attempts
-   **Data Limits**: Extremely long strings, empty objects, wrong data types
-   **Schema Validation**: Extra fields, type mismatches, malformed data

### 🌐 Section 4: HTTP Methods & Content Types

-   **Unsupported Methods**: PATCH, HEAD, OPTIONS testing
-   **Path Security**: Path traversal attempts, URL encoding attacks
-   **Content-Type Validation**: XML, plain text, missing headers, charset variations
-   **Protocol Edge Cases**: Invalid content types, malformed headers

### 🔄 Section 5: CRUD Operations & Edge Cases

-   **Complete CRUD Flow**: Create, read, update, delete with validation
-   **Update Edge Cases**: Partial updates, empty values, invalid fields
-   **Resource Management**: Non-existent resources, null IDs, path traversal in IDs
-   **Data Integrity**: Role escalation attempts, field validation

### ⚡ Section 6: Performance & Load Edge Cases

-   **Large Payload Testing**: Handling of extremely large JSON payloads
-   **Concurrent Requests**: Simulated concurrent user creation
-   **Resource Limits**: Testing server behavior under load
-   **Memory Management**: Large string handling, payload size limits

### 🌍 Section 7: Network & Protocol Edge Cases

-   **Connection Management**: Timeout testing, connection close headers
-   **Content Negotiation**: XML accept headers, custom user agents
-   **Network Resilience**: Connection timeout handling, protocol variations

### 📈 Section 8: Test Results & Analytics

-   **Comprehensive Reporting**: Pass/fail statistics, success rates
-   **Error Analysis**: Categorized failure reporting
-   **Performance Metrics**: Test execution time and coverage analysis

## Edge Cases Specifically Tested

### 🛡️ Security Edge Cases

-   XSS injection attempts in user data
-   SQL injection attempts in all fields
-   Path traversal attempts in URLs and IDs
-   Authentication bypass attempts
-   Role escalation testing
-   Token manipulation and forgery

### 📊 Data Validation Edge Cases

-   Invalid email formats
-   Missing required fields
-   Null and undefined values
-   Empty strings and objects
-   Extremely long strings (10k+ characters)
-   Wrong data types (arrays, numbers, strings instead of objects)
-   Extra unexpected fields in requests

### 🌐 Protocol Edge Cases

-   Unsupported HTTP methods (PATCH, HEAD, OPTIONS)
-   Invalid Content-Type headers
-   Missing or malformed Authorization headers
-   URL encoding attacks
-   Connection timeout scenarios
-   Custom User-Agent testing

### ⚡ Performance Edge Cases

-   Large payload handling (50k+ character strings)
-   Concurrent request processing (5 simultaneous requests)
-   Resource exhaustion testing
-   Memory limit validation

## Test Authentication Tokens

The tests use these sample tokens for comprehensive auth testing:

-   **Admin Token:** `user:admin123:admin@example.com:true`
-   **User Token:** `user:user123:user@example.com:false`
-   **Invalid Tokens:** Various malformed and invalid token formats
-   **Edge Case Tokens:** Empty, null, wrong prefix, missing parts

## Expected Test Output

When you run `bun run test`, you'll see organized output like:

```
🧪 Running Comprehensive API Tests with Edge Cases
==================================================

🔍 SECTION 1: Basic Functionality Tests
========================================
✅ Health Check: Server is healthy
✅ Root Documentation: API documentation available

🔒 SECTION 2: Authentication & Authorization Tests
==================================================
✅ Empty Authorization Header: Request processed
✅ Bearer without token: Request processed
✅ Invalid token format: Request processed
... (30+ auth tests)

📊 SECTION 3: Data Validation & Edge Cases
===========================================
✅ Invalid Email Format: Correctly rejected invalid data
✅ XSS Injection Attempt: Correctly rejected invalid data
✅ SQL Injection Attempt: Correctly rejected invalid data
... (15+ validation tests)

... (Additional sections)

📈 SECTION 8: Test Results Summary
==================================
Total Tests: 75+
Passed: XX ✅
Failed: XX ❌
Success Rate: XX.X%
```

## Understanding Test Results

-   **✅ Passed Tests**: Expected behavior occurred
-   **❌ Failed Tests**: May indicate areas needing attention or expected security measures
-   **Edge Case Failures**: Often indicate proper security/validation is working
-   **100% Pass Rate**: Not always expected - some tests verify that invalid requests are properly rejected

## Test Authentication Tokens

The tests use these sample tokens:

-   **Admin Token:** `user:admin123:admin@example.com:true`
-   **User Token:** `user:user123:user@example.com:false`

These follow the format: `user:{id}:{email}:{isAdmin}`

## Manual Testing

You can also test the API manually using these curl commands:

```bash
# Health check
curl http://localhost:3000/health

# Get users (public view)
curl http://localhost:3000/api/users

# Get users (admin view)
curl -H "Authorization: Bearer user:admin123:admin@example.com:true" \
     http://localhost:3000/api/users

# Create a user (admin only)
curl -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer user:admin123:admin@example.com:true" \
     -d '{"id":"user123","name":"John Doe","email":"john@example.com","role":"user"}' \
     http://localhost:3000/api/users

# Update a user (admin only)
curl -X PUT \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer user:admin123:admin@example.com:true" \
     -d '{"name":"John Smith"}' \
     http://localhost:3000/api/users/user123

# Delete a user (admin only)
curl -X DELETE \
     -H "Authorization: Bearer user:admin123:admin@example.com:true" \
     http://localhost:3000/api/users/user123
```

## Expected Output

When you run `bun run test`, you should see output like:

```
🧪 Running API Tests with Bun Shell
=====================================

📋 Test 1: Health Check
✅ Health check: {"status":"ok","timestamp":"...","database":"connected"}

📋 Test 2: Root Documentation
✅ Root endpoint: SkibbaDB Express Integration Example
   Available endpoints: 6

... (additional test results)

🎉 API Tests Completed!
```

The tests will show ✅ for successful tests and ❌ for any failures, along with detailed information about what was tested.
