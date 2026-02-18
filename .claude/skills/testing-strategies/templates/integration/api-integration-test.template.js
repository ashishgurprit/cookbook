/**
 * API Integration Test Template
 *
 * Purpose: Test API endpoints with real HTTP requests
 * Framework: Jest + Supertest (or similar)
 *
 * Usage:
 *   1. Copy this template
 *   2. Replace {apiName}, {endpoint}, etc. with actual values
 *   3. Configure test database/environment
 *   4. Run: npm test --testPathPattern=integration
 */

// ============================================================================
// IMPORTS
// ============================================================================

import request from 'supertest';
import { app } from '../src/app'; // Your Express/Fastify/etc app
import { setupTestDatabase, teardownTestDatabase, clearDatabase } from './helpers/database';
import { createAuthToken } from './helpers/auth';

// ============================================================================
// TEST SUITE SETUP
// ============================================================================

describe('API Integration Tests - {ApiName}', () => {
  let authToken;
  let testUserId;

  // ──────────────────────────────────────────────────────────────────────
  // Setup & Teardown
  // ──────────────────────────────────────────────────────────────────────

  beforeAll(async () => {
    // Setup test database
    await setupTestDatabase();

    // Create test user and get auth token
    const testUser = await createTestUser({
      email: 'test@example.com',
      password: 'Password123!',
      role: 'user'
    });
    testUserId = testUser.id;
    authToken = createAuthToken(testUser);
  });

  afterAll(async () => {
    // Cleanup database and close connections
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    // Clear data between tests to ensure isolation
    await clearDatabase();
  });

  // ──────────────────────────────────────────────────────────────────────
  // GET Endpoint Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('GET /api/{resource}', () => {
    test('should return 200 and list of resources', async () => {
      // Arrange: Seed test data
      await seedTestData([
        { name: 'Resource 1', active: true },
        { name: 'Resource 2', active: true },
        { name: 'Resource 3', active: false }
      ]);

      // Act
      const response = await request(app)
        .get('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(200);

      // Assert
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toBeInstanceOf(Array);
      expect(response.body.data).toHaveLength(3);
      expect(response.body.data[0]).toMatchObject({
        name: expect.any(String),
        active: expect.any(Boolean)
      });
    });

    test('should return 401 without authentication', async () => {
      const response = await request(app)
        .get('/api/{resource}')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toContain('Unauthorized');
    });

    test('should support pagination', async () => {
      // Arrange: Create 25 items
      await seedTestData(Array(25).fill(null).map((_, i) => ({
        name: `Resource ${i + 1}`
      })));

      // Act: Request page 2 with 10 items per page
      const response = await request(app)
        .get('/api/{resource}?page=2&limit=10')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Assert
      expect(response.body.data).toHaveLength(10);
      expect(response.body.pagination).toMatchObject({
        page: 2,
        limit: 10,
        total: 25,
        pages: 3
      });
    });

    test('should support filtering', async () => {
      // Arrange
      await seedTestData([
        { name: 'Active Resource', active: true },
        { name: 'Inactive Resource', active: false }
      ]);

      // Act
      const response = await request(app)
        .get('/api/{resource}?active=true')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Assert
      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].active).toBe(true);
    });

    test('should support sorting', async () => {
      // Arrange
      await seedTestData([
        { name: 'Zebra', order: 3 },
        { name: 'Apple', order: 1 },
        { name: 'Banana', order: 2 }
      ]);

      // Act
      const response = await request(app)
        .get('/api/{resource}?sort=name&order=asc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Assert
      const names = response.body.data.map(item => item.name);
      expect(names).toEqual(['Apple', 'Banana', 'Zebra']);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // GET by ID Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('GET /api/{resource}/:id', () => {
    test('should return 200 and single resource', async () => {
      // Arrange
      const created = await createTestResource({ name: 'Test Resource' });

      // Act
      const response = await request(app)
        .get(`/api/{resource}/${created.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Assert
      expect(response.body.data).toMatchObject({
        id: created.id,
        name: 'Test Resource'
      });
    });

    test('should return 404 for non-existent resource', async () => {
      const response = await request(app)
        .get('/api/{resource}/999999')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.error).toContain('not found');
    });

    test('should return 400 for invalid ID format', async () => {
      const response = await request(app)
        .get('/api/{resource}/invalid-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);

      expect(response.body.error).toContain('Invalid ID');
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // POST Endpoint Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('POST /api/{resource}', () => {
    test('should create resource and return 201', async () => {
      // Arrange
      const newResource = {
        name: 'New Resource',
        description: 'Test description',
        active: true
      };

      // Act
      const response = await request(app)
        .post('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .send(newResource)
        .expect('Content-Type', /json/)
        .expect(201);

      // Assert
      expect(response.body.data).toMatchObject({
        id: expect.any(Number),
        name: 'New Resource',
        description: 'Test description',
        active: true,
        createdAt: expect.any(String)
      });

      // Verify in database
      const dbResource = await findResourceById(response.body.data.id);
      expect(dbResource).toBeDefined();
      expect(dbResource.name).toBe('New Resource');
    });

    test('should return 400 for invalid data', async () => {
      const invalidData = {
        // Missing required field 'name'
        description: 'No name provided'
      };

      const response = await request(app)
        .post('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.errors).toContainEqual(
        expect.objectContaining({
          field: 'name',
          message: expect.stringContaining('required')
        })
      );
    });

    test('should return 409 for duplicate resource', async () => {
      // Arrange: Create initial resource
      await createTestResource({ name: 'Unique Name' });

      // Act: Try to create duplicate
      const response = await request(app)
        .post('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Unique Name' })
        .expect(409);

      expect(response.body.error).toContain('already exists');
    });

    test('should validate data types', async () => {
      const invalidTypes = {
        name: 123, // Should be string
        active: 'yes', // Should be boolean
        count: 'invalid' // Should be number
      };

      const response = await request(app)
        .post('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidTypes)
        .expect(400);

      expect(response.body.errors.length).toBeGreaterThan(0);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // PUT/PATCH Endpoint Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('PUT /api/{resource}/:id', () => {
    test('should update resource and return 200', async () => {
      // Arrange
      const existing = await createTestResource({ name: 'Original Name' });

      // Act
      const response = await request(app)
        .put(`/api/{resource}/${existing.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Updated Name' })
        .expect(200);

      // Assert
      expect(response.body.data.name).toBe('Updated Name');

      // Verify in database
      const updated = await findResourceById(existing.id);
      expect(updated.name).toBe('Updated Name');
    });

    test('should return 404 for non-existent resource', async () => {
      const response = await request(app)
        .put('/api/{resource}/999999')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Updated' })
        .expect(404);
    });

    test('should handle partial updates (PATCH)', async () => {
      // Arrange
      const existing = await createTestResource({
        name: 'Original',
        description: 'Original description',
        active: true
      });

      // Act: Only update description
      const response = await request(app)
        .patch(`/api/{resource}/${existing.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ description: 'New description' })
        .expect(200);

      // Assert: Other fields unchanged
      expect(response.body.data).toMatchObject({
        name: 'Original',
        description: 'New description',
        active: true
      });
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // DELETE Endpoint Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('DELETE /api/{resource}/:id', () => {
    test('should delete resource and return 204', async () => {
      // Arrange
      const existing = await createTestResource({ name: 'To Delete' });

      // Act
      await request(app)
        .delete(`/api/{resource}/${existing.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(204);

      // Assert: Verify deleted from database
      const deleted = await findResourceById(existing.id);
      expect(deleted).toBeNull();
    });

    test('should return 404 for non-existent resource', async () => {
      await request(app)
        .delete('/api/{resource}/999999')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });

    test('should handle cascading deletes', async () => {
      // Arrange: Create parent with children
      const parent = await createTestResource({ name: 'Parent' });
      const child = await createRelatedResource(parent.id, { name: 'Child' });

      // Act: Delete parent
      await request(app)
        .delete(`/api/{resource}/${parent.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(204);

      // Assert: Child should also be deleted (or orphaned, depending on schema)
      const orphanedChild = await findRelatedResource(child.id);
      expect(orphanedChild).toBeNull(); // or .parentId.toBeNull()
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Authorization Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('Authorization', () => {
    test('should allow admin to access all resources', async () => {
      const adminToken = createAuthToken({ role: 'admin' });

      const response = await request(app)
        .get('/api/{resource}')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.data).toBeDefined();
    });

    test('should prevent user from accessing other users\' resources', async () => {
      // Arrange: Create resource owned by different user
      const otherUserResource = await createTestResource({
        name: 'Other User Resource',
        userId: 999
      });

      // Act: Try to access with current user token
      const response = await request(app)
        .get(`/api/{resource}/${otherUserResource.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(403);

      expect(response.body.error).toContain('Forbidden');
    });

    test('should allow user to access own resources', async () => {
      // Arrange
      const ownResource = await createTestResource({
        name: 'Own Resource',
        userId: testUserId
      });

      // Act
      const response = await request(app)
        .get(`/api/{resource}/${ownResource.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.id).toBe(ownResource.id);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Error Handling Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('Error Handling', () => {
    test('should return 500 for server errors', async () => {
      // Arrange: Force a server error (e.g., disconnect database)
      await simulateServerError();

      // Act
      const response = await request(app)
        .get('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(500);

      // Assert
      expect(response.body.error).toBeDefined();
      // Should NOT expose internal error details in production
      expect(response.body.error).not.toContain('stack');
    });

    test('should handle malformed JSON', async () => {
      const response = await request(app)
        .post('/api/{resource}')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Content-Type', 'application/json')
        .send('{"invalid json"}')
        .expect(400);

      expect(response.body.error).toContain('Invalid JSON');
    });

    test('should handle SQL injection attempts', async () => {
      const sqlInjection = "'; DROP TABLE users; --";

      const response = await request(app)
        .get(`/api/{resource}?name=${sqlInjection}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200); // Should not crash

      // Verify database is still intact
      const usersExist = await checkTableExists('users');
      expect(usersExist).toBe(true);
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Rate Limiting Tests
  // ──────────────────────────────────────────────────────────────────────

  describe('Rate Limiting', () => {
    test('should enforce rate limits', async () => {
      const requests = [];

      // Make 101 requests (assuming limit is 100/minute)
      for (let i = 0; i < 101; i++) {
        requests.push(
          request(app)
            .get('/api/{resource}')
            .set('Authorization', `Bearer ${authToken}`)
        );
      }

      const responses = await Promise.all(requests);
      const tooManyRequests = responses.filter(r => r.status === 429);

      expect(tooManyRequests.length).toBeGreaterThan(0);
      expect(tooManyRequests[0].body.error).toContain('Too many requests');
    });
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function seedTestData(items) {
  // Implement database seeding
}

async function createTestUser(userData) {
  // Implement user creation
}

async function createTestResource(data) {
  // Implement resource creation
}

async function findResourceById(id) {
  // Implement database query
}

async function simulateServerError() {
  // Implement error simulation
}

async function checkTableExists(tableName) {
  // Implement table existence check
}

// ============================================================================
// COVERAGE NOTES
// ============================================================================

/*
Integration Test Best Practices:
1. Use separate test database
2. Clean data between tests
3. Test full request/response cycle
4. Verify database state after operations
5. Test authentication and authorization
6. Test error handling and edge cases
7. Test rate limiting and security
8. Use realistic test data
9. Test pagination, filtering, sorting
10. Verify cascading operations

Run integration tests:
  npm test -- --testPathPattern=integration --runInBand
  npm test -- --testPathPattern=integration --verbose
  npm test -- --testPathPattern=integration --coverage
*/
