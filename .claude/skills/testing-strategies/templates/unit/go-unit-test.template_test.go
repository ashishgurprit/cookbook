package {packagename}_test

/*
Go Unit Test Template

Purpose: Test individual functions/packages in isolation
Framework: testing (Go standard library) + testify

Usage:
    1. Copy this template
    2. Replace {packagename}, {FunctionName}, etc. with actual names
    3. Fill in test cases based on requirements
    4. Run: go test -v ./...

Installation:
    go get github.com/stretchr/testify
*/

// ============================================================================
// IMPORTS
// ============================================================================

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"{module}/{packagename}"
)

// ============================================================================
// TEST SUITE SETUP (using testify/suite)
// ============================================================================

type {TypeName}TestSuite struct {
	suite.Suite
	instance    *{packagename}.{TypeName}
	mockDep     *MockDependency
	testData    map[string]interface{}
}

// SetupSuite runs once before all tests in the suite
func (s *{TypeName}TestSuite) SetupSuite() {
	// Expensive setup (database, external services)
}

// TearDownSuite runs once after all tests in the suite
func (s *{TypeName}TestSuite) TearDownSuite() {
	// Cleanup resources
}

// SetupTest runs before each test
func (s *{TypeName}TestSuite) SetupTest() {
	s.mockDep = new(MockDependency)
	s.instance = {packagename}.New{TypeName}(s.mockDep)
	s.testData = map[string]interface{}{
		"id":   1,
		"name": "test",
	}
}

// TearDownTest runs after each test
func (s *{TypeName}TestSuite) TearDownTest() {
	s.mockDep = nil
	s.instance = nil
}

// Run the test suite
func Test{TypeName}Suite(t *testing.T) {
	suite.Run(t, new({TypeName}TestSuite))
}

// ============================================================================
// HAPPY PATH TESTS
// ============================================================================

func (s *{TypeName}TestSuite) TestBasicFunctionality() {
	// Arrange
	input := "test input"
	expectedOutput := "expected output"

	// Act
	result, err := s.instance.Method(input)

	// Assert
	require.NoError(s.T(), err, "Should not return error")
	assert.Equal(s.T(), expectedOutput, result)
}

func (s *{TypeName}TestSuite) TestReturnsCorrectType() {
	// Act
	result := s.instance.GetData()

	// Assert
	assert.NotNil(s.T(), result)
	assert.IsType(s.T(), &{packagename}.Data{}, result)
}

// ============================================================================
// TABLE-DRIVEN TESTS
// ============================================================================

func TestFunctionName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Valid input returns success",
			input:    "valid",
			expected: "output",
			wantErr:  false,
		},
		{
			name:     "Empty input returns error",
			input:    "",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Special characters handled",
			input:    "!@#$%",
			expected: "sanitized",
			wantErr:  false,
		},
		{
			name:     "Unicode characters supported",
			input:    "你好",
			expected: "你好",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result, err := {FunctionName}(tt.input)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// ============================================================================
// EDGE CASES
// ============================================================================

func TestEdgeCases(t *testing.T) {
	t.Run("Empty string", func(t *testing.T) {
		result := {FunctionName}("")
		assert.NotNil(t, result)
	})

	t.Run("Nil pointer", func(t *testing.T) {
		result := {FunctionName}(nil)
		assert.NotNil(t, result)
	})

	t.Run("Very large input", func(t *testing.T) {
		largeInput := make([]byte, 1000000) // 1MB
		result := {FunctionName}(largeInput)
		assert.NotNil(t, result)
	})

	t.Run("Concurrent access", func(t *testing.T) {
		instance := {packagename}.New{TypeName}()
		done := make(chan bool)

		// Launch 100 goroutines
		for i := 0; i < 100; i++ {
			go func() {
				instance.Method("concurrent")
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 100; i++ {
			<-done
		}
	})
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

func (s *{TypeName}TestSuite) TestReturnsErrorForInvalidInput() {
	// Act
	_, err := s.instance.Method("invalid")

	// Assert
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "expected error message")
}

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantErr   error
		checkFunc func(error) bool
	}{
		{
			name:      "NotFound error",
			input:     "missing",
			wantErr:   {packagename}.ErrNotFound,
			checkFunc: func(err error) bool { return errors.Is(err, {packagename}.ErrNotFound) },
		},
		{
			name:      "Validation error",
			input:     "invalid",
			wantErr:   {packagename}.ErrValidation,
			checkFunc: func(err error) bool { return errors.Is(err, {packagename}.ErrValidation) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := {FunctionName}(tt.input)

			require.Error(t, err)
			assert.True(t, tt.checkFunc(err))
		})
	}
}

// ============================================================================
// MOCK TESTS
// ============================================================================

// MockDependency is a mock implementation
type MockDependency struct {
	mock.Mock
}

func (m *MockDependency) FetchData(id int) (string, error) {
	args := m.Called(id)
	return args.String(0), args.Error(1)
}

func (s *{TypeName}TestSuite) TestCallsDependencyCorrectly() {
	// Arrange
	s.mockDep.On("FetchData", 123).Return("mocked data", nil)

	// Act
	result, err := s.instance.ProcessData(123)

	// Assert
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "mocked data", result)
	s.mockDep.AssertCalled(s.T(), "FetchData", 123)
	s.mockDep.AssertNumberOfCalls(s.T(), "FetchData", 1)
}

func (s *{TypeName}TestSuite) TestHandlesDependencyFailure() {
	// Arrange
	s.mockDep.On("FetchData", mock.Anything).Return("", errors.New("dependency failed"))

	// Act
	_, err := s.instance.ProcessData(123)

	// Assert
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "dependency failed")
}

// ============================================================================
// CONTEXT AND TIMEOUT TESTS
// ============================================================================

func TestWithContext(t *testing.T) {
	t.Run("Respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := {FunctionName}(ctx, "input")

		assert.Equal(t, context.Canceled, err)
	})

	t.Run("Completes before timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := {FunctionName}(ctx, "input")

		assert.NoError(t, err)
	})

	t.Run("Returns timeout error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := {SlowFunctionName}(ctx, "input")

		assert.Equal(t, context.DeadlineExceeded, err)
	})
}

// ============================================================================
// BENCHMARK TESTS
// ============================================================================

func BenchmarkFunctionName(b *testing.B) {
	input := "test input"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		{FunctionName}(input)
	}
}

func BenchmarkFunctionNameParallel(b *testing.B) {
	input := "test input"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			{FunctionName}(input)
		}
	})
}

func BenchmarkWithSetup(b *testing.B) {
	// Setup (not timed)
	instance := {packagename}.New{TypeName}()

	b.ResetTimer() // Reset timer after setup
	for i := 0; i < b.N; i++ {
		instance.Method("input")
	}
}

// Run specific benchmarks:
//   go test -bench=. -benchmem
//   go test -bench=BenchmarkFunctionName -benchtime=5s
//   go test -bench=. -cpuprofile=cpu.prof

// ============================================================================
// EXAMPLE TESTS (shown in godoc)
// ============================================================================

func Example{FunctionName}() {
	result := {FunctionName}("example input")
	fmt.Println(result)
	// Output: example output
}

func Example{FunctionName}_error() {
	_, err := {FunctionName}("invalid")
	if err != nil {
		fmt.Println("Error:", err)
	}
	// Output: Error: invalid input
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func createTestData() *{packagename}.Data {
	return &{packagename}.Data{
		ID:   1,
		Name: "test",
	}
}

func assertValidResult(t *testing.T, result *{packagename}.Result) {
	t.Helper() // Mark as helper for better error messages

	assert.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	assert.True(t, result.Valid)
}

// ============================================================================
// GOLDEN FILE TESTING (for complex outputs)
// ============================================================================

func TestGoldenFile(t *testing.T) {
	result := {FunctionName}("input")

	goldenFile := "testdata/golden/{functionname}.golden"

	if *update {
		// Update golden file: go test -update
		os.WriteFile(goldenFile, []byte(result), 0644)
	}

	expected, _ := os.ReadFile(goldenFile)
	assert.Equal(t, string(expected), result)
}

var update = flag.Bool("update", false, "update golden files")

// ============================================================================
// FUZZING (Go 1.18+)
// ============================================================================

func FuzzFunctionName(f *testing.F) {
	// Seed corpus
	f.Add("test")
	f.Add("example")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		// This should never panic
		result := {FunctionName}(input)

		// Properties that should always hold
		assert.NotNil(t, result)
		assert.True(t, len(result) >= 0)
	})
}

// Run fuzzing:
//   go test -fuzz=FuzzFunctionName -fuzztime=30s

// ============================================================================
// TEST MAIN (for global setup/teardown)
// ============================================================================

func TestMain(m *testing.M) {
	// Global setup
	setup()

	// Run tests
	code := m.Run()

	// Global teardown
	teardown()

	os.Exit(code)
}

func setup() {
	// Setup test database, external services, etc.
}

func teardown() {
	// Cleanup
}

// ============================================================================
// COVERAGE NOTES
// ============================================================================

/*
Coverage Targets:
- Line coverage: 80%+
- Branch coverage: 75%+
- Function coverage: 100%

To run tests with coverage:
	go test -v -cover ./...
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

To run specific tests:
	go test -v -run TestFunctionName
	go test -v -run "TestSuite/TestMethod"
	go test -short                  # Skip slow tests
	go test -race                   # Race detector
	go test -timeout 30s            # Set timeout

Common flags:
	-v          verbose output
	-cover      show coverage
	-race       enable race detector
	-short      skip long-running tests
	-parallel N run N tests in parallel
	-count N    run tests N times
	-failfast   stop on first failure

Integration with CI:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
*/
