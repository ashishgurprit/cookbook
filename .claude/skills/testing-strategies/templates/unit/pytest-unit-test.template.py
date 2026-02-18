"""
PyTest Unit Test Template

Purpose: Test individual functions/classes in isolation
Framework: pytest (Python)

Usage:
    1. Copy this template
    2. Replace {ModuleName}, {function_name}, etc. with actual names
    3. Fill in test cases based on requirements
    4. Run: pytest test_{module_name}.py -v

Installation:
    pip install pytest pytest-cov pytest-mock pytest-asyncio
"""

# ============================================================================
# IMPORTS
# ============================================================================

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from typing import List, Dict, Any

# Import the module/function under test
from src.{module_path} import {FunctionName}, {ClassName}

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def sample_data():
    """Fixture providing sample test data."""
    return {
        'id': 1,
        'name': 'test',
        'active': True
    }


@pytest.fixture
def mock_dependency():
    """Fixture providing mocked dependency."""
    mock = Mock()
    mock.method.return_value = 'mocked_value'
    return mock


@pytest.fixture(scope='module')
def expensive_resource():
    """
    Module-scoped fixture for expensive setup/teardown.
    Runs once per test module.
    """
    # Setup
    resource = create_expensive_resource()
    yield resource
    # Teardown
    resource.cleanup()


@pytest.fixture(scope='function', autouse=True)
def reset_state():
    """Auto-use fixture that runs before each test to reset state."""
    # Setup before each test
    yield
    # Teardown after each test
    clear_global_state()


# ============================================================================
# TEST CLASS (organized tests)
# ============================================================================

class Test{ClassName}:
    """Test suite for {ClassName}."""

    # ────────────────────────────────────────────────────────────────────
    # Happy Path Tests
    # ────────────────────────────────────────────────────────────────────

    def test_basic_functionality(self, sample_data):
        """Test basic functionality with valid input."""
        # Arrange
        instance = {ClassName}()
        expected = {'result': 'success'}

        # Act
        result = instance.method(sample_data)

        # Assert
        assert result == expected
        assert result['result'] == 'success'

    def test_returns_correct_type(self):
        """Test that function returns correct type."""
        result = {function_name}('input')

        assert isinstance(result, dict)
        assert 'key' in result

    @pytest.mark.parametrize('input,expected', [
        ('input1', 'output1'),
        ('input2', 'output2'),
        ('input3', 'output3'),
    ])
    def test_multiple_inputs(self, input, expected):
        """Test function with multiple input/output pairs."""
        result = {function_name}(input)
        assert result == expected

    # ────────────────────────────────────────────────────────────────────
    # Edge Cases
    # ────────────────────────────────────────────────────────────────────

    @pytest.mark.edge_case
    def test_empty_input(self):
        """Test handling of empty input."""
        result = {function_name}('')
        assert result == {'empty': True}

    def test_none_input(self):
        """Test handling of None input."""
        result = {function_name}(None)
        assert result is not None

    def test_very_large_input(self):
        """Test handling of very large input."""
        large_input = 'x' * 10000
        result = {function_name}(large_input)
        assert len(result) > 0

    @pytest.mark.parametrize('edge_case', [
        '',  # empty
        None,  # null
        [],  # empty list
        {},  # empty dict
        0,  # zero
        -1,  # negative
        float('inf'),  # infinity
        '🎉',  # emoji
        '你好',  # unicode
    ])
    def test_edge_cases(self, edge_case):
        """Test various edge cases."""
        # Should not raise exception
        result = {function_name}(edge_case)
        assert result is not None

    # ────────────────────────────────────────────────────────────────────
    # Error Handling
    # ────────────────────────────────────────────────────────────────────

    def test_raises_value_error_for_invalid_input(self):
        """Test that function raises ValueError for invalid input."""
        with pytest.raises(ValueError) as exc_info:
            {function_name}(invalid_input)

        assert 'expected error message' in str(exc_info.value)

    def test_raises_type_error_for_wrong_type(self):
        """Test that function raises TypeError for wrong type."""
        with pytest.raises(TypeError):
            {function_name}(123)  # Expecting string

    @pytest.mark.parametrize('invalid_input,exception_type', [
        ('bad', ValueError),
        (None, TypeError),
        ([], AttributeError),
    ])
    def test_various_exceptions(self, invalid_input, exception_type):
        """Test that function raises appropriate exceptions."""
        with pytest.raises(exception_type):
            {function_name}(invalid_input)

    # ────────────────────────────────────────────────────────────────────
    # Mock/Patch Tests
    # ────────────────────────────────────────────────────────────────────

    def test_calls_dependency_correctly(self, mock_dependency):
        """Test that function calls dependency with correct params."""
        result = {function_name}('input', dependency=mock_dependency)

        mock_dependency.method.assert_called_once_with('expected_param')
        assert result == 'mocked_value'

    @patch('src.{module_path}.external_service')
    def test_with_patched_external_service(self, mock_service):
        """Test with mocked external service."""
        mock_service.fetch.return_value = {'data': 'mocked'}

        result = {function_name}('input')

        assert result['data'] == 'mocked'
        mock_service.fetch.assert_called()

    @patch.object({ClassName}, 'internal_method')
    def test_with_mocked_internal_method(self, mock_internal):
        """Test with mocked internal method."""
        mock_internal.return_value = 'internal_result'
        instance = {ClassName}()

        result = instance.public_method()

        assert result == 'internal_result'
        mock_internal.assert_called_once()

    def test_spy_on_method_calls(self, mocker):
        """Test using pytest-mock to spy on calls."""
        spy = mocker.spy({ClassName}, 'method_to_spy')
        instance = {ClassName}()

        instance.method_to_spy('arg1', 'arg2')

        spy.assert_called_once_with(instance, 'arg1', 'arg2')

    # ────────────────────────────────────────────────────────────────────
    # Async Tests
    # ────────────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_async_function(self):
        """Test async function."""
        result = await {async_function_name}('input')
        assert result == 'expected'

    @pytest.mark.asyncio
    async def test_async_exception(self):
        """Test async function raises exception."""
        with pytest.raises(ValueError):
            await {async_function_name}('invalid')

    @pytest.mark.asyncio
    @pytest.mark.timeout(5)
    async def test_async_with_timeout(self):
        """Test async function with timeout."""
        result = await {async_function_name}('slow')
        assert result is not None

    # ────────────────────────────────────────────────────────────────────
    # Property-Based Testing (requires hypothesis)
    # ────────────────────────────────────────────────────────────────────

    @pytest.mark.hypothesis
    def test_with_generated_data(self):
        """Test with generated data using hypothesis."""
        from hypothesis import given
        from hypothesis import strategies as st

        @given(st.text())
        def check_property(text):
            result = {function_name}(text)
            assert isinstance(result, str)
            assert len(result) >= 0

        check_property()

    # ────────────────────────────────────────────────────────────────────
    # Performance Tests
    # ────────────────────────────────────────────────────────────────────

    @pytest.mark.performance
    def test_performance_within_limits(self, benchmark):
        """Test performance using pytest-benchmark."""
        # benchmark.pedantic runs function multiple times
        result = benchmark({function_name}, 'input')
        assert result is not None

    def test_completes_quickly(self):
        """Test that function completes within time limit."""
        import time
        start = time.time()

        {function_name}('input')

        duration = time.time() - start
        assert duration < 0.1  # 100ms

    # ────────────────────────────────────────────────────────────────────
    # Integration-Like Tests (still unit tests, but test interactions)
    # ────────────────────────────────────────────────────────────────────

    def test_full_workflow(self, sample_data):
        """Test complete workflow with multiple steps."""
        # Step 1: Create instance
        instance = {ClassName}()

        # Step 2: Configure
        instance.configure(sample_data)

        # Step 3: Execute
        result = instance.execute()

        # Step 4: Verify
        assert result['status'] == 'success'
        assert instance.state == 'completed'


# ============================================================================
# STANDALONE TEST FUNCTIONS
# ============================================================================

def test_standalone_function():
    """Test standalone function (not in a class)."""
    result = {function_name}('test')
    assert result is not None


@pytest.mark.slow
def test_slow_operation():
    """Mark tests that are slow."""
    # This test can be skipped with: pytest -m "not slow"
    import time
    time.sleep(2)
    assert True


@pytest.mark.skip(reason="Not implemented yet")
def test_future_feature():
    """Skip tests that aren't ready."""
    pass


@pytest.mark.skipif(sys.platform == 'win32', reason="Unix only")
def test_unix_specific():
    """Conditionally skip tests based on platform."""
    assert os.name == 'posix'


@pytest.mark.xfail(reason="Known bug - ticket #123")
def test_known_failure():
    """Mark expected failures."""
    assert {buggy_function}() == 'fixed'  # We know this fails


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_test_data(overrides: Dict[str, Any] = None) -> Dict[str, Any]:
    """Helper to create test data with optional overrides."""
    base_data = {
        'id': 1,
        'name': 'test',
        'active': True
    }
    if overrides:
        base_data.update(overrides)
    return base_data


def assert_valid_response(response: Dict[str, Any]) -> None:
    """Helper to validate response structure."""
    assert 'status' in response
    assert 'data' in response
    assert response['status'] in ['success', 'error']


# ============================================================================
# CONFTEST.PY EXAMPLES (put these in conftest.py at package root)
# ============================================================================

"""
# conftest.py - shared fixtures for all tests

import pytest

@pytest.fixture(scope='session')
def database():
    '''Session-scoped database fixture.'''
    db = setup_test_database()
    yield db
    teardown_test_database(db)

@pytest.fixture
def api_client():
    '''Test API client.'''
    client = TestClient(app)
    return client

def pytest_configure(config):
    '''Configure pytest with custom markers.'''
    config.addinivalue_line('markers', 'slow: marks tests as slow')
    config.addinivalue_line('markers', 'integration: integration tests')
    config.addinivalue_line('markers', 'unit: unit tests')
    config.addinivalue_line('markers', 'performance: performance tests')
"""

# ============================================================================
# COVERAGE NOTES
# ============================================================================

"""
Coverage Targets:
- Line coverage: 80%+
- Branch coverage: 75%+
- Function coverage: 100%

To run tests with coverage:
    pytest --cov=src --cov-report=html --cov-report=term

To run specific test types:
    pytest -m unit                    # Only unit tests
    pytest -m "not slow"              # Skip slow tests
    pytest -k "test_basic"            # Tests matching pattern
    pytest --lf                       # Last failed tests
    pytest -x                         # Stop on first failure
    pytest -v                         # Verbose output
    pytest --pdb                      # Drop into debugger on failure

Configuration (pytest.ini or pyproject.toml):
    [tool.pytest.ini_options]
    testpaths = ["tests"]
    python_files = ["test_*.py"]
    python_classes = ["Test*"]
    python_functions = ["test_*"]
    addopts = "-v --strict-markers"
    markers = [
        "slow: marks tests as slow",
        "integration: integration tests",
        "unit: unit tests",
    ]
"""
