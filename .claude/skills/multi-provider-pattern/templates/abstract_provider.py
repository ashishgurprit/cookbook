"""
Abstract Base Provider Template

Copy this template to create new providers for your multi-provider service.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import time


class ProviderStatus(Enum):
    """Provider health status"""
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass
class ProviderResult:
    """
    Standardized result format from any provider.

    All providers must return this format for consistency.
    """
    success: bool
    data: Any
    provider_name: str
    cost: float  # Cost in USD
    latency_ms: float
    metadata: Dict[str, Any]
    error: Optional[str] = None
    confidence: Optional[float] = None  # 0.0 to 1.0 for quality scoring


class BaseProvider(ABC):
    """
    Abstract base class for all service providers.

    Inherit from this class and implement all abstract methods.

    Example:
        class MyCustomProvider(BaseProvider):
            def __init__(self, config: Dict[str, Any]):
                super().__init__(config)
                self.api_key = config.get('api_key')
                self.api_client = MyAPIClient(self.api_key)

            def process(self, input_data: Any, **kwargs) -> ProviderResult:
                # Implementation here
                pass
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize provider with configuration.

        Args:
            config: Dictionary containing provider-specific configuration
                   Common keys: api_key, priority, enabled, quality_score
        """
        self.config = config
        self.name = self.__class__.__name__
        self._status = ProviderStatus.AVAILABLE
        self._metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_cost': 0.0,
            'total_latency_ms': 0.0
        }

    @abstractmethod
    def process(self, input_data: Any, **kwargs) -> ProviderResult:
        """
        Process input data and return standardized result.

        This is the main method that executes the provider's functionality.

        Args:
            input_data: The data to process (varies by service type)
            **kwargs: Additional provider-specific parameters

        Returns:
            ProviderResult with standardized fields

        Example:
            def process(self, image_path: str, **kwargs) -> ProviderResult:
                start_time = time.time()

                try:
                    # Call API
                    response = self.api_client.analyze(image_path)

                    # Calculate metrics
                    latency_ms = (time.time() - start_time) * 1000

                    # Return standardized result
                    return ProviderResult(
                        success=True,
                        data={'result': response.data},
                        provider_name=self.name,
                        cost=self.estimate_cost(image_path),
                        latency_ms=latency_ms,
                        metadata={'extra_info': response.metadata}
                    )
                except Exception as e:
                    latency_ms = (time.time() - start_time) * 1000
                    return ProviderResult(
                        success=False,
                        data=None,
                        provider_name=self.name,
                        cost=0.0,
                        latency_ms=latency_ms,
                        metadata={},
                        error=str(e)
                    )
        """
        pass

    @abstractmethod
    def validate_input(self, input_data: Any) -> bool:
        """
        Validate input before processing.

        Args:
            input_data: The data to validate

        Returns:
            True if input is valid, False otherwise

        Example:
            def validate_input(self, image_path: str) -> bool:
                import os
                # Check file exists
                if not os.path.exists(image_path):
                    return False
                # Check file size
                if os.path.getsize(image_path) > 20 * 1024 * 1024:  # 20MB limit
                    return False
                # Check file extension
                if not image_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                    return False
                return True
        """
        pass

    @abstractmethod
    def estimate_cost(self, input_data: Any) -> float:
        """
        Estimate cost for processing this input.

        Args:
            input_data: The data to estimate cost for

        Returns:
            Estimated cost in USD

        Example:
            def estimate_cost(self, image_path: str) -> float:
                # Fixed cost per image
                return 0.0015  # $1.50 per 1000 images

            def estimate_cost(self, text: str) -> float:
                # Cost per character
                char_count = len(text)
                return char_count * 0.00002  # $20 per 1M characters
        """
        pass

    @abstractmethod
    def health_check(self) -> ProviderStatus:
        """
        Check provider availability and health.

        Returns:
            ProviderStatus enum value

        Example:
            def health_check(self) -> ProviderStatus:
                try:
                    # Ping API endpoint
                    response = self.api_client.ping()
                    if response.status_code == 200:
                        return ProviderStatus.AVAILABLE
                    elif response.status_code in [429, 503]:
                        return ProviderStatus.DEGRADED
                    else:
                        return ProviderStatus.UNAVAILABLE
                except Exception:
                    return ProviderStatus.UNAVAILABLE
        """
        pass

    @property
    def is_available(self) -> bool:
        """Quick check if provider is available"""
        return self._status == ProviderStatus.AVAILABLE

    @property
    def is_enabled(self) -> bool:
        """Check if provider is enabled in config"""
        return self.config.get('enabled', True)

    @property
    def priority(self) -> int:
        """
        Provider priority (lower number = higher priority)

        Default: 100
        """
        return self.config.get('priority', 100)

    @property
    def quality_score(self) -> float:
        """
        Provider quality score (0.0 to 1.0)

        Used for quality-based provider selection
        """
        return self.config.get('quality_score', 0.5)

    def update_metrics(self, result: ProviderResult):
        """Update provider metrics after processing"""
        self._metrics['total_requests'] += 1
        if result.success:
            self._metrics['successful_requests'] += 1
        else:
            self._metrics['failed_requests'] += 1
        self._metrics['total_cost'] += result.cost
        self._metrics['total_latency_ms'] += result.latency_ms

    def get_metrics(self) -> Dict[str, Any]:
        """Get provider performance metrics"""
        success_rate = (
            self._metrics['successful_requests'] / self._metrics['total_requests']
            if self._metrics['total_requests'] > 0 else 0.0
        )
        avg_latency = (
            self._metrics['total_latency_ms'] / self._metrics['total_requests']
            if self._metrics['total_requests'] > 0 else 0.0
        )

        return {
            **self._metrics,
            'success_rate': success_rate,
            'avg_latency_ms': avg_latency,
            'avg_cost': self._metrics['total_cost'] / max(self._metrics['total_requests'], 1)
        }

    def reset_metrics(self):
        """Reset provider metrics"""
        self._metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_cost': 0.0,
            'total_latency_ms': 0.0
        }

    def __repr__(self) -> str:
        return f"{self.name}(priority={self.priority}, enabled={self.is_enabled}, status={self._status.value})"
