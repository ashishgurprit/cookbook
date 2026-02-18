"""
Base security scanner interface and shared data structures.

This module defines the abstract base class for all security connectors
and the normalized data format for security reports.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any


class PlatformType(Enum):
    """Supported platform types for security scanning."""
    GENERIC_URL = "generic_url"
    WORDPRESS = "wordpress"
    GHOST = "ghost"
    STATIC_SITE = "static_site"
    SSH_SERVER = "ssh_server"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities and misconfigurations."""
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"          # Important to fix soon
    MEDIUM = "medium"      # Should be addressed
    LOW = "low"            # Nice to fix
    INFO = "info"          # Informational


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    severity: SeverityLevel
    title: str
    description: str
    affected_component: str
    cve_id: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        """String representation of vulnerability."""
        severity_emoji = {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🟢",
            SeverityLevel.INFO: "ℹ️"
        }
        emoji = severity_emoji.get(self.severity, "•")
        cve = f" [{self.cve_id}]" if self.cve_id else ""
        return f"{emoji} {self.title}{cve}\n   {self.description}\n   Component: {self.affected_component}"


@dataclass
class Misconfiguration:
    """Represents a security misconfiguration."""
    severity: SeverityLevel
    category: str  # headers, ssl, authentication, permissions, etc.
    issue: str
    recommendation: str
    config_file: Optional[str] = None
    fix_code: Optional[str] = None

    def __str__(self) -> str:
        """String representation of misconfiguration."""
        severity_emoji = {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🟢",
            SeverityLevel.INFO: "ℹ️"
        }
        emoji = severity_emoji.get(self.severity, "•")
        config_info = f" ({self.config_file})" if self.config_file else ""
        return f"{emoji} [{self.category}] {self.issue}{config_info}\n   Recommendation: {self.recommendation}"


@dataclass
class NormalizedSecurityReport:
    """
    Normalized security report format.
    All security scanners must return data in this format.
    """
    # REQUIRED FIELDS
    target_url: str
    platform: PlatformType
    scan_date: datetime

    # VULNERABILITIES
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    misconfigurations: List[Misconfiguration] = field(default_factory=list)

    # SECURITY POSTURE
    security_headers: Dict[str, bool] = field(default_factory=dict)
    ssl_tls_status: Dict[str, Any] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)

    # SCORING
    risk_score: int = 100  # 100 = secure, 0 = critical risk

    # METADATA
    scan_duration: float = 0.0
    scanner_version: str = "1.0.0"

    # PLATFORM-SPECIFIC DATA
    raw_data: Optional[Dict] = None

    def get_severity_counts(self) -> Dict[SeverityLevel, int]:
        """Get count of issues by severity level."""
        counts = {level: 0 for level in SeverityLevel}

        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1

        for config in self.misconfigurations:
            counts[config.severity] += 1

        return counts

    def get_critical_issues(self) -> List:
        """Get all critical severity issues."""
        issues = []

        for vuln in self.vulnerabilities:
            if vuln.severity == SeverityLevel.CRITICAL:
                issues.append(vuln)

        for config in self.misconfigurations:
            if config.severity == SeverityLevel.CRITICAL:
                issues.append(config)

        return issues

    def get_high_priority_issues(self) -> List:
        """Get all high and critical severity issues."""
        issues = []

        for vuln in self.vulnerabilities:
            if vuln.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                issues.append(vuln)

        for config in self.misconfigurations:
            if config.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                issues.append(config)

        return issues

    def get_risk_grade(self) -> str:
        """Get letter grade based on risk score."""
        if self.risk_score >= 90:
            return "A"
        elif self.risk_score >= 70:
            return "B"
        elif self.risk_score >= 50:
            return "C"
        elif self.risk_score >= 30:
            return "D"
        else:
            return "F"


class BaseSecurityConnector(ABC):
    """
    Abstract base class for all security scanners.

    All platform-specific scanners must inherit from this class
    and implement the required methods.
    """

    def __init__(self, target: str, **kwargs):
        """
        Initialize the security connector.

        Args:
            target: Target URL, hostname, or IP address
            **kwargs: Additional connector-specific configuration
        """
        self.target = target
        self.config = kwargs
        self.scanner_version = "1.0.0"

    @abstractmethod
    def scan(self) -> NormalizedSecurityReport:
        """
        Perform security scan and return normalized report.

        Returns:
            NormalizedSecurityReport: Normalized security scan results

        Raises:
            Exception: If scan fails
        """
        pass

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test connection to target.

        Returns:
            Tuple[bool, str]: (success, message)
        """
        pass

    def apply_hardening(self, fixes: List[str]) -> bool:
        """
        Apply security hardening fixes (optional).

        Args:
            fixes: List of fix identifiers to apply

        Returns:
            bool: True if all fixes applied successfully

        Note:
            Not all scanners support automated hardening.
            Override this method in subclasses that support it.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support automated hardening"
        )

    def _create_report(self) -> NormalizedSecurityReport:
        """Helper to create a new normalized report."""
        return NormalizedSecurityReport(
            target_url=self.target,
            platform=self._detect_platform(),
            scan_date=datetime.now(),
            scanner_version=self.scanner_version
        )

    def _detect_platform(self) -> PlatformType:
        """
        Detect platform type (can be overridden by subclasses).

        Returns:
            PlatformType: Detected platform type
        """
        return PlatformType.UNKNOWN
