"""Base analyzer class for vulnerability detection"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from engin33r.core.vulnerability import Vulnerability


class VulnerabilityAnalyzer(ABC):
    """Abstract base class for vulnerability analyzers"""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.enabled = True

    @abstractmethod
    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Analyze target for vulnerabilities

        Args:
            target: Target to analyze (file path, code, URL, etc.)
            context: Optional context information

        Returns:
            List of discovered Vulnerability objects
        """
        pass

    def supports_target(self, target: str) -> bool:
        """
        Check if analyzer supports the given target

        Args:
            target: Target to check

        Returns:
            True if analyzer can handle this target
        """
        return True
