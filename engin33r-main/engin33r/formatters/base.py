"""Base formatter class"""

from abc import ABC, abstractmethod
from engin33r.core.vulnerability import VulnerabilityReport


class Formatter(ABC):
    """Abstract base class for report formatters"""

    @abstractmethod
    def format_report(self, report: VulnerabilityReport) -> str:
        """
        Format a vulnerability report

        Args:
            report: VulnerabilityReport to format

        Returns:
            Formatted report as string
        """
        pass
