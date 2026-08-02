"""Command-line interface for engin33r"""

import sys
import argparse
import json
import logging
from typing import Optional
from pathlib import Path

from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.analyzers.dependency import DependencyAnalyzer
from engin33r.formatters.json_formatter import JSONFormatter
from engin33r.formatters.text_formatter import TextFormatter

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="engin33r - Complete Bug Vulnerability Framework"
    )

    parser.add_argument("target", help="Target to scan (file or directory path)")
    parser.add_argument(
        "-a",
        "--analyzers",
        nargs="+",
        default=["static", "dependency"],
        help="Analyzers to use (static, dependency)",
    )
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "-f", "--format", choices=["json", "text"], default="text", help="Output format"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize engine
    engine = VulnerabilityEngine()

    # Register selected analyzers
    if "static" in args.analyzers:
        engine.register_analyzer(StaticAnalyzer())
    if "dependency" in args.analyzers:
        engine.register_analyzer(DependencyAnalyzer())

    # Run scan
    logger.info(f"Scanning target: {args.target}")
    vulnerabilities = engine.scan(args.target)

    # Generate report
    report = engine.generate_report(title=f"Vulnerability Report for {args.target}")

    # Format output
    if args.format == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    output = formatter.format_report(report)

    # Write output
    if args.output:
        Path(args.output).write_text(output)
        logger.info(f"Report written to {args.output}")
    else:
        print(output)

    # Return exit code based on vulnerabilities
    if report.metrics.get("critical", 0) > 0:
        return 2
    elif report.metrics.get("high", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
