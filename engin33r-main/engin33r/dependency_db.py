"""Integration with vulnerability databases (NVD, OSV, Snyk)"""

import logging
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json

logger = logging.getLogger(__name__)


class VulnDBSource(Enum):
    """Vulnerability database sources"""

    NVD = "nvd"  # National Vulnerability Database
    OSV = "osv"  # Open Source Vulnerabilities
    SNYK = "snyk"  # Snyk Vulnerability Database
    ADVISORY = "advisory"  # GitHub Security Advisories


@dataclass
class CVEEntry:
    """CVE database entry"""

    cve_id: str
    package_name: str
    affected_versions: List[str]
    fixed_version: Optional[str]
    description: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity: str
    published_date: Optional[datetime]
    source: VulnDBSource
    references: List[str]


class NVDIntegration:
    """National Vulnerability Database integration"""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    API_TIMEOUT = 10

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache: Dict[str, CVEEntry] = {}

    def search_by_cpe(self, cpe: str) -> List[CVEEntry]:
        """
        Search NVD by CPE (Common Platform Enumeration)

        CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        """
        try:
            params = {
                "cpeMatchString": cpe,
                "addOns": "dictionaryLookup",
            }
            if self.api_key:
                params["apiKey"] = self.api_key

            response = requests.get(
                f"{self.BASE_URL}", params=params, timeout=self.API_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            for item in data.get("result", {}).get("CVE_Items", []):
                cve_id = item["cve"]["CVE_data_meta"]["ID"]

                if cve_id in self.cache:
                    cves.append(self.cache[cve_id])
                    continue

                # Parse CVE data
                impact = item.get("impact", {})
                baseMetricV3 = impact.get("baseMetricV3", {})
                cvss_v3 = baseMetricV3.get("cvssV3", {})

                cve_entry = CVEEntry(
                    cve_id=cve_id,
                    package_name=cpe,
                    affected_versions=[],
                    fixed_version=None,
                    description=item["cve"]["description"]["description_data"][0][
                        "value"
                    ],
                    cvss_score=cvss_v3.get("baseScore"),
                    cvss_vector=cvss_v3.get("vectorString"),
                    severity=baseMetricV3.get("cvssV3", {}).get(
                        "baseSeverity", "UNKNOWN"
                    ),
                    published_date=(
                        datetime.fromisoformat(
                            item["publishedDate"].replace("Z", "+00:00")
                        )
                        if "publishedDate" in item
                        else None
                    ),
                    source=VulnDBSource.NVD,
                    references=[
                        ref.get("url")
                        for ref in item["cve"]
                        .get("references", {})
                        .get("reference_data", [])
                    ],
                )

                self.cache[cve_id] = cve_entry
                cves.append(cve_entry)

            logger.info(f"Found {len(cves)} CVEs for {cpe}")
            return cves

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API error: {e}")
            return []

    def search_by_package(
        self, package_name: str, version: Optional[str] = None
    ) -> List[CVEEntry]:
        """
        Search NVD by package name
        """
        try:
            params = {
                "keyword": f"{package_name}",
            }
            if self.api_key:
                params["apiKey"] = self.api_key

            response = requests.get(
                f"{self.BASE_URL}", params=params, timeout=self.API_TIMEOUT
            )
            response.raise_for_status()

            return self._parse_nvd_response(response.json(), package_name)

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD search failed: {e}")
            return []

    def _parse_nvd_response(self, data: Dict, package_name: str) -> List[CVEEntry]:
        """
        Parse NVD API response
        """
        cves = []
        for item in data.get("result", {}).get("CVE_Items", []):
            cve_id = item["cve"]["CVE_data_meta"]["ID"]

            if cve_id in self.cache:
                cves.append(self.cache[cve_id])
                continue

            impact = item.get("impact", {})
            baseMetricV3 = impact.get("baseMetricV3", {})
            cvss_v3 = baseMetricV3.get("cvssV3", {})

            cve_entry = CVEEntry(
                cve_id=cve_id,
                package_name=package_name,
                affected_versions=[],
                fixed_version=None,
                description=item["cve"]["description"]["description_data"][0]["value"],
                cvss_score=cvss_v3.get("baseScore"),
                cvss_vector=cvss_v3.get("vectorString"),
                severity=baseMetricV3.get("cvssV3", {}).get("baseSeverity", "UNKNOWN"),
                published_date=(
                    datetime.fromisoformat(item["publishedDate"].replace("Z", "+00:00"))
                    if "publishedDate" in item
                    else None
                ),
                source=VulnDBSource.NVD,
                references=[
                    ref.get("url")
                    for ref in item["cve"]
                    .get("references", {})
                    .get("reference_data", [])
                ],
            )

            self.cache[cve_id] = cve_entry
            cves.append(cve_entry)

        return cves


class OSVIntegration:
    """Open Source Vulnerabilities (OSV.dev) integration"""

    BASE_URL = "https://api.osv.dev/v1"
    API_TIMEOUT = 10

    def __init__(self):
        self.cache: Dict[str, CVEEntry] = {}

    def query(
        self, ecosystem: str, package: str, version: Optional[str] = None
    ) -> List[CVEEntry]:
        """
        Query OSV for vulnerabilities

        Ecosystems: npm, PyPI, RubyGems, crates.io, Maven, NuGet, Linux, etc.
        """
        try:
            payload = {
                "package": {
                    "ecosystem": ecosystem,
                    "name": package,
                },
            }
            if version:
                payload["version"] = version

            response = requests.post(
                f"{self.BASE_URL}/query", json=payload, timeout=self.API_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            for vuln in data.get("vulns", []):
                cve_id = vuln.get("id", "unknown")

                if cve_id in self.cache:
                    cves.append(self.cache[cve_id])
                    continue

                # Extract version info
                affected_versions = []
                fixed_version = None

                for affected in vuln.get("affected", []):
                    if affected.get("package", {}).get("name") == package:
                        for range_data in affected.get("ranges", []):
                            for event in range_data.get("events", []):
                                if "introduced" in event:
                                    affected_versions.append(event["introduced"])
                                if "fixed" in event:
                                    fixed_version = event["fixed"]

                cve_entry = CVEEntry(
                    cve_id=cve_id,
                    package_name=package,
                    affected_versions=affected_versions,
                    fixed_version=fixed_version,
                    description=vuln.get("summary", ""),
                    cvss_score=vuln.get("cvss_score"),
                    cvss_vector=None,
                    severity=vuln.get("severity", "UNKNOWN"),
                    published_date=(
                        datetime.fromisoformat(
                            vuln.get("published", "").replace("Z", "+00:00")
                        )
                        if vuln.get("published")
                        else None
                    ),
                    source=VulnDBSource.OSV,
                    references=vuln.get("references", []),
                )

                self.cache[cve_id] = cve_entry
                cves.append(cve_entry)

            logger.info(f"Found {len(cves)} OSV entries for {package}")
            return cves

        except requests.exceptions.RequestException as e:
            logger.error(f"OSV API error: {e}")
            return []


class GitHubAdvisoryIntegration:
    """GitHub Security Advisory integration"""

    BASE_URL = "https://api.github.com/graphql"
    API_TIMEOUT = 10

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self.cache: Dict[str, CVEEntry] = {}

    def search_advisories(
        self, package_name: str, ecosystem: str = "pip"
    ) -> List[CVEEntry]:
        """
        Search GitHub Advisories for vulnerabilities

        Ecosystems: pip, npm, rubygems, maven, nuget, composer, etc.
        """
        try:
            query = f"""
            query {{
              securityAdvisories(
                first: 100
                ecosystem: {ecosystem.upper()}
                orderBy: {{field: UPDATED_AT, direction: DESC}}
              ) {{
                edges {{
                  node {{
                    ghsaId
                    cveId
                    summary
                    description
                    severity
                    vulnerabilities(first: 10) {{
                      edges {{
                        node {{
                          package {{
                            name
                          }}
                          vulnerableVersionRange
                          firstPatchedVersion {{
                            identifier
                          }}
                        }}
                      }}
                    }}
                    references {{
                      url
                    }}
                    publishedAt
                    updatedAt
                  }}
                }}
              }}
            }}
            """

            headers = {}
            if self.github_token:
                headers["Authorization"] = f"Bearer {self.github_token}"

            response = requests.post(
                self.BASE_URL,
                json={"query": query},
                headers=headers,
                timeout=self.API_TIMEOUT,
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            for advisory in (
                data.get("data", {}).get("securityAdvisories", {}).get("edges", [])
            ):
                node = advisory["node"]
                cve_id = node.get("cveId", node.get("ghsaId"))

                if cve_id in self.cache:
                    cves.append(self.cache[cve_id])
                    continue

                cve_entry = CVEEntry(
                    cve_id=cve_id,
                    package_name=package_name,
                    affected_versions=[],
                    fixed_version=None,
                    description=node.get("description", node.get("summary", "")),
                    cvss_score=None,
                    cvss_vector=None,
                    severity=node.get("severity", "UNKNOWN"),
                    published_date=(
                        datetime.fromisoformat(
                            node.get("publishedAt", "").replace("Z", "+00:00")
                        )
                        if node.get("publishedAt")
                        else None
                    ),
                    source=VulnDBSource.ADVISORY,
                    references=[ref.get("url") for ref in node.get("references", [])],
                )

                self.cache[cve_id] = cve_entry
                cves.append(cve_entry)

            logger.info(f"Found {len(cves)} GitHub Advisories for {package_name}")
            return cves

        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub Advisory API error: {e}")
            return []


class DependencyVulnerabilityDB:
    """Centralized dependency vulnerability database"""

    def __init__(
        self,
        use_nvd: bool = True,
        use_osv: bool = True,
        use_github: bool = False,
        nvd_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.nvd = NVDIntegration(nvd_api_key) if use_nvd else None
        self.osv = OSVIntegration() if use_osv else None
        self.github = GitHubAdvisoryIntegration(github_token) if use_github else None
        self.merged_cache: Dict[str, List[CVEEntry]] = {}

    def search_vulnerabilities(
        self,
        package_name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> List[CVEEntry]:
        """
        Search for vulnerabilities across all enabled databases
        """
        cache_key = f"{package_name}:{version or 'any'}:{ecosystem or 'any'}"

        if cache_key in self.merged_cache:
            return self.merged_cache[cache_key]

        all_cves = {}

        # Search NVD
        if self.nvd:
            try:
                nvd_cves = self.nvd.search_by_package(package_name, version)
                for cve in nvd_cves:
                    all_cves[cve.cve_id] = cve
            except Exception as e:
                logger.warning(f"NVD search failed: {e}")

        # Search OSV
        if self.osv and ecosystem:
            try:
                osv_cves = self.osv.query(ecosystem, package_name, version)
                for cve in osv_cves:
                    if cve.cve_id not in all_cves:
                        all_cves[cve.cve_id] = cve
            except Exception as e:
                logger.warning(f"OSV search failed: {e}")

        # Search GitHub Advisories
        if self.github and ecosystem:
            try:
                github_cves = self.github.search_advisories(package_name, ecosystem)
                for cve in github_cves:
                    if cve.cve_id not in all_cves:
                        all_cves[cve.cve_id] = cve
            except Exception as e:
                logger.warning(f"GitHub Advisory search failed: {e}")

        result = list(all_cves.values())
        self.merged_cache[cache_key] = result

        logger.info(f"Found {len(result)} unique vulnerabilities for {package_name}")
        return result

    def get_severity_distribution(self, cves: List[CVEEntry]) -> Dict[str, int]:
        """
        Get distribution of severity levels
        """
        distribution = {}
        for cve in cves:
            severity = cve.severity or "UNKNOWN"
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution

    def filter_by_severity(
        self, cves: List[CVEEntry], min_severity: str
    ) -> List[CVEEntry]:
        """
        Filter CVEs by minimum severity

        Severity order: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN
        """
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        min_level = severity_order.get(min_severity, 0)

        return [cve for cve in cves if severity_order.get(cve.severity, 0) >= min_level]

    def get_recent_vulnerabilities(
        self, cves: List[CVEEntry], days: int = 30
    ) -> List[CVEEntry]:
        """
        Get vulnerabilities published in last N days
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=days)

        return [
            cve for cve in cves if cve.published_date and cve.published_date >= cutoff
        ]

    def generate_report(self, cves: List[CVEEntry]) -> str:
        """
        Generate vulnerability report
        """
        report = "Dependency Vulnerability Report\n"
        report += "=" * 80 + "\n\n"

        severity_dist = self.get_severity_distribution(cves)
        report += "Severity Distribution:\n"
        for severity, count in sorted(
            severity_dist.items(), key=lambda x: x[1], reverse=True
        ):
            report += f"  {severity}: {count}\n"

        report += f"\nTotal Vulnerabilities: {len(cves)}\n\n"
        report += "Details:\n"
        report += "-" * 80 + "\n"

        for cve in sorted(cves, key=lambda x: x.cvss_score or 0, reverse=True):
            report += f"CVE ID: {cve.cve_id}\n"
            report += f"Package: {cve.package_name}\n"
            report += f"Severity: {cve.severity}\n"
            if cve.cvss_score:
                report += f"CVSS Score: {cve.cvss_score}\n"
            report += f"Description: {cve.description[:200]}...\n"
            if cve.fixed_version:
                report += f"Fixed Version: {cve.fixed_version}\n"
            report += "\n"

        return report
