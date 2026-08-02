"""AI-powered vulnerability analysis assistant with fallback strategy"""

import logging
import os
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from enum import Enum
import json

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    """AI provider types"""

    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    LOCAL = "local"


class AIProviderBase(ABC):
    """Base class for AI providers"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.available = False

    @abstractmethod
    def validate_credentials(self) -> bool:
        """Validate API credentials"""
        pass

    @abstractmethod
    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Analyze a vulnerability"""
        pass

    @abstractmethod
    def generate_remediation(self, vulnerability: Any) -> str:
        """Generate remediation guidance"""
        pass

    @abstractmethod
    def risk_assessment(self, vulnerability: Any) -> Dict[str, Any]:
        """Perform risk assessment"""
        pass


class GeminiProvider(AIProviderBase):
    """Google Gemini API provider"""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key or os.getenv("GEMINI_API_KEY"))
        self.model = "gemini-pro"
        self.validate_credentials()

    def validate_credentials(self) -> bool:
        """Validate Gemini API key"""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)
            self.client = genai.GenerativeModel(self.model)
            self.available = bool(self.api_key)
            logger.info("Gemini API provider initialized")
            return self.available
        except Exception as e:
            logger.warning(f"Gemini API initialization failed: {e}")
            self.available = False
            return False

    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Analyze vulnerability using Gemini"""
        if not self.available:
            return {}

        try:
            prompt = f"""
            Analyze the following security vulnerability:
            
            Title: {vulnerability.title}
            Type: {vulnerability.vulnerability_type.value}
            Severity: {vulnerability.severity.value}
            Description: {vulnerability.description}
            
            Provide:
            1. Root cause analysis
            2. Potential attack scenarios
            3. Business impact assessment
            4. Likelihood of exploitation
            
            Format response as JSON.
            """

            response = self.client.generate_content(prompt)
            analysis_text = response.text

            # Parse JSON from response
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                analysis = {"analysis": analysis_text}

            return {"provider": "gemini", "analysis": analysis, "status": "success"}
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {"provider": "gemini", "status": "error", "error": str(e)}

    def generate_remediation(self, vulnerability: Any) -> str:
        """Generate remediation guidance using Gemini"""
        if not self.available:
            return ""

        try:
            prompt = f"""
            Generate detailed remediation steps for this vulnerability:
            
            Title: {vulnerability.title}
            Type: {vulnerability.vulnerability_type.value}
            File: {vulnerability.file_path}
            Code: {vulnerability.code_snippet}
            
            Provide:
            1. Immediate actions
            2. Code changes with examples
            3. Testing procedures
            4. Preventive measures
            """

            response = self.client.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini remediation generation failed: {e}")
            return ""

    def risk_assessment(self, vulnerability: Any) -> Dict[str, Any]:
        """Perform risk assessment using Gemini"""
        if not self.available:
            return {}

        try:
            prompt = f"""
            Perform a risk assessment for this vulnerability:
            
            {vulnerability.description}
            
            Provide as JSON:
            {{
                "exploitability": 0-10,
                "business_impact": "high/medium/low",
                "affected_users": 0-100000,
                "financial_impact": "estimate in USD",
                "compliance_risk": "list applicable regulations",
                "recommended_priority": "critical/high/medium/low"
            }}
            """

            response = self.client.generate_content(prompt)
            risk_data = json.loads(response.text)

            return {
                "provider": "gemini",
                "risk_assessment": risk_data,
                "status": "success",
            }
        except Exception as e:
            logger.error(f"Gemini risk assessment failed: {e}")
            return {"provider": "gemini", "status": "error", "error": str(e)}


class DeepSeekProvider(AIProviderBase):
    """DeepSeek API provider"""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key or os.getenv("DEEPSEEK_API_KEY"))
        self.base_url = "https://api.deepseek.com/v1"
        self.model = "deepseek-chat"
        self.validate_credentials()

    def validate_credentials(self) -> bool:
        """Validate DeepSeek API key"""
        try:
            import requests

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            response = requests.get(
                f"{self.base_url}/models", headers=headers, timeout=10
            )
            self.available = response.status_code == 200
            if self.available:
                logger.info("DeepSeek API provider initialized")
            else:
                logger.warning(f"DeepSeek validation failed: {response.status_code}")
            return self.available
        except Exception as e:
            logger.warning(f"DeepSeek API initialization failed: {e}")
            self.available = False
            return False

    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Analyze vulnerability using DeepSeek"""
        if not self.available:
            return {}

        try:
            import requests

            prompt = f"""
            Analyze security vulnerability:
            Title: {vulnerability.title}
            Type: {vulnerability.vulnerability_type.value}
            Description: {vulnerability.description}
            
            Provide JSON analysis of root causes, attack scenarios, and impact.
            """

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                analysis_text = data["choices"][0]["message"]["content"]

                try:
                    analysis = json.loads(analysis_text)
                except json.JSONDecodeError:
                    analysis = {"analysis": analysis_text}

                return {
                    "provider": "deepseek",
                    "analysis": analysis,
                    "status": "success",
                }
            else:
                return {
                    "provider": "deepseek",
                    "status": "error",
                    "error": str(response.status_code),
                }

        except Exception as e:
            logger.error(f"DeepSeek analysis failed: {e}")
            return {"provider": "deepseek", "status": "error", "error": str(e)}

    def generate_remediation(self, vulnerability: Any) -> str:
        """Generate remediation using DeepSeek"""
        if not self.available:
            return ""

        try:
            import requests

            prompt = f"""
            Generate remediation steps for:
            {vulnerability.title}
            
            File: {vulnerability.file_path}
            Code: {vulnerability.code_snippet}
            
            Provide detailed fixes with code examples.
            """

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                return ""

        except Exception as e:
            logger.error(f"DeepSeek remediation generation failed: {e}")
            return ""

    def risk_assessment(self, vulnerability: Any) -> Dict[str, Any]:
        """Risk assessment using DeepSeek"""
        if not self.available:
            return {}

        try:
            import requests

            prompt = f"""
            Risk assessment for: {vulnerability.description}
            
            Return JSON with exploitability, business_impact, affected_users, etc.
            """

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                risk_text = data["choices"][0]["message"]["content"]

                try:
                    risk_data = json.loads(risk_text)
                except json.JSONDecodeError:
                    risk_data = {"assessment": risk_text}

                return {
                    "provider": "deepseek",
                    "risk_assessment": risk_data,
                    "status": "success",
                }
            else:
                return {"provider": "deepseek", "status": "error"}

        except Exception as e:
            logger.error(f"DeepSeek risk assessment failed: {e}")
            return {"provider": "deepseek", "status": "error", "error": str(e)}


class AnthropicProvider(AIProviderBase):
    """Anthropic Claude provider"""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = "claude-3-sonnet-20240229"
        self.validate_credentials()

    def validate_credentials(self) -> bool:
        """Validate Anthropic API key"""
        try:
            from anthropic import Anthropic

            self.client = Anthropic(api_key=self.api_key)
            self.available = bool(self.api_key)
            if self.available:
                logger.info("Anthropic API provider initialized")
            return self.available
        except Exception as e:
            logger.warning(f"Anthropic API initialization failed: {e}")
            self.available = False
            return False

    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Analyze vulnerability using Claude"""
        if not self.available:
            return {}

        try:
            prompt = f"""
            Analyze the following security vulnerability and provide detailed analysis in JSON format:
            
            Title: {vulnerability.title}
            Type: {vulnerability.vulnerability_type.value}
            Severity: {vulnerability.severity.value}
            Description: {vulnerability.description}
            
            Include: root_cause, attack_scenarios, business_impact, exploitation_likelihood
            """

            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            analysis_text = response.content[0].text

            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                analysis = {"analysis": analysis_text}

            return {"provider": "anthropic", "analysis": analysis, "status": "success"}
        except Exception as e:
            logger.error(f"Anthropic analysis failed: {e}")
            return {"provider": "anthropic", "status": "error", "error": str(e)}

    def generate_remediation(self, vulnerability: Any) -> str:
        """Generate remediation using Claude"""
        if not self.available:
            return ""

        try:
            prompt = f"""
            Generate step-by-step remediation guidance for this vulnerability:
            
            Title: {vulnerability.title}
            File: {vulnerability.file_path}
            Code: {vulnerability.code_snippet}
            
            Include immediate actions, code changes with examples, and preventive measures.
            """

            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )

            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic remediation generation failed: {e}")
            return ""

    def risk_assessment(self, vulnerability: Any) -> Dict[str, Any]:
        """Risk assessment using Claude"""
        if not self.available:
            return {}

        try:
            prompt = f"""
            Perform comprehensive risk assessment for:
            {vulnerability.description}
            
            Return JSON with:
            - exploitability (0-10)
            - business_impact (high/medium/low)
            - affected_users (estimated count)
            - financial_impact (USD estimate)
            - compliance_risk (list regulations)
            - recommended_priority
            """

            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            risk_text = response.content[0].text

            try:
                risk_data = json.loads(risk_text)
            except json.JSONDecodeError:
                risk_data = {"assessment": risk_text}

            return {
                "provider": "anthropic",
                "risk_assessment": risk_data,
                "status": "success",
            }
        except Exception as e:
            logger.error(f"Anthropic risk assessment failed: {e}")
            return {"provider": "anthropic", "status": "error", "error": str(e)}


class VulnerabilityAssistant:
    """AI-powered vulnerability assistant with fallback"""

    def __init__(self, providers: Optional[List[AIProvider]] = None):
        """
        Initialize assistant with fallback providers

        Default order: Gemini > DeepSeek > Anthropic
        """
        self.providers = providers or [
            GeminiProvider(),
            DeepSeekProvider(),
            AnthropicProvider(),
        ]
        self.available_providers = [p for p in self.providers if p.available]

        if not self.available_providers:
            logger.warning("No AI providers available")

    def analyze_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Analyze vulnerability with fallback"""
        for provider in self.available_providers:
            try:
                result = provider.analyze_vulnerability(vulnerability)
                if result.get("status") == "success":
                    return result
            except Exception as e:
                logger.warning(f"{provider.__class__.__name__} analysis failed: {e}")
                continue

        return {"status": "failed", "message": "All AI providers failed"}

    def generate_remediation(self, vulnerability: Any) -> str:
        """Generate remediation with fallback"""
        for provider in self.available_providers:
            try:
                result = provider.generate_remediation(vulnerability)
                if result:
                    return result
            except Exception as e:
                logger.warning(f"{provider.__class__.__name__} remediation failed: {e}")
                continue

        return "Unable to generate AI remediation. Please review manually."

    def risk_assessment(self, vulnerability: Any) -> Dict[str, Any]:
        """Risk assessment with fallback"""
        for provider in self.available_providers:
            try:
                result = provider.risk_assessment(vulnerability)
                if result.get("status") == "success":
                    return result
            except Exception as e:
                logger.warning(
                    f"{provider.__class__.__name__} risk assessment failed: {e}"
                )
                continue

        return {"status": "failed", "message": "All AI providers failed"}

    def get_provider_status(self) -> Dict[str, bool]:
        """Get status of all providers"""
        return {p.__class__.__name__: p.available for p in self.providers}
