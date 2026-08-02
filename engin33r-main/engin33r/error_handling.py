"""Comprehensive error handling and validation"""

import logging
from typing import Any, Callable, TypeVar, Optional, Dict
from functools import wraps
from enum import Enum
from datetime import datetime
import traceback

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ErrorSeverity(Enum):
    """Error severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngineeringException(Exception):
    """Base exception for engin33r framework"""

    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.HIGH,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        self.message = message
        self.severity = severity
        self.context = context or {}
        self.original_error = original_error
        self.timestamp = datetime.utcnow()
        self.traceback_str = traceback.format_exc() if original_error else None

        full_message = f"[{severity.value.upper()}] {message}"
        if context:
            full_message += f" | Context: {context}"
        if original_error:
            full_message += f" | Caused by: {str(original_error)}"

        super().__init__(full_message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/serialization"""
        return {
            "exception": self.__class__.__name__,
            "message": self.message,
            "severity": self.severity.value,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "traceback": self.traceback_str,
        }


class ValidationError(EngineeringException):
    """Input validation error"""

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, ErrorSeverity.MEDIUM, context, original_error)


class ConfigurationError(EngineeringException):
    """Configuration error"""

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, ErrorSeverity.HIGH, context, original_error)


class AnalysisError(EngineeringException):
    """Analysis execution error"""

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, ErrorSeverity.HIGH, context, original_error)


class DatabaseError(EngineeringException):
    """Database/API access error"""

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, ErrorSeverity.CRITICAL, context, original_error)


class IntegrationError(EngineeringException):
    """Integration error"""

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, ErrorSeverity.HIGH, context, original_error)


class InputValidator:
    """Validate user inputs"""

    @staticmethod
    def validate_string(
        value: Any,
        name: str,
        min_length: int = 1,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
    ) -> str:
        """
        Validate string input
        """
        if not isinstance(value, str):
            raise ValidationError(
                f"{name} must be a string, got {type(value).__name__}",
                context={"value": str(value), "type": type(value).__name__},
            )

        if len(value) < min_length:
            raise ValidationError(
                f"{name} must be at least {min_length} characters, got {len(value)}",
                context={"name": name, "required": min_length, "provided": len(value)},
            )

        if max_length and len(value) > max_length:
            raise ValidationError(
                f"{name} must be at most {max_length} characters, got {len(value)}",
                context={"name": name, "max": max_length, "provided": len(value)},
            )

        if pattern:
            import re

            if not re.match(pattern, value):
                raise ValidationError(
                    f"{name} does not match required pattern: {pattern}",
                    context={"name": name, "pattern": pattern, "value": value},
                )

        return value

    @staticmethod
    def validate_integer(
        value: Any,
        name: str,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
    ) -> int:
        """
        Validate integer input
        """
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(
                f"{name} must be an integer, got {type(value).__name__}",
                context={"value": str(value), "type": type(value).__name__},
            )

        if min_value is not None and value < min_value:
            raise ValidationError(
                f"{name} must be at least {min_value}, got {value}",
                context={"name": name, "min": min_value, "provided": value},
            )

        if max_value is not None and value > max_value:
            raise ValidationError(
                f"{name} must be at most {max_value}, got {value}",
                context={"name": name, "max": max_value, "provided": value},
            )

        return value

    @staticmethod
    def validate_float(
        value: Any,
        name: str,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
    ) -> float:
        """
        Validate float input
        """
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValidationError(
                f"{name} must be a number, got {type(value).__name__}",
                context={"value": str(value), "type": type(value).__name__},
            )

        float_val = float(value)

        if min_value is not None and float_val < min_value:
            raise ValidationError(
                f"{name} must be at least {min_value}, got {float_val}",
                context={"name": name, "min": min_value, "provided": float_val},
            )

        if max_value is not None and float_val > max_value:
            raise ValidationError(
                f"{name} must be at most {max_value}, got {float_val}",
                context={"name": name, "max": max_value, "provided": float_val},
            )

        return float_val

    @staticmethod
    def validate_choice(value: Any, name: str, choices: list) -> Any:
        """
        Validate value is in allowed choices
        """
        if value not in choices:
            raise ValidationError(
                f"{name} must be one of {choices}, got {value}",
                context={"name": name, "allowed": choices, "provided": value},
            )
        return value

    @staticmethod
    def validate_list(
        value: Any,
        name: str,
        min_items: int = 0,
        max_items: Optional[int] = None,
        item_type: Optional[type] = None,
    ) -> list:
        """
        Validate list input
        """
        if not isinstance(value, list):
            raise ValidationError(
                f"{name} must be a list, got {type(value).__name__}",
                context={"value": str(value), "type": type(value).__name__},
            )

        if len(value) < min_items:
            raise ValidationError(
                f"{name} must have at least {min_items} items, got {len(value)}",
                context={"name": name, "min": min_items, "provided": len(value)},
            )

        if max_items and len(value) > max_items:
            raise ValidationError(
                f"{name} must have at most {max_items} items, got {len(value)}",
                context={"name": name, "max": max_items, "provided": len(value)},
            )

        if item_type:
            for i, item in enumerate(value):
                if not isinstance(item, item_type):
                    raise ValidationError(
                        f"{name}[{i}] must be {item_type.__name__}, got {type(item).__name__}",
                        context={
                            "index": i,
                            "expected": item_type.__name__,
                            "got": type(item).__name__,
                        },
                    )

        return value

    @staticmethod
    def validate_dict(
        value: Any,
        name: str,
        required_keys: Optional[list] = None,
        key_types: Optional[Dict[str, type]] = None,
    ) -> dict:
        """
        Validate dictionary input
        """
        if not isinstance(value, dict):
            raise ValidationError(
                f"{name} must be a dictionary, got {type(value).__name__}",
                context={"value": str(value), "type": type(value).__name__},
            )

        if required_keys:
            missing = set(required_keys) - set(value.keys())
            if missing:
                raise ValidationError(
                    f"{name} missing required keys: {missing}",
                    context={
                        "name": name,
                        "required": required_keys,
                        "provided": list(value.keys()),
                    },
                )

        if key_types:
            for key, expected_type in key_types.items():
                if key in value and not isinstance(value[key], expected_type):
                    raise ValidationError(
                        f"{name}[{key}] must be {expected_type.__name__}, got {type(value[key]).__name__}",
                        context={
                            "key": key,
                            "expected": expected_type.__name__,
                            "got": type(value[key]).__name__,
                        },
                    )

        return value


def validate_input(validator_func: Callable) -> Callable:
    """
    Decorator for input validation
    """

    @wraps(validator_func)
    def wrapper(*args, **kwargs):
        try:
            return validator_func(*args, **kwargs)
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(
                f"Validation failed in {validator_func.__name__}",
                context={"function": validator_func.__name__},
                original_error=e,
            )

    return wrapper


def handle_errors(default_return: Any = None, log_traceback: bool = True) -> Callable:
    """
    Decorator for comprehensive error handling
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except EngineeringException:
                raise  # Re-raise our custom exceptions
            except Exception as e:
                error_context = {
                    "function": func.__name__,
                    "args": str(args)[:200],
                    "kwargs": str(kwargs)[:200],
                }

                logger.error(
                    f"Error in {func.__name__}: {str(e)}",
                    extra={
                        "context": error_context,
                        "traceback": traceback.format_exc() if log_traceback else None,
                    },
                )

                if default_return is not None:
                    return default_return

                raise AnalysisError(
                    f"Error executing {func.__name__}",
                    context=error_context,
                    original_error=e,
                )

        return wrapper

    return decorator


class ErrorHandler:
    """Centralized error handling"""

    def __init__(self):
        self.errors: list = []
        self.warnings: list = []

    def record_error(self, error: EngineeringException) -> None:
        """Record an error"""
        self.errors.append(error)
        logger.error(f"{error.severity.value}: {error.message}")

    def record_warning(self, message: str, context: Optional[Dict] = None) -> None:
        """Record a warning"""
        warning = {
            "message": message,
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.warnings.append(warning)
        logger.warning(message, extra=context or {})

    def has_critical_errors(self) -> bool:
        """Check if there are critical errors"""
        return any(e.severity == ErrorSeverity.CRITICAL for e in self.errors)

    def get_summary(self) -> Dict[str, Any]:
        """Get error summary"""
        return {
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings),
            "critical": sum(
                1 for e in self.errors if e.severity == ErrorSeverity.CRITICAL
            ),
            "high": sum(1 for e in self.errors if e.severity == ErrorSeverity.HIGH),
            "medium": sum(1 for e in self.errors if e.severity == ErrorSeverity.MEDIUM),
            "low": sum(1 for e in self.errors if e.severity == ErrorSeverity.LOW),
            "has_critical": self.has_critical_errors(),
        }

    def get_errors_dict(self) -> list:
        """Get all errors as dictionaries"""
        return [e.to_dict() for e in self.errors]

    def clear(self) -> None:
        """Clear all errors and warnings"""
        self.errors.clear()
        self.warnings.clear()
