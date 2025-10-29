"""Prompts package for different Burp AI request types."""

from .explain import ExplainThisPrompt
from .montoya import MontoyaPrompt
from .explore import ExplorePrompt

__all__ = ["ExplainThisPrompt", "MontoyaPrompt", "ExplorePrompt"]
