#!/usr/bin/env python3
"""
LLM Factory Module
Centralized LLM initialization supporting multiple providers (Google GenAI and OpenAI)
"""

import os
from langchain.chat_models import init_chat_model
from colorama import Fore, Style, init

init(autoreset=True)


def create_llm(temperature=0.1, model=None):
    """
    Factory function to create LLM based on LLM_PROVIDER environment variable.

    Supported providers:
    - "google_genai": Google Gemini (default model: gemini-2.5-flash)
    - "openai": OpenAI (default model: gpt-4o-mini)

    Args:
        temperature: Temperature setting for the LLM (default: 0.1)
        model: Override the default model for the current provider (e.g. "gpt-4o").
            If None, uses the provider's default.

    Returns:
        Initialized LLM instance

    Raises:
        ValueError: If LLM_PROVIDER is not supported or required API key is missing
    """
    provider = os.getenv("LLM_PROVIDER", "google_genai").lower()

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables. Please set OPENAI_API_KEY in your .env file.")

        chosen = model or "gpt-4o-mini"
        print(f"{Fore.GREEN}[LLM Factory] Initializing OpenAI model: {chosen}{Style.RESET_ALL}")
        return init_chat_model(chosen, model_provider="openai", temperature=temperature)

    elif provider == "google_genai":
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables. Please set GOOGLE_API_KEY in your .env file.")

        chosen = model or "gemini-2.5-flash"
        print(f"{Fore.GREEN}[LLM Factory] Initializing Google Gemini model: {chosen}{Style.RESET_ALL}")
        return init_chat_model(chosen, model_provider="google_genai", temperature=temperature)

    else:
        raise ValueError(
            f"Unsupported LLM_PROVIDER: {provider}. "
            f"Supported providers: 'google_genai', 'openai'. "
            f"Please set LLM_PROVIDER in your .env file."
        )


def get_current_provider():
    """
    Get the currently configured LLM provider.

    Returns:
        str: The current LLM provider name
    """
    return os.getenv("LLM_PROVIDER", "google_genai").lower()
