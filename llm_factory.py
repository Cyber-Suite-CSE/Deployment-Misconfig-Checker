#!/usr/bin/env python3
"""
LLM Factory Module
Centralized LLM initialization supporting multiple providers (Google GenAI and OpenAI)
"""

import os
from langchain.chat_models import init_chat_model
from colorama import Fore, Style, init

init(autoreset=True)


def create_llm(temperature=0.1):
    """
    Factory function to create LLM based on LLM_PROVIDER environment variable.

    Supported providers:
    - "google_genai": Google Gemini (gemini-2.5-flash)
    - "openai": OpenAI (gpt-4o-mini)

    Args:
        temperature: Temperature setting for the LLM (default: 0.1)

    Returns:
        Initialized LLM instance

    Raises:
        ValueError: If LLM_PROVIDER is not supported or required API key is missing
    """
    provider = os.getenv("LLM_PROVIDER", "google_genai").lower()
    # Cap any silent socket hang in the underlying SDK; surfaces as TimeoutError.
    timeout_s = float(os.getenv("LLM_TIMEOUT", "90"))
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "2"))

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables. Please set OPENAI_API_KEY in your .env file.")

        print(f"{Fore.GREEN}[LLM Factory] Initializing OpenAI model: gpt-4o-mini (timeout={timeout_s}s, max_retries={max_retries}){Style.RESET_ALL}")
        return init_chat_model(
            "gpt-4o-mini",
            model_provider="openai",
            temperature=temperature,
            timeout=timeout_s,
            max_retries=max_retries,
        )

    elif provider == "google_genai":
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables. Please set GOOGLE_API_KEY in your .env file.")

        print(f"{Fore.GREEN}[LLM Factory] Initializing Google Gemini model: gemini-2.5-flash (timeout={timeout_s}s, max_retries={max_retries}){Style.RESET_ALL}")
        return init_chat_model(
            "gemini-2.5-flash",
            model_provider="google_genai",
            temperature=temperature,
            timeout=timeout_s,
            max_retries=max_retries,
        )

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
