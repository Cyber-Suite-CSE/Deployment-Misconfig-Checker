import os
from typing import Dict, Optional
from colorama import Fore, Style


class PromptProvider:
    """Provider class for loading LLM prompts from filesystem."""

    _cache: Dict[str, str] = {}

    @classmethod
    def _get_prompts_dir(cls) -> str:
        """Get the absolute path to the prompts directory."""
        return os.path.dirname(os.path.abspath(__file__))

    @classmethod
    def _load_prompt(cls, relative_path: str) -> str:
        """Load a prompt from a file, using cache if available.

        Args:
            relative_path: Relative path from prompts directory

        Returns:
            Prompt content as string

        Raises:
            FileNotFoundError: If prompt file doesn't exist
            IOError: If there's an error reading the file
        """
        if relative_path in cls._cache:
            return cls._cache[relative_path]

        prompts_dir = cls._get_prompts_dir()
        file_path = os.path.join(prompts_dir, relative_path)

        if not os.path.exists(file_path):
            print(
                f"{Fore.RED}Error: Prompt file not found: {file_path}{Style.RESET_ALL}"
            )
            raise FileNotFoundError(f"Prompt file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                cls._cache[relative_path] = content
                return content
        except Exception as e:
            print(
                f"{Fore.RED}Error loading prompt from {file_path}: {e}{Style.RESET_ALL}"
            )
            raise

    @classmethod
    def get_orchestrator_prompt(cls, prompt_name: str) -> str:
        """Get an orchestrator prompt by name.

        Args:
            prompt_name: Name of the orchestrator prompt (without .txt extension)

        Returns:
            Prompt content

        Examples:
            get_orchestrator_prompt("system")
            get_orchestrator_prompt("info_vs_exec_analysis")
        """
        file_path = f"orchestrator/{prompt_name}.txt"
        return cls._load_prompt(file_path)

    @classmethod
    def get_agent_prompt(cls, agent: str, prompt_name: str) -> str:
        """Get an agent-specific prompt.

        Args:
            agent: Agent name (nmap, wpscan, nikto, metasploit, etc.)
            prompt_name: Name of the prompt (without .txt extension)

        Returns:
            Prompt content

        Examples:
            get_agent_prompt("nmap", "system")
            get_agent_prompt("wpscan", "parsing")
        """
        file_path = f"agents/{agent}_{prompt_name}.txt"
        return cls._load_prompt(file_path)

    @classmethod
    def get_initial_agent_task(cls, agent: str, task_type: str) -> str:
        """Get an initial agent task prompt.

        Args:
            agent: Agent name (nmap, wpscan, nikto)
            task_type: Type of task (exploit, direct)

        Returns:
            Prompt content

        Examples:
            get_initial_agent_task("nmap", "exploit")
            get_initial_agent_task("wpscan", "direct")
        """
        file_path = f"orchestrator/initial_agent_tasks/{agent}_{task_type}.txt"
        return cls._load_prompt(file_path)

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the prompt cache (useful for development/testing)."""
        cls._cache.clear()

    @classmethod
    def reload_prompt(cls, relative_path: str) -> str:
        """Force reload a prompt from file, bypassing cache.

        Args:
            relative_path: Relative path from prompts directory

        Returns:
            Freshly loaded prompt content
        """
        if relative_path in cls._cache:
            del cls._cache[relative_path]
        return cls._load_prompt(relative_path)
