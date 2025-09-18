import os
from typing import Dict, Optional, List
import google.generativeai as genai


class MitigationGenerator:
    """Generate actionable mitigation steps using Google Gemini API."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        """
        Initialize the mitigation generator.

        Args:
            api_key: Gemini API key (can also be set via GEMINI_API_KEY env var)
            model: Gemini model to use (default: gemini-2.5-flash)
        """
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model
        self.model = None

        if self.api_key:
            self._initialize_client()

    def _initialize_client(self):
        """Initialize the Gemini client."""
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        except Exception as e:
            print(f"Failed to initialize Gemini client: {e}")
            self.model = None

    def generate_mitigation_steps(
        self,
        cve_id: str,
        cve_description: str,
        affected_software: str,
        severity: str = "UNKNOWN",
    ) -> Dict[str, any]:
        """
        Generate mitigation steps for a validated CVE.

        Args:
            cve_id: The CVE identifier
            cve_description: Full description of the vulnerability
            affected_software: Software name and version (from CPE)
            severity: CVE severity level

        Returns:
            Dict with mitigation steps and metadata
        """
        if not self.model:
            return {"error": "Gemini API not configured", "steps": []}

        # Create a focused prompt for actionable mitigation steps
        prompt = f"""You are a security expert providing mitigation guidance.

CVE: {cve_id}
Severity: {severity}
Affected Software: {affected_software}
Description: {cve_description}

Provide a concise, actionable checklist of 3-5 mitigation steps for system administrators.
Focus on immediate, practical actions. Format as a numbered list.
Each step should be one clear action item, not more than 2 lines.
Prioritize patching/updating if available, then workarounds.

Don't give in markdown, just plain text.
Response format:
1. [Action]
2. [Action]
3. [Action]
"""

        try:
            response = self.model.generate_content(prompt)

            # Parse the response into structured steps
            steps = self._parse_mitigation_steps(response.text)

            return {
                "cve_id": cve_id,
                "affected_software": affected_software,
                "severity": severity,
                "steps": steps,
                "raw_response": response.text,
            }

        except Exception as e:
            return {"error": f"Failed to generate mitigation: {str(e)}", "steps": []}

    def _parse_mitigation_steps(self, response_text: str) -> List[str]:
        """Parse the Gemini response into a list of mitigation steps."""
        steps = []

        # Split by newlines and look for numbered items
        lines = response_text.strip().split("\n")

        for line in lines:
            line = line.strip()
            # Check if line starts with a number followed by period or parenthesis
            if line and (
                (line[0].isdigit() and len(line) > 2 and line[1] in ".)")
                or line.startswith("-")
                or line.startswith("*")
            ):
                # Remove the number/bullet and clean up
                if line[0].isdigit():
                    step = (
                        line.split(".", 1)[1].strip()
                        if "." in line
                        else line.split(")", 1)[1].strip()
                    )
                else:
                    step = line[1:].strip()

                if step:
                    steps.append(step)

        # If no numbered steps found, try to extract meaningful lines
        if not steps:
            for line in lines:
                line = line.strip()
                if line and len(line) > 10 and not line.endswith(":"):
                    steps.append(line)

        # Limit to 5 steps
        return steps[:5]

    def generate_batch_mitigations(self, cve_list: List[Dict]) -> Dict[str, Dict]:
        """
        Generate mitigations for multiple CVEs.

        Args:
            cve_list: List of CVE dictionaries with id, description, software info

        Returns:
            Dict mapping CVE IDs to mitigation results
        """
        results = {}

        for cve in cve_list:
            cve_id = cve.get("cve_id")
            if cve_id:
                result = self.generate_mitigation_steps(
                    cve_id=cve_id,
                    cve_description=cve.get("description", ""),
                    affected_software=cve.get("affected_software", ""),
                    severity=cve.get("severity", "UNKNOWN"),
                )
                results[cve_id] = result

        return results


# Example usage and testing
if __name__ == "__main__":
    # Test with a sample CVE
    generator = MitigationGenerator()

    test_cve = {
        "cve_id": "CVE-2016-20012",
        "description": "OpenSSH through 8.7 allows remote attackers to test username/key combinations",
        "affected_software": "OpenSSH 8.7",
        "severity": "MEDIUM",
    }

    if generator.api_key:
        result = generator.generate_mitigation_steps(
            cve_id=test_cve["cve_id"],
            cve_description=test_cve["description"],
            affected_software=test_cve["affected_software"],
            severity=test_cve["severity"],
        )

        print(f"Mitigation for {test_cve['cve_id']}:")
        if "error" in result:
            print(f"  Error: {result['error']}")
        else:
            for i, step in enumerate(result["steps"], 1):
                print(f"  {i}. {step}")
    else:
        print("No Gemini API key found. Set GEMINI_API_KEY environment variable.")
