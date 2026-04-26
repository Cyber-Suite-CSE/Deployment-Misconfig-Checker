"""V1 baseline: single agent with all security tools attached.

This is the deliberately monolithic design described in the paper as the
predecessor to V2. It exists so that V1 vs. V2 metrics can be measured under
the same target, prompt, and tool implementations.
"""

from v1.single_agent import SingleSecurityAgent

__all__ = ["SingleSecurityAgent"]
