import logging
from abc import ABC, abstractmethod
from typing import Any

from strix.agents.state import AgentState
from strix.llm import LLM


logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all security agents."""

    def __init__(self, llm: LLM, state: AgentState):
        self.llm = llm
        self.state = state
        self.agent_name = self.__class__.__name__
        self.llm.set_agent_identity(self.agent_name, id(self))

    @abstractmethod
    async def run(self) -> AgentState:
        """Run the agent's main execution loop."""
        pass

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a security finding to the agent's state."""
        self.state.findings.append(finding)
        logger.info(f"[{self.agent_name}] New finding added: {finding.get('title', 'Untitled')}")

    def update_status(self, status: str) -> None:
        """Update the agent's current status."""
        self.state.status = status
        logger.debug(f"[{self.agent_name}] Status updated to: {status}")
