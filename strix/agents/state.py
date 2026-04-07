from typing import Any

from pydantic import BaseModel, Field


class AgentState(BaseModel):
    """Base state for agents, designed to be serializable."""

    target: str
    instruction: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: str = "initialized"
    current_step: int = 0
    max_steps: int = 50

    class Config:
        arbitrary_types_allowed = True
