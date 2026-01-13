"""Intent lifecycle and status transition management."""

from typing import Set


class InvalidTransitionError(Exception):
    """Raised when an invalid status transition is attempted."""

    def __init__(self, from_status: str, to_status: str):
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Invalid transition from '{from_status}' to '{to_status}'"
        )


class IntentLifecycle:
    """Manages intent status transitions.

    Status flow:
        pending → solving → solved → deploying → deployed → verifying → active
                    ↓          ↓           ↓            ↓
                  failed    failed      failed       failed

    States:
        - pending: Intent created, awaiting solver
        - solving: Z3 solver is computing paths
        - solved: Paths computed, ready for config generation
        - deploying: Configs being pushed to devices
        - deployed: Configs pushed, awaiting verification
        - verifying: Checking BGP/BFD sessions
        - active: Intent fully deployed and verified
        - failed: Any step failed (terminal)
    """

    # Define valid transitions: from_status -> set of valid to_statuses
    TRANSITIONS: dict[str, Set[str]] = {
        "pending": {"solving"},
        "solving": {"solved", "failed"},
        "solved": {"deploying"},
        "deploying": {"deployed", "failed"},
        "deployed": {"verifying"},
        "verifying": {"active", "failed"},
        "active": set(),  # Terminal state
        "failed": set(),  # Terminal state
    }

    TERMINAL_STATES = {"active", "failed"}

    def can_transition(self, from_status: str, to_status: str) -> bool:
        """Check if a transition is valid."""
        valid_targets = self.TRANSITIONS.get(from_status, set())
        return to_status in valid_targets

    def transition(self, from_status: str, to_status: str) -> str:
        """Perform a status transition with validation.

        Args:
            from_status: Current status
            to_status: Desired new status

        Returns:
            The new status

        Raises:
            InvalidTransitionError: If the transition is not allowed
        """
        if not self.can_transition(from_status, to_status):
            raise InvalidTransitionError(from_status, to_status)
        return to_status

    def next_statuses(self, current_status: str) -> list[str]:
        """Get the list of valid next statuses from current state."""
        return list(self.TRANSITIONS.get(current_status, set()))

    def is_terminal(self, status: str) -> bool:
        """Check if a status is terminal (no further transitions)."""
        return status in self.TERMINAL_STATES


# Singleton instance for convenience
lifecycle = IntentLifecycle()
