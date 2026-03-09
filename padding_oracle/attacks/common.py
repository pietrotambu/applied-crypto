"""Shared exception and oracle callable types for attacks."""

from __future__ import annotations

from typing import Callable


class AttackError(RuntimeError):
    """Raised when an attack cannot recover plaintext under current assumptions."""


# Oracle types shared by attack implementations.
BoolOracle = Callable[[bytes], bool]
TimingOracle = Callable[[bytes], int]
