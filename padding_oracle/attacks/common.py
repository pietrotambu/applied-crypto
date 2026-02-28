from __future__ import annotations

from typing import Callable


class AttackError(RuntimeError):
    pass


BoolOracle = Callable[[bytes], bool]
TimingOracle = Callable[[bytes], int]
