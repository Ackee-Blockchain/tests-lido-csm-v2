from __future__ import annotations

from wake.testing import *
from wake.testing.fuzzing import *

from .tw import TriggerableWithdrawalsFuzzTest

class LidoFuzzTest(TriggerableWithdrawalsFuzzTest):
    pass


@chain.connect(fork="http://localhost:8545@22576118", accounts=50)
def test_lido():
    LidoFuzzTest().run(100, 100_000)
