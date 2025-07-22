from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.csm.src.CSExitPenalties import CSExitPenalties
from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSStrikes import CSStrikes
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy

from .test_fuzz import (
    CSMFuzzTest,
    MODULE_TYPE,
    ST_ETH,
    MIN_BOND_LOCK_PERIOD,
    MAX_BOND_LOCK_PERIOD,
    SECONDS_PER_SLOT,
    GENESIS_TIME,
    CONSENSUS_VERSION,
    SLOTS_PER_EPOCH,
    EPOCHS_PER_FRAME,
    FAST_LANE_LENGTH_SLOTS,
)


class CSMNoUpgradeFuzzTest(CSMFuzzTest):
    def _deploy_or_upgrade(self):
        Account(1).code = b"\xaa"

        self.accounting = CSAccounting(
            OssifiableProxy.deploy(Account(1), self.admin, b"")
        )
        self.module = CSModule(
            OssifiableProxy.deploy(Account(1), self.admin, b"")
        )

        self.fee_distributor = CSFeeDistributor(OssifiableProxy.deploy(Account(1), self.admin, b""))

        self.fee_oracle = CSFeeOracle(OssifiableProxy.deploy(Account(1), self.admin, b""))

        self.exit_penalties = CSExitPenalties(OssifiableProxy.deploy(Account(1), self.admin, b""))

        self.strikes = CSStrikes(OssifiableProxy.deploy(Account(1), self.admin, b""))

        self.hash_consensus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            self.fee_oracle,
        )

        OssifiableProxy(self.fee_oracle).proxy__upgradeToAndCall(
            CSFeeOracle.deploy(
                self.fee_distributor,
                self.strikes,
                SECONDS_PER_SLOT,
                GENESIS_TIME,
            ),
            abi.encode_call(CSFeeOracle.initialize, [self.admin, self.hash_consensus, CONSENSUS_VERSION]),
            from_=self.admin,
        )

        OssifiableProxy(self.accounting).proxy__upgradeToAndCall(
            CSAccounting.deploy(
                self.mock_locator,
                self.module,
                self.fee_distributor,
                MIN_BOND_LOCK_PERIOD,
                MAX_BOND_LOCK_PERIOD,
            ),
            abi.encode_call(CSAccounting.initialize, [self.curves[0], self.admin, self.bond_lock_period, self.charge_penalty_recipient]),
            from_=self.admin,
        )
        # add vetted bond curve
        self.accounting.grantRole(
            self.accounting.MANAGE_BOND_CURVES_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.accounting.addBondCurve(self.curves[1], from_=self.admin)

        OssifiableProxy(self.fee_distributor).proxy__upgradeToAndCall(
            CSFeeDistributor.deploy(
                ST_ETH,
                self.accounting,
                self.fee_oracle,
            ),
            abi.encode_call(CSFeeDistributor.initialize, [self.admin, self.rebate_recipient]),
            from_=self.admin,
        )

        OssifiableProxy(self.module).proxy__upgradeToAndCall(
            CSModule.deploy(
                MODULE_TYPE,
                self.mock_locator,
                self.parameters_registry,
                self.accounting,
                self.exit_penalties,
            ),
            abi.encode_call(CSModule.initialize, [self.admin]),
            from_=self.admin,
        )
        self.module.grantRole(
            self.module.RESUME_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.module.resume(from_=self.admin)

        OssifiableProxy(self.exit_penalties).proxy__upgradeToAndCall(
            CSExitPenalties.deploy(
                self.module, self.parameters_registry, self.strikes
            ),
            b"",
            from_=self.admin,
        )

        OssifiableProxy(self.strikes).proxy__upgradeToAndCall(
            CSStrikes.deploy(
                self.module, self.fee_oracle, self.exit_penalties, self.parameters_registry
            ),
            b"",
            from_=self.admin,
        )

        Account(1).code = b""


@chain.connect(fork="http://localhost:8545@22576118", accounts=50)
def test_no_upgrade_fuzz():
    CSMNoUpgradeFuzzTest().run(100, 100_000)
