from __future__ import annotations

from pathlib import Path

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.tw.contracts._0_8_9.StakingRouter import StakingRouter
from pytypes.migrated.nos.NodeOperatorsRegistry import NodeOperatorsRegistry
from pytypes.migrated.aragon.os.contracts.acl.ACL import ACL
from pytypes.migrated.aragon.os.contracts.kernel.Kernel import Kernel

from pytypes.csm.src.CSExitPenalties import CSExitPenalties
from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSStrikes import CSStrikes
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.tw.contracts._0_8_9.StakingRouter import StakingRouter

from .csm import (
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
    LIDO_LOCATOR,
)

from .nor import LIDO_LOCATOR, deploy_nor
from .tw import TriggerableWithdrawalsFuzzTest

acl_code = bytes.fromhex((Path(__file__).parent.parent.parent / "bin" / "ACL.bin").read_text())
kernel_code = bytes.fromhex((Path(__file__).parent.parent.parent / "bin" / "Kernel.bin").read_text())


class LidoNoUpgradeFuzzTest(TriggerableWithdrawalsFuzzTest):
    def _deploy_or_upgrade(self):
        self.nor_id = self.staking_router.getStakingModulesCount() + 1

        acl_template = ACL(chain.deploy(acl_code))
        acl_template.pytypes_resolver = ACL
        kernel = Kernel(chain.deploy(kernel_code + abi.encode(False), from_=self.admin))
        kernel.pytypes_resolver = Kernel
        kernel.initialize(acl_template, self.admin, from_=self.admin)
        kernel_acl = ACL(kernel.acl())
        kernel_acl.createPermission(
            self.admin, kernel, kernel.APP_MANAGER_ROLE(), self.admin, from_=self.admin
        )

        nor_impl = deploy_nor()
        self.nor = NodeOperatorsRegistry(
            kernel.newAppInstance(
                random_bytes(32), nor_impl, from_=self.admin
            ).return_value
        )
        self.nor.pytypes_resolver = NodeOperatorsRegistry
        self.nor.initialize(LIDO_LOCATOR, random_bytes(32), self.nor_exit_delay_threshold)

        kernel_acl.createPermission(
            self.admin,
            self.nor,
            self.nor.MANAGE_NODE_OPERATOR_ROLE(),
            self.admin,
            from_=self.admin,
        )
        kernel_acl.createPermission(
            self.admin,
            self.nor,
            self.nor.SET_NODE_OPERATOR_LIMIT_ROLE(),
            self.admin,
            from_=self.admin,
        )
        kernel_acl.createPermission(
            self.staking_router,
            self.nor,
            self.nor.STAKING_ROUTER_ROLE(),
            self.admin,
            from_=self.admin,
        )

        tx = self.staking_router.addStakingModule(
            "NOR",
            self.nor,
            5_000,
            5_000,
            0,
            0,
            100,
            1,
            from_=self.admin,
        )
        assert self.nor_id == next(
            e.stakingModuleId
            for e in tx.events
            if isinstance(e, StakingRouter.StakingModuleAdded)
        )

    def _csm_deploy_or_upgrade(self):
        self.csm_id = self.staking_router.getStakingModulesCount() + 1

        Account(1).code = b"\xaa"

        self.accounting = CSAccounting(
            OssifiableProxy.deploy(Account(1), self.admin, b"")
        )
        self.csm = CSModule(
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
                LIDO_LOCATOR,
                self.csm,
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

        OssifiableProxy(self.csm).proxy__upgradeToAndCall(
            CSModule.deploy(
                MODULE_TYPE,
                LIDO_LOCATOR,
                self.parameters_registry,
                self.accounting,
                self.exit_penalties,
            ),
            abi.encode_call(CSModule.initialize, [self.admin]),
            from_=self.admin,
        )
        self.csm.grantRole(
            self.csm.RESUME_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.csm.resume(from_=self.admin)

        OssifiableProxy(self.exit_penalties).proxy__upgradeToAndCall(
            CSExitPenalties.deploy(
                self.csm, self.parameters_registry, self.strikes
            ),
            b"",
            from_=self.admin,
        )

        OssifiableProxy(self.strikes).proxy__upgradeToAndCall(
            CSStrikes.deploy(
                self.csm, self.fee_oracle, self.exit_penalties, self.parameters_registry
            ),
            b"",
            from_=self.admin,
        )

        Account(1).code = b""

        tx = self.staking_router.addStakingModule(
            "CSM",
            self.csm,
            5_000,
            5_000,
            0,
            0,
            100,
            1,
            from_=self.admin,
        )
        assert self.csm_id == next(
            e.stakingModuleId
            for e in tx.events
            if isinstance(e, StakingRouter.StakingModuleAdded)
        )


@chain.connect(fork="http://localhost:8545@22576118", accounts=50)
def test_lido():
    LidoNoUpgradeFuzzTest().run(100, 100_000)
