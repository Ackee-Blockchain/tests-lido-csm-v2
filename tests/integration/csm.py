from __future__ import annotations

import itertools
import logging
import math
from collections import deque, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *
from typing import Callable, TYPE_CHECKING

from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.PermissionlessGate import PermissionlessGate
from pytypes.csm.src.CSParametersRegistry import CSParametersRegistry
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSExitPenalties import CSExitPenalties
from pytypes.csm.src.CSStrikes import CSStrikes
from pytypes.csm.src.CSEjector import CSEjector
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.VettedGate import VettedGate
from pytypes.csm.src.VettedGateFactory import VettedGateFactory
from pytypes.csm.src.CSVerifier import CSVerifier
from pytypes.csm.src.interfaces.ICSExitPenalties import ExitPenaltyInfo, MarkedUint248
from pytypes.csm.src.interfaces.ICSModule import NodeOperatorManagementProperties
from pytypes.csm.src.interfaces.IWithdrawalQueue import IWithdrawalQueue
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.Types import BeaconBlockHeader, Withdrawal, Validator
from pytypes.csm.src.lib.NOAddresses import NOAddresses
from pytypes.csm.src.lib.QueueLib import QueueLib
from pytypes.csm.src.interfaces.IStETH import IStETH
from pytypes.csm.src.interfaces.IWstETH import IWstETH
from pytypes.csm.src.interfaces.IBurner import IBurner
from pytypes.csm.src.interfaces.ILidoLocator import ILidoLocator
from pytypes.csm.src.interfaces.IStakingRouter import IStakingRouter
from pytypes.csm.src.interfaces.ITriggerableWithdrawalsGateway import (
    ITriggerableWithdrawalsGateway,
)
from pytypes.csm.node_modules.openzeppelin.contracts.token.ERC20.extensions.IERC20Permit import (
    IERC20Permit,
)
from pytypes.tw.contracts._0_8_9.TriggerableWithdrawalsGateway import TriggerableWithdrawalsGateway
from pytypes.tests.IEIP712 import IEIP712

from ..merkle_tree import MerkleTree
from .common import *

if TYPE_CHECKING:
    from .tw import ExitLimitsInfo

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

QUEUE_LOWEST_PRIORITY = 5
MODULE_TYPE = random_bytes(32)
CONSENSUS_VERSION = 1
DEFAULT_CURVE_ID = uint(0)
VETTED_CURVE_ID = uint(1)
MIN_BOND_LOCK_PERIOD = 4 * 7 * 24 * 60 * 60  # 4 weeks
MAX_BOND_LOCK_PERIOD = 365 * 24 * 60 * 60  # 365 days
FAST_LANE_LENGTH_SLOTS = 0
HISTORICAL_SUMMARIES_COUNT = 2**16

LIDO_LOCATOR = ILidoLocator("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
ST_ETH = IStETH("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
WST_ETH = IWstETH("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0")
UNST_ETH = IWithdrawalQueue("0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1")
BURNER: IBurner
STAKING_ROUTER: IStakingRouter
EL_REWARDS_VAULT: Account

ORIGINAL_ADMIN = Account("0x3e40d73eb977dc6a537af587d48316fee66e9c8c")

DEFAULT_PARAMETERS = CSParametersRegistry.InitializationData(
    keyRemovalCharge=Wei.from_ether(0.05),
    elRewardsStealingAdditionalFine=Wei.from_ether(0.1),
    keysLimit=uint256.max,
    performanceLeeway=450,
    rewardShare=10000,
    strikesLifetime=6,
    strikesThreshold=3,
    defaultQueuePriority=QUEUE_LOWEST_PRIORITY,
    defaultQueueMaxDeposits=uint32.max,
    badPerformancePenalty=Wei.from_ether(0.1),
    attestationsWeight=54,
    blocksWeight=8,
    syncWeight=2,
    defaultAllowedExitDelay=4 * 24 * 60 * 60,  # 4 days
    defaultExitDelayPenalty=Wei.from_ether(0.1),
    defaultMaxWithdrawalRequestFee=Wei.from_ether(0.1),
)

MAX_WITHDRAWAL_EXCESS = 700


def hash_beacon_block_header(header: BeaconBlockHeader) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    for leaf in [
        header.slot.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        header.proposerIndex.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        header.parentRoot,
        header.stateRoot,
        header.bodyRoot,
        bytes32(0),  # dummy for power of 2 number of leaves
        bytes32(0),  # dummy for power of 2 number of leaves
        bytes32(0),  # dummy for power of 2 number of leaves
    ]:
        tree.add_leaf(leaf)
    return tree.root


def hash_validator(validator: Validator) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)

    pubkey_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    pubkey_tree.add_leaf(validator.pubkey[:32])
    pubkey_tree.add_leaf(validator.pubkey[32:] + b"\x00" * 16)

    for leaf in [
        pubkey_tree.root,
        validator.withdrawalCredentials,
        validator.effectiveBalance.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.slashed.to_bytes(1, "little") + b"\x00" * 31,  # bool
        validator.activationEligibilityEpoch.to_bytes(8, "little")
        + b"\x00" * 24,  # uint64
        validator.activationEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.exitEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.withdrawableEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
    ]:
        tree.add_leaf(leaf)
    return tree.root


def hash_withdrawal(withdrawal: Withdrawal) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    for leaf in [
        withdrawal.index.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        withdrawal.validatorIndex.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        bytes(withdrawal.withdrawalAddress) + b"\x00" * 12,
        withdrawal.amount.to_bytes(8, "little") + b"\x00" * 24,  # uint64
    ]:
        tree.add_leaf(leaf)
    return tree.root


def random_bond_curve() -> list[CSAccounting.BondCurveIntervalInput]:
    def random_trend():
        return random_int(100, 1000) * 10**16  # 1 - 10 ETH

    curve: list[CSAccounting.BondCurveIntervalInput] = []

    count = random_int(1, 10)
    curve.append(CSAccounting.BondCurveIntervalInput(1, random_trend()))
    for _ in range(count - 1):
        curve.append(
            CSAccounting.BondCurveIntervalInput(
                curve[-1].minKeysCount + random_int(1, 10), random_trend()
            )
        )

    return curve


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint
    nonce: uint
    deadline: uint


@dataclass
class NodeOperator:
    id: uint
    curve_id: uint
    keys: list[bytes]
    signatures: list[bytes]
    manager: Account
    rewards_account: Account
    extended_permissions: bool
    target_limit: uint
    target_limit_mode: uint
    bond_shares: uint  # in stETH shares
    total_rewards: uint  # in stETH shares
    claimed_rewards: uint  # in stETH shares
    total_keys: uint
    withdrawn_keys: uint
    deposited_keys: uint
    vetted_keys: uint
    stuck_keys: uint
    exited_keys: uint
    locked_bond: uint  # in ETH
    lock_expiry: uint  # timestamp
    withdrawn: dict[int, bool]  # validator key index -> withdrawn
    key_strikes: dict[int, list[int]]  # key index -> strike counts
    used_priority_queue: bool
    strikes_penalties: dict[int, uint | None]  # key index -> penalty
    withdrawal_request_fees: dict[int, uint | None]  # key index -> fee
    exit_delay_penalties: dict[int, uint | None]  # key index -> penalty


@dataclass
class QueueItem:
    no_id: uint
    keys_count: uint


class Parameters:
    _key_removal_charge: int | None
    _el_rewards_stealing_additional_fine: int | None
    _keys_limit: int | None
    _strikes_lifetime: int
    _strikes_threshold: int
    _bad_performance_penalty: int | None
    _queue_priority: int
    _queue_max_deposits: int
    _allowed_exit_delay: int
    _exit_delay_penalty: int | None
    _max_withdrawal_request_fee: int | None

    def __init__(self):
        self._key_removal_charge = None
        self._el_rewards_stealing_additional_fine = None
        self._keys_limit = None
        self._strikes_lifetime = 0
        self._strikes_threshold = 0
        self._bad_performance_penalty = None
        self._queue_priority = 0
        self._queue_max_deposits = 0
        self._allowed_exit_delay = 0
        self._exit_delay_penalty = None
        self._max_withdrawal_request_fee = None

    @property
    def key_removal_charge(self) -> int:
        if self._key_removal_charge is None:
            return DEFAULT_PARAMETERS.keyRemovalCharge
        return self._key_removal_charge

    @key_removal_charge.setter
    def key_removal_charge(self, value: int | None):
        self._key_removal_charge = value

    @property
    def el_rewards_stealing_additional_fine(self) -> int:
        if self._el_rewards_stealing_additional_fine is None:
            return DEFAULT_PARAMETERS.elRewardsStealingAdditionalFine
        return self._el_rewards_stealing_additional_fine

    @el_rewards_stealing_additional_fine.setter
    def el_rewards_stealing_additional_fine(self, value: int | None):
        self._el_rewards_stealing_additional_fine = value

    @property
    def keys_limit(self) -> int:
        if self._keys_limit is None:
            return DEFAULT_PARAMETERS.keysLimit
        return self._keys_limit

    @keys_limit.setter
    def keys_limit(self, value: int | None):
        self._keys_limit = value

    @property
    def strikes_info(self) -> tuple[int, int]:
        if self._strikes_threshold == 0:
            return (
                DEFAULT_PARAMETERS.strikesLifetime,
                DEFAULT_PARAMETERS.strikesThreshold,
            )
        return self._strikes_lifetime, self._strikes_threshold

    @strikes_info.setter
    def strikes_info(self, value: tuple[int, int]):
        self._strikes_lifetime = value[0]
        self._strikes_threshold = value[1]

    @property
    def bad_performance_penalty(self) -> int:
        if self._bad_performance_penalty is None:
            return DEFAULT_PARAMETERS.badPerformancePenalty
        return self._bad_performance_penalty

    @bad_performance_penalty.setter
    def bad_performance_penalty(self, value: int | None):
        self._bad_performance_penalty = value

    @property
    def queue_config(self) -> tuple[int, int]:
        if self._queue_max_deposits == 0:
            return (
                DEFAULT_PARAMETERS.defaultQueuePriority,
                DEFAULT_PARAMETERS.defaultQueueMaxDeposits,
            )
        return self._queue_priority, self._queue_max_deposits

    @queue_config.setter
    def queue_config(self, value: tuple[int, int]):
        self._queue_priority = value[0]
        self._queue_max_deposits = value[1]

    @property
    def allowed_exit_delay(self) -> int:
        if self._allowed_exit_delay == 0:
            return DEFAULT_PARAMETERS.defaultAllowedExitDelay
        return self._allowed_exit_delay

    @allowed_exit_delay.setter
    def allowed_exit_delay(self, value: int):
        self._allowed_exit_delay = value

    @property
    def exit_delay_penalty(self) -> int:
        if self._exit_delay_penalty is None:
            return DEFAULT_PARAMETERS.defaultExitDelayPenalty
        return self._exit_delay_penalty

    @exit_delay_penalty.setter
    def exit_delay_penalty(self, value: int | None):
        self._exit_delay_penalty = value

    @property
    def max_withdrawal_request_fee(self) -> int:
        if self._max_withdrawal_request_fee is None:
            return DEFAULT_PARAMETERS.defaultMaxWithdrawalRequestFee
        return self._max_withdrawal_request_fee

    @max_withdrawal_request_fee.setter
    def max_withdrawal_request_fee(self, value: int | None):
        self._max_withdrawal_request_fee = value


class CSMFuzzTest(FuzzTest):
    rebate_recipient: Account
    parameters_registry: CSParametersRegistry
    accounting: CSAccounting
    exit_penalties: CSExitPenalties
    strikes: CSStrikes
    ejector: CSEjector
    fee_oracle: CSFeeOracle
    fee_distributor: CSFeeDistributor
    csm: CSModule
    permissionless_gate: PermissionlessGate
    vetted_gate: VettedGate
    vetted_gate_factory: VettedGateFactory
    verifier: CSVerifier

    # to be set in tw.py
    admin: Account
    csm_id: int
    triggerable_withdrawals_gateway: ITriggerableWithdrawalsGateway
    withdrawal_vault: Account
    tw_limits: ExitLimitsInfo
    staking_router: IStakingRouter
    _calculate_current_exit_limit: Callable[[ExitLimitsInfo, int], int]
    _update_tw_exit_limits: Callable[[int, int, int], None]

    hash_consensus: HashConsensus

    steth_domain: Eip712Domain
    wsteth_domain: Eip712Domain

    vetted_tree: MerkleTree
    vetted_accounts: OrderedSet[Account]
    claimed_vetted_accounts: OrderedSet[Account]
    queue: list[deque[QueueItem]]
    consensus_members: OrderedSet[Account]
    consensus_quorum: int
    initial_epoch: int
    last_report_ref_slot: int

    rewards_tree: MerkleTree
    strikes_tree: MerkleTree

    curves: List[List[CSAccounting.BondCurveIntervalInput]]
    csm_node_operators: dict[uint, NodeOperator]
    bond_lock_period: uint256
    charge_penalty_recipient: Account

    parameters: dict[int, Parameters]

    balances: dict[Account, uint]
    shares: dict[Account, uint]

    distribution_history: list[CSFeeDistributor.DistributionData]

    no_id: uint
    nonce: uint

    vetted_season_active: bool
    vetted_referrals: dict[Account, uint]
    referral_season_id: int
    referral_season_threshold: int
    referral_season_curve_id: int
    claimed_referrers: OrderedSet[Account]

    def _csm_deploy_or_upgrade(self):
        # use forked proxies
        self.csm = CSModule("0xdA7dE2ECdDfccC6c3AF10108Db212ACBBf9EA83F")
        self.accounting = CSAccounting("0x4d72BFF1BeaC69925F8Bd12526a39BAAb069e5Da")
        self.fee_oracle = CSFeeOracle("0x4D4074628678Bd302921c20573EEa1ed38DdF7FB")
        self.fee_distributor = CSFeeDistributor(
            "0xD99CC66fEC647E68294C6477B40fC7E0F6F618D0"
        )

        # find CSM id
        all_modules = self.staking_router.getStakingModules()
        self.csm_id = next(m.id for m in all_modules if m.stakingModuleAddress == self.csm.address)

        # migrate deposit queue
        destination_queue = self.queue[QUEUE_LOWEST_PRIORITY - 1]
        head, tail = abi.decode(
            self.csm.call(abi.encode_with_signature("depositQueue()")),
            [uint128, uint128],
        )
        for i in range(head, tail):
            item = abi.decode(
                self.csm.call(
                    abi.encode_with_signature("depositQueueItem(uint128)", uint128(i))
                ),
                [uint],
            )
            destination_queue.append(
                QueueItem(item >> 192, keys_count=(item >> 128) & 0xFFFFFFFFFFFFFFFF)
            )

        # temporarily point to CSM
        # there is a limitation than implementation address must be a contract
        self.strikes = CSStrikes(OssifiableProxy.deploy(self.csm, self.admin, b""))

        self.exit_penalties = CSExitPenalties(
            OssifiableProxy.deploy(
                CSExitPenalties.deploy(self.csm, self.parameters_registry, self.strikes),
                self.admin,
                b"",
            )
        )

        OssifiableProxy(self.strikes).proxy__upgradeTo(
            CSStrikes.deploy(
                self.csm,
                self.fee_oracle,
                self.exit_penalties,
                self.parameters_registry,
            ),
            from_=self.admin,
        )

        OssifiableProxy(self.csm).proxy__changeAdmin(
            self.admin, from_=OssifiableProxy(self.csm).proxy__getAdmin()
        )
        OssifiableProxy(self.accounting).proxy__changeAdmin(
            self.admin, from_=OssifiableProxy(self.accounting).proxy__getAdmin()
        )
        OssifiableProxy(self.fee_oracle).proxy__changeAdmin(
            self.admin, from_=OssifiableProxy(self.fee_oracle).proxy__getAdmin()
        )
        OssifiableProxy(self.fee_distributor).proxy__changeAdmin(
            self.admin, from_=OssifiableProxy(self.fee_distributor).proxy__getAdmin()
        )

        OssifiableProxy(self.csm).proxy__upgradeToAndCall(
            CSModule.deploy(
                MODULE_TYPE,
                LIDO_LOCATOR,
                self.parameters_registry,
                self.accounting,
                self.exit_penalties,
            ),
            abi.encode_call(CSModule.finalizeUpgradeV2, []),
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
            abi.encode_call(CSAccounting.finalizeUpgradeV2, [self.curves]),
            from_=self.admin,
        )
        OssifiableProxy(self.fee_oracle).proxy__upgradeToAndCall(
            CSFeeOracle.deploy(
                self.fee_distributor, self.strikes, SECONDS_PER_SLOT, GENESIS_TIME
            ),
            abi.encode_call(CSFeeOracle.finalizeUpgradeV2, [CONSENSUS_VERSION]),
            from_=self.admin,
        )
        OssifiableProxy(self.fee_distributor).proxy__upgradeToAndCall(
            CSFeeDistributor.deploy(ST_ETH, self.accounting, self.fee_oracle),
            abi.encode_call(
                CSFeeDistributor.finalizeUpgradeV2, [self.rebate_recipient]
            ),
            from_=self.admin,
        )

        # new HashConsensus deployed for the ease of testing
        self.hash_consensus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            self.fee_oracle,
        )

        self.csm.grantRole(
            self.csm.DEFAULT_ADMIN_ROLE(), self.admin, from_=ORIGINAL_ADMIN
        )
        self.accounting.grantRole(
            self.accounting.DEFAULT_ADMIN_ROLE(), self.admin, from_=ORIGINAL_ADMIN
        )
        self.fee_oracle.grantRole(
            self.fee_oracle.DEFAULT_ADMIN_ROLE(), self.admin, from_=ORIGINAL_ADMIN
        )
        self.fee_distributor.grantRole(
            self.fee_distributor.DEFAULT_ADMIN_ROLE(), self.admin, from_=ORIGINAL_ADMIN
        )

    def pre_sequence(self) -> None:
        global BURNER, STAKING_ROUTER, EL_REWARDS_VAULT

        AssetRecovererLib.deploy()
        NOAddresses.deploy()
        QueueLib.deploy()

        domain = IEIP712(ST_ETH).eip712Domain()
        self.steth_domain = Eip712Domain(
            name=domain[0],
            version=domain[1],
            chainId=domain[2],
            verifyingContract=domain[3],
        )
        self.wsteth_domain = Eip712Domain(
            name="Wrapped liquid staked Ether 2.0",
            version="1",
            chainId=1,
            verifyingContract=WST_ETH,
        )

        self.rebate_recipient = random_account()
        self.charge_penalty_recipient = random_account()
        self.vetted_season_active = False
        self.vetted_referrals = defaultdict(int)
        self.referral_season_id = 0
        self.referral_season_threshold = -1
        self.referral_season_curve_id = -1
        self.claimed_referrers = OrderedSet([])
        self.vetted_tree = MerkleTree()
        self.vetted_accounts = OrderedSet(random.sample(chain.accounts, 20))
        self.claimed_vetted_accounts = OrderedSet([])
        for acc in self.vetted_accounts:
            self.vetted_tree.add_leaf(
                keccak256(abi.encode(acc))
            )  # empty tree is not allowed

        self.curves = [
            [  # default curve
                CSAccounting.BondCurveIntervalInput(1, Wei.from_ether(2.4)),
                CSAccounting.BondCurveIntervalInput(2, Wei.from_ether(1.3)),
            ],
            [  # vetted curve
                CSAccounting.BondCurveIntervalInput(1, Wei.from_ether(1.5)),
                CSAccounting.BondCurveIntervalInput(2, Wei.from_ether(1.3)),
            ],
        ]
        self.csm_node_operators = {}
        self.rewards_tree = MerkleTree()
        self.strikes_tree = MerkleTree()
        self.distribution_history = []

        BURNER = IBurner(LIDO_LOCATOR.burner())
        STAKING_ROUTER = IStakingRouter(LIDO_LOCATOR.stakingRouter())
        EL_REWARDS_VAULT = Account(LIDO_LOCATOR.elRewardsVault())
        self.bond_lock_period = random_int(MIN_BOND_LOCK_PERIOD, MAX_BOND_LOCK_PERIOD)

        self.parameters_registry = CSParametersRegistry(
            OssifiableProxy.deploy(
                CSParametersRegistry.deploy(QUEUE_LOWEST_PRIORITY),
                self.admin,
                abi.encode_call(
                    CSParametersRegistry.initialize, [self.admin, DEFAULT_PARAMETERS]
                ),
            )
        )

        self.queue = [deque() for _ in range(QUEUE_LOWEST_PRIORITY + 1)]

        self._csm_deploy_or_upgrade()

        self.permissionless_gate = PermissionlessGate.deploy(self.csm, self.admin)

        self.vetted_gate_factory = VettedGateFactory.deploy(
            VettedGate.deploy(self.csm),
        )
        self.vetted_gate = VettedGate(
            self.vetted_gate_factory.create(
                VETTED_CURVE_ID,
                bytes32(self.vetted_tree.root),
                "TREE_CID",
                self.admin,
            ).return_value
        )

        first_supported_slot = (
            chain.blocks["latest"].timestamp - GENESIS_TIME
        ) // SECONDS_PER_SLOT

        historical_summaries_pow = int(math.log2(HISTORICAL_SUMMARIES_COUNT))
        if 2**historical_summaries_pow != HISTORICAL_SUMMARIES_COUNT:
            raise ValueError(
                f"HISTORICAL_SUMMARIES_COUNT must be a power of 2, got {HISTORICAL_SUMMARIES_COUNT}"
            )
        historical_summary_index = 0b110 << historical_summaries_pow
        historical_summary_gi = historical_summary_index.to_bytes(
            31, "big"
        ) + historical_summaries_pow.to_bytes(1, "big")

        # new CSVerifier must be deployed and attached
        self.verifier = CSVerifier.deploy(
            LIDO_LOCATOR.withdrawalVault(),
            self.csm,
            SLOTS_PER_EPOCH,
            SLOTS_PER_HISTORICAL_ROOT,
            #  simplified beacon state
            #  | validators (1024) | withdrawals (16) | historical summaries (HISTORICAL_SUMMARIES_COUNT) |
            CSVerifier.GIndices(
                # where to search for the first withdrawal within the state tree
                bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000005004"
                ),
                bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000005004"
                ),
                # where to search for the first validator within the state tree
                bytes.fromhex(
                    "000000000000000000000000000000000000000000000000000000000010000a"
                ),
                bytes.fromhex(
                    "000000000000000000000000000000000000000000000000000000000010000a"
                ),
                # where to search for the first historical summary within the state tree
                historical_summary_gi,
                historical_summary_gi,
                # where to search for the first block root in the historical summary within the state tree
                # each root in summary contains 8192 = 2**13 (SLOTS_PER_HISTORICAL_ROOT) block and state roots
                #           historical summary
                #      blocks root      states root
                bytes.fromhex(
                    "000000000000000000000000000000000000000000000000000000000040000d"
                ),
                bytes.fromhex(
                    "000000000000000000000000000000000000000000000000000000000040000d"
                ),
            ),
            first_supported_slot,
            first_supported_slot,
            CAPELLA_SLOT,
            self.admin,
        )

        self.ejector = CSEjector.deploy(
            self.csm, self.strikes, self.csm_id, self.admin
        )

        self.strikes.initialize(self.admin, self.ejector)

        self.hash_consensus.grantRole(
            self.hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(),
            self.admin,
            from_=self.admin,
        )

        self.initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        self.hash_consensus.updateInitialEpoch(self.initial_epoch, from_=self.admin)

        self.consensus_members = OrderedSet([])
        self.consensus_quorum = 0
        self.last_report_ref_slot = -1

        self.fee_oracle.grantRole(
            self.fee_oracle.MANAGE_CONSENSUS_CONTRACT_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.fee_oracle.grantRole(
            self.fee_oracle.SUBMIT_DATA_ROLE(), self.admin, from_=self.admin
        )

        if self.fee_oracle.getConsensusContract() != self.hash_consensus.address:
            self.fee_oracle.setConsensusContract(self.hash_consensus, from_=self.admin)

        self.csm.grantRole(
            self.csm.CREATE_NODE_OPERATOR_ROLE(),
            self.permissionless_gate,
            from_=self.admin,
        )
        self.csm.grantRole(
            self.csm.CREATE_NODE_OPERATOR_ROLE(), self.vetted_gate, from_=self.admin
        )
        self.csm.grantRole(
            self.csm.REPORT_EL_REWARDS_STEALING_PENALTY_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.csm.grantRole(
            self.csm.SETTLE_EL_REWARDS_STEALING_PENALTY_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.csm.grantRole(
            self.csm.VERIFIER_ROLE(),
            self.verifier,
            from_=self.admin,
        )
        # needed for direct call of CSModule.onValidatorExitTriggered from TW gateway
        self.csm.grantRole(
            self.csm.STAKING_ROUTER_ROLE(),
            self.triggerable_withdrawals_gateway,
            from_=self.admin,
        )
        self.accounting.grantRole(
            self.accounting.SET_BOND_CURVE_ROLE(), self.vetted_gate, from_=self.admin
        )
        self.accounting.grantRole(
            self.accounting.SET_BOND_CURVE_ROLE(), self.admin, from_=self.admin
        )
        self.accounting.grantRole(
            self.accounting.MANAGE_BOND_CURVES_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.vetted_gate.grantRole(
            self.vetted_gate.START_REFERRAL_SEASON_ROLE(), self.admin, from_=self.admin
        )
        self.vetted_gate.grantRole(
            self.vetted_gate.END_REFERRAL_SEASON_ROLE(), self.admin, from_=self.admin
        )
        self.vetted_gate.grantRole(
            self.vetted_gate.SET_TREE_ROLE(), self.admin, from_=self.admin
        )

        BURNER.grantRole(
            BURNER.REQUEST_BURN_SHARES_ROLE(),
            self.accounting,
            from_="0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c",
        )

        self.accounting.setChargePenaltyRecipient(
            self.charge_penalty_recipient, from_=self.admin
        )
        self.accounting.setBondLockPeriod(self.bond_lock_period, from_=self.admin)

        self.no_id = self.csm.getNodeOperatorsCount()
        self.nonce = self.csm.getNonce()

        self.parameters_registry.setQueueConfig(
            VETTED_CURVE_ID, 0, uint32.max, from_=self.admin
        )

        self.parameters = {}
        self.parameters[DEFAULT_CURVE_ID] = Parameters()
        self.parameters[VETTED_CURVE_ID] = Parameters()
        self.parameters[VETTED_CURVE_ID].queue_config = (0, uint32.max)

        self._csm_migrate_forked_node_operators()

        self.balances = defaultdict(int)
        self.shares = defaultdict(int)
        for acc in itertools.chain(
            [
                self.csm,
                self.accounting,
                self.fee_oracle,
                self.fee_distributor,
                BURNER,
                EL_REWARDS_VAULT,
            ],
            [no.rewards_account for no in self.csm_node_operators.values()],
            [no.manager for no in self.csm_node_operators.values()],
            chain.accounts,
        ):
            self.balances[acc] = acc.balance
            self.shares[acc] = ST_ETH.sharesOf(acc)

        # transfer extra (undistributed) shares from CSFeeDistributor to Address(1)
        ST_ETH.transferShares(
            Account(1),
            self.shares[self.fee_distributor]
            - self.fee_distributor.totalClaimableShares(),
            from_=self.fee_distributor,
        )
        self.shares[self.fee_distributor] = self.fee_distributor.totalClaimableShares()

    # overriden in tw.py with the same logic
    def post_invariants(self) -> None:
        time_delta = random_int(60 * 60, 5 * 60 * 60)
        chain.mine(lambda t: t + time_delta)

        # change EIP-7002 dynamic fee
        chain.chain_interface.set_storage_at(
            "0x00000961Ef480Eb55e80D19ad83579A64c007002",
            0,
            abi.encode(uint(random_int(1, MAX_WITHDRAWAL_EXCESS))),
        )

    def _csm_migrate_forked_node_operators(self):
        total_node_operators = self.csm.getNodeOperatorsCount()
        for no_id in range(total_node_operators):
            no = self.csm.getNodeOperator(no_id)
            keys, signatures = self.csm.getSigningKeysWithSignatures(
                no_id, 0, no.totalAddedKeys
            )
            lock_info = self.accounting.getLockedBondInfo(no_id)

            withdrawn = defaultdict(bool)
            for i in range(no.totalAddedKeys):
                withdrawn[i] = self.csm.isValidatorWithdrawn(no_id, i)

            self.csm_node_operators[no_id] = NodeOperator(
                id=no_id,
                curve_id=self.accounting.getBondCurveId(no_id),
                keys=[keys[i : i + 48] for i in range(0, len(keys), 48)],
                signatures=[
                    signatures[i : i + 96] for i in range(0, len(signatures), 96)
                ],
                manager=Account(no.managerAddress),
                rewards_account=Account(no.rewardAddress),
                extended_permissions=no.extendedManagerPermissions,
                target_limit=no.targetLimit,
                target_limit_mode=no.targetLimitMode,
                bond_shares=self.accounting.getBondShares(no_id),
                total_rewards=self.fee_distributor.distributedShares(no_id),
                claimed_rewards=self.fee_distributor.distributedShares(no_id),
                total_keys=no.totalAddedKeys,
                withdrawn_keys=no.totalWithdrawnKeys,
                deposited_keys=no.totalDepositedKeys - no.totalWithdrawnKeys,
                vetted_keys=no.totalVettedKeys,
                stuck_keys=no.stuckValidatorsCount,
                exited_keys=no.totalExitedKeys,
                locked_bond=lock_info.amount,
                lock_expiry=lock_info.until,
                withdrawn=withdrawn,
                key_strikes=defaultdict(list),
                used_priority_queue=False,
                strikes_penalties=defaultdict(lambda: None),
                withdrawal_request_fees=defaultdict(lambda: None),
                exit_delay_penalties=defaultdict(lambda: None),
            )
            logger.info(f"Migrated node operator {no_id + 1}/{total_node_operators}")

    @contextmanager
    def _change_manager(self, no: NodeOperator, new_manager: Account):
        if no.extended_permissions:
            if no.manager != new_manager:
                self.csm.proposeNodeOperatorManagerAddressChange(
                    no.id, new_manager, from_=no.manager
                )
                self.csm.confirmNodeOperatorManagerAddressChange(
                    no.id, from_=new_manager
                )

                yield

                self.csm.proposeNodeOperatorManagerAddressChange(
                    no.id, no.manager, from_=new_manager
                )
                self.csm.confirmNodeOperatorManagerAddressChange(
                    no.id, from_=no.manager
                )
            else:
                yield
        else:
            if no.rewards_account != new_manager:
                self.csm.proposeNodeOperatorRewardAddressChange(
                    no.id, new_manager, from_=no.rewards_account
                )
                self.csm.confirmNodeOperatorRewardAddressChange(
                    no.id, from_=new_manager
                )

                yield

                self.csm.proposeNodeOperatorRewardAddressChange(
                    no.id, no.rewards_account, from_=new_manager
                )
                self.csm.confirmNodeOperatorRewardAddressChange(
                    no.id, from_=no.rewards_account
                )
            else:
                yield

    @staticmethod
    def _get_total_bond(
        keys_count: uint, curve: list[CSAccounting.BondCurveIntervalInput]
    ) -> uint:
        if keys_count == 0:
            return 0

        i = max((i for i in range(len(curve)) if keys_count >= curve[i].minKeysCount))
        return (
            sum(
                (curve[j + 1].minKeysCount - curve[j].minKeysCount) * curve[j].trend
                for j in range(i)
            )
            + (keys_count - curve[i].minKeysCount + 1) * curve[i].trend
        )

    def _get_claimable_bond_shares(self, no: NodeOperator, timestamp: uint) -> int:
        return max(
            no.bond_shares
            - ST_ETH.getSharesByPooledEth(
                self._get_total_bond(
                    no.total_keys - no.withdrawn_keys, self.curves[no.curve_id]
                )
                + self._get_actual_locked_bond(no, timestamp)
            ),
            0,
        )

    def _get_claimable_bond_shares_with_pull(
        self, no: NodeOperator, timestamp: uint
    ) -> int:
        return max(
            no.bond_shares
            + no.total_rewards
            - no.claimed_rewards
            - ST_ETH.getSharesByPooledEth(
                self._get_total_bond(
                    no.total_keys - no.withdrawn_keys, self.curves[no.curve_id]
                )
                + self._get_actual_locked_bond(no, timestamp)
            ),
            0,
        )

    def _get_actual_locked_bond(self, no: NodeOperator, timestamp: uint) -> uint:
        if no.lock_expiry <= timestamp:
            return 0
        return no.locked_bond

    def _get_keys_by_eth(self, no: NodeOperator, timestamp: uint, locked: bool) -> int:
        # 10 wei is added due to rounding errors in stETH shares
        available_eth = ST_ETH.getPooledEthByShares(no.bond_shares) + 10
        if locked:
            available_eth = max(
                available_eth - self._get_actual_locked_bond(no, timestamp), 0
            )

        curve = self.curves[no.curve_id]

        if available_eth < curve[0].trend:
            return 0
        elif len(curve) == 1:
            return available_eth // curve[0].trend

        sum = 0
        i = 0
        while (
            whole_interval := (curve[i + 1].minKeysCount - curve[i].minKeysCount)
            * curve[i].trend
        ) + sum < available_eth:
            sum += whole_interval
            i += 1
            if i == len(curve) - 1:
                break

        return curve[i].minKeysCount + (available_eth - sum) // curve[i].trend - 1

    def _get_depositable_keys(self, no: NodeOperator, timestamp: uint) -> int:
        if no.stuck_keys > 0:
            return 0

        keys_by_eth = self._get_keys_by_eth(no, timestamp, True)
        limit = 2**256 - 1 if no.target_limit_mode == 0 else no.target_limit

        return max(
            min(
                no.vetted_keys - no.deposited_keys - no.withdrawn_keys,
                keys_by_eth - no.deposited_keys,
                limit - no.deposited_keys,
            ),
            0,
        )

    def _get_enqueued_keys(self, no_id: int) -> int:
        return sum(
            sum(item.keys_count for item in q if item.no_id == no_id)
            for q in self.queue
        )

    def _reenqueue(
        self,
        no_id: int,
        depositable_before: int,
        update_nonce: bool = False,
        tx: TransactionAbc | None = None,
    ):
        if tx is None:
            tx = chain.txs[-1]

        no = self.csm_node_operators[no_id]

        depositable = self._get_depositable_keys(no, tx.block.timestamp)
        enqueued = self._get_enqueued_keys(no_id)

        if depositable_before != depositable:
            assert (
                CSModule.DepositableSigningKeysCountChanged(no_id, depositable)
                in tx.events
            )
            if update_nonce:
                self.nonce += 1
                assert CSModule.NonceChanged(self.nonce) in tx.events

            priority, max_deposits = self.parameters[no.curve_id].queue_config

            if depositable > enqueued:
                into_priority = min(
                    depositable - enqueued,
                    max(
                        max_deposits - no.deposited_keys - no.withdrawn_keys - enqueued,
                        0,
                    ),
                )
                if priority < QUEUE_LOWEST_PRIORITY:
                    if into_priority > 0:
                        self.csm_node_operators[no_id].used_priority_queue = True
                        assert self.csm.getNodeOperator(no_id).usedPriorityQueue
                        self.queue[priority].append(
                            QueueItem(
                                no_id,
                                into_priority,
                            )
                        )
                        assert (
                            CSModule.BatchEnqueued(
                                priority,
                                no_id,
                                into_priority,
                            )
                            in tx.events
                        )
                    else:
                        assert not any(
                            e
                            for e in tx.events
                            if isinstance(e, CSModule.BatchEnqueued)
                            and e.nodeOperatorId == no_id
                            and e.queuePriority == priority
                        )
                else:
                    into_priority = 0

                if into_priority < depositable - enqueued:
                    self.queue[QUEUE_LOWEST_PRIORITY].append(
                        QueueItem(
                            no_id,
                            depositable - enqueued - into_priority,
                        )
                    )
                    assert CSModule.BatchEnqueued(
                        QUEUE_LOWEST_PRIORITY,
                        no_id,
                        depositable - enqueued - into_priority,
                    )
                else:
                    assert not any(
                        e
                        for e in tx.events
                        if isinstance(e, CSModule.BatchEnqueued)
                        and e.nodeOperatorId == no_id
                        and e.queuePriority == QUEUE_LOWEST_PRIORITY
                    )
                return
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSModule.DepositableSigningKeysCountChanged)
                and e.nodeOperatorId == no_id
            )

        assert not any(
            e
            for e in tx.events
            if isinstance(e, CSModule.BatchEnqueued) and e.nodeOperatorId == no_id
        )

    @flow(max_times=100)
    def flow_add_no(self) -> str | None:
        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        manager = random_account()
        rewards = random_account()
        extended_permissions = random_bool()

        sender = random_account()
        if sender in self.vetted_accounts and random.random() < 0.33:
            curve_id = VETTED_CURVE_ID
        else:
            curve_id = DEFAULT_CURVE_ID
        total_bond = self._get_total_bond(keys_count, self.curves[curve_id])

        referrer = random.choice(list(self.vetted_accounts))

        p = random.random()
        if p < 0.33:
            # native ETH
            required_eth = self.accounting.getBondAmountByKeysCount(
                keys_count,
                curve_id,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond

            if curve_id == VETTED_CURVE_ID:
                call = partial(
                    self.vetted_gate.addNodeOperatorETH,
                    proof=self.vetted_tree.get_proof(
                        self.vetted_tree.leaves.index(keccak256(abi.encode(sender)))
                    ),
                )
            else:
                call = self.permissionless_gate.addNodeOperatorETH

            with may_revert(
                (VettedGate.AlreadyConsumed, CSModule.KeysLimitExceeded)
            ) as ex:
                tx = call(
                    keysCount=keys_count,
                    publicKeys=b"".join(public_keys),
                    signatures=b"".join(signatures),
                    managementProperties=NodeOperatorManagementProperties(
                        manager.address,
                        rewards.address,
                        extended_permissions,
                    ),
                    referrer=referrer,
                    value=total_bond,
                    from_=sender,
                )

            if sender in self.claimed_vetted_accounts and curve_id == VETTED_CURVE_ID:
                assert ex.value == VettedGate.AlreadyConsumed()
                self.balances[sender] += total_bond
                return "Already claimed"
            elif keys_count > self.parameters[curve_id].keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                self.balances[sender] += total_bond
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            assert (
                CSAccounting.BondDepositedETH(self.no_id, sender.address, total_bond)
                in tx.events
            )
        elif p < 0.66:
            # stETH
            required_eth = self.accounting.getBondAmountByKeysCount(
                keys_count,
                curve_id,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond
            ST_ETH.transact(from_=sender, value=total_bond)

            if random_bool() or sender not in chain.accounts:
                ST_ETH.approve(self.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(ST_ETH).nonces(sender),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.steth_domain)

            if curve_id == VETTED_CURVE_ID:
                call = partial(
                    self.vetted_gate.addNodeOperatorStETH,
                    proof=self.vetted_tree.get_proof(
                        self.vetted_tree.leaves.index(keccak256(abi.encode(sender)))
                    ),
                )
            else:
                call = self.permissionless_gate.addNodeOperatorStETH

            with may_revert(
                (VettedGate.AlreadyConsumed, CSModule.KeysLimitExceeded)
            ) as ex:
                tx = call(
                    keysCount=keys_count,
                    publicKeys=b"".join(public_keys),
                    signatures=b"".join(signatures),
                    managementProperties=NodeOperatorManagementProperties(
                        manager.address,
                        rewards.address,
                        extended_permissions,
                    ),
                    permit=CSAccounting.PermitInput(
                        total_bond,
                        2**256 - 1,
                        permit_signature[64],
                        permit_signature[:32],
                        permit_signature[32:64],
                    ),
                    referrer=referrer,
                    from_=sender,
                )

            if sender in self.claimed_vetted_accounts and curve_id == VETTED_CURVE_ID:
                assert ex.value == VettedGate.AlreadyConsumed()
                self.shares[sender] += shares
                return "Already claimed"
            elif keys_count > self.parameters[curve_id].keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                self.shares[sender] += shares
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            assert (
                CSAccounting.BondDepositedStETH(self.no_id, sender.address, total_bond)
                in tx.events
            )
        else:
            # wstETH
            total_bond = WST_ETH.getWstETHByStETH(total_bond)

            required_wst_eth = self.accounting.getBondAmountByKeysCountWstETH(
                keys_count,
                curve_id,
            )
            assert abs(required_wst_eth - total_bond) <= 10
            total_bond = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(
                ST_ETH.getPooledEthByShares(total_bond)
            )

            mint_erc20(WST_ETH, sender, total_bond)
            if random_bool() or sender not in chain.accounts:
                WST_ETH.approve(self.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(WST_ETH).nonces(sender),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.wsteth_domain)

            if curve_id == VETTED_CURVE_ID:
                call = partial(
                    self.vetted_gate.addNodeOperatorWstETH,
                    proof=self.vetted_tree.get_proof(
                        self.vetted_tree.leaves.index(keccak256(abi.encode(sender)))
                    ),
                )
            else:
                call = self.permissionless_gate.addNodeOperatorWstETH

            with may_revert(
                (VettedGate.AlreadyConsumed, CSModule.KeysLimitExceeded)
            ) as ex:
                tx = call(
                    keysCount=keys_count,
                    publicKeys=b"".join(public_keys),
                    signatures=b"".join(signatures),
                    managementProperties=NodeOperatorManagementProperties(
                        manager.address,
                        rewards.address,
                        extended_permissions,
                    ),
                    permit=CSAccounting.PermitInput(
                        total_bond,
                        2**256 - 1,
                        permit_signature[64],
                        permit_signature[:32],
                        permit_signature[32:64],
                    ),
                    referrer=referrer,
                    from_=sender,
                )

            if sender in self.claimed_vetted_accounts and curve_id == VETTED_CURVE_ID:
                assert ex.value == VettedGate.AlreadyConsumed()
                return "Already claimed"
            elif keys_count > self.parameters[curve_id].keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            assert (
                CSAccounting.BondDepositedWstETH(self.no_id, sender.address, total_bond)
                in tx.events
            )

        self.csm_node_operators[self.no_id] = NodeOperator(
            id=self.no_id,
            curve_id=curve_id,
            keys=public_keys,
            signatures=signatures,
            manager=manager,
            rewards_account=rewards,
            extended_permissions=extended_permissions,
            target_limit=0,
            target_limit_mode=0,
            bond_shares=shares,
            total_rewards=0,
            claimed_rewards=0,
            total_keys=keys_count,
            deposited_keys=0,
            vetted_keys=keys_count,
            stuck_keys=0,
            withdrawn_keys=0,
            exited_keys=0,
            locked_bond=0,
            lock_expiry=0,
            withdrawn=defaultdict(bool),
            key_strikes=defaultdict(list),
            used_priority_queue=False,
            strikes_penalties=defaultdict(lambda: None),
            withdrawal_request_fees=defaultdict(lambda: None),
            exit_delay_penalties=defaultdict(lambda: None),
        )
        self.shares[self.accounting] += shares

        if curve_id == VETTED_CURVE_ID:
            assert VettedGate.Consumed(sender.address) in tx.events
            assert CSAccounting.BondCurveSet(self.no_id, VETTED_CURVE_ID) in tx.events
            self.claimed_vetted_accounts.add(sender)
            if self.vetted_season_active and referrer != sender:
                assert (
                    VettedGate.ReferralRecorded(
                        referrer.address, self.referral_season_id, self.no_id
                    )
                    in tx.events
                )
                self.vetted_referrals[referrer] += 1
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, VettedGate.ReferralRecorded)
                )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(
                    e,
                    (
                        VettedGate.Consumed,
                        CSAccounting.BondCurveSet,
                        VettedGate.ReferralRecorded,
                    ),
                )
            )

        assert (
            CSModule.NodeOperatorAdded(
                self.no_id, manager.address, rewards.address, extended_permissions
            )
            in tx.events
        )
        assert [CSModule.SigningKeyAdded(self.no_id, k) for k in public_keys] == [
            e for e in tx.events if isinstance(e, CSModule.SigningKeyAdded)
        ]
        assert (
            CSModule.VettedSigningKeysCountChanged(self.no_id, keys_count) in tx.events
        )
        assert (
            CSModule.TotalSigningKeysCountChanged(self.no_id, keys_count) in tx.events
        )
        assert (
            CSModule.DepositableSigningKeysCountChanged(self.no_id, keys_count)
            in tx.events
        )
        assert CSModule.NonceChanged(self.nonce + 1) in tx.events  # NO created
        assert CSModule.NonceChanged(self.nonce + 2) in tx.events  # NO keys added

        priority, max_keys = self.parameters[curve_id].queue_config
        if priority < QUEUE_LOWEST_PRIORITY - 1:
            self.csm_node_operators[self.no_id].used_priority_queue = True

        into_priority = min(max_keys, keys_count)
        if priority != QUEUE_LOWEST_PRIORITY:
            self.queue[priority].append(QueueItem(self.no_id, into_priority))
            assert (
                CSModule.BatchEnqueued(priority, self.no_id, into_priority) in tx.events
            )
        else:
            into_priority = 0

        if keys_count > into_priority:
            self.queue[QUEUE_LOWEST_PRIORITY].append(
                QueueItem(self.no_id, keys_count - into_priority)
            )
            assert (
                CSModule.BatchEnqueued(
                    QUEUE_LOWEST_PRIORITY, self.no_id, keys_count - into_priority
                )
                in tx.events
            )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSModule.BatchEnqueued)
                and e.nodeOperatorId == self.no_id
                and e.queuePriority == QUEUE_LOWEST_PRIORITY
            )

        self.nonce += 2
        self.no_id += 1

        logger.info(
            f"Added NO {self.no_id - 1} with {keys_count} keys and referrer {referrer}"
        )

    @flow()
    def flow_no_add_keys(self) -> str | None:
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No node operators"

        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        bond_increase = max(
            self._get_total_bond(
                no.total_keys - no.withdrawn_keys + keys_count, self.curves[no.curve_id]
            )
            - ST_ETH.getPooledEthByShares(no.bond_shares)
            + self._get_actual_locked_bond(no, chain.blocks["pending"].timestamp),
            0,
        )

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        keys_limit = self.parameters[no.curve_id].keys_limit

        p = random.random()
        if p < 0.33:
            # native ETH
            required_eth = self.accounting.getRequiredBondForNextKeys(
                no.id,
                keys_count,
            )
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)

            no.manager.balance += bond_increase

            with may_revert(CSModule.KeysLimitExceeded) as ex:
                tx = self.csm.addValidatorKeysETH(
                    no.manager,
                    no.id,
                    keys_count,
                    b"".join(public_keys),
                    b"".join(signatures),
                    value=bond_increase,
                    from_=no.manager,
                )

            if no.total_keys - no.withdrawn_keys + keys_count > keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                self.balances[no.manager] += bond_increase
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            if bond_increase > 0:
                assert (
                    CSAccounting.BondDepositedETH(
                        no.id, no.manager.address, bond_increase
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondDepositedETH)
                )
        elif p < 0.66:
            # stETH
            required_eth = self.accounting.getRequiredBondForNextKeys(
                no.id,
                keys_count,
            )
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)

            if bond_increase > 0:
                no.manager.balance += bond_increase
                ST_ETH.transact(from_=no.manager, value=bond_increase)

            if random_bool() or no.manager not in chain.accounts:
                ST_ETH.approve(self.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=self.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(ST_ETH).nonces(no.manager),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, self.steth_domain)

            with may_revert(CSModule.KeysLimitExceeded) as ex:
                tx = self.csm.addValidatorKeysStETH(
                    no.manager,
                    no.id,
                    keys_count,
                    b"".join(public_keys),
                    b"".join(signatures),
                    permit=CSAccounting.PermitInput(
                        bond_increase,
                        2**256 - 1,
                        permit_signature[64],
                        permit_signature[:32],
                        permit_signature[32:64],
                    ),
                    from_=no.manager,
                )

            if no.total_keys - no.withdrawn_keys + keys_count > keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                self.shares[no.manager] += shares
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            if bond_increase > 0:
                assert (
                    CSAccounting.BondDepositedStETH(
                        no.id, no.manager.address, bond_increase
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSAccounting.BondDepositedStETH)
                )
        else:
            # wstETH
            bond_increase = WST_ETH.getWstETHByStETH(bond_increase)
            required_wst_eth = self.accounting.getRequiredBondForNextKeysWstETH(
                no.id,
                keys_count,
                request_type="tx",
            ).return_value
            assert abs(required_wst_eth - bond_increase) <= 10
            bond_increase = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(
                ST_ETH.getPooledEthByShares(bond_increase)
            )

            if bond_increase > 0:
                mint_erc20(WST_ETH, no.manager, bond_increase)

            if random_bool() or no.manager not in chain.accounts:
                WST_ETH.approve(self.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=self.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(WST_ETH).nonces(no.manager),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(
                    permit, self.wsteth_domain
                )

            with may_revert(CSModule.KeysLimitExceeded) as ex:
                tx = self.csm.addValidatorKeysWstETH(
                    no.manager,
                    no.id,
                    keys_count,
                    b"".join(public_keys),
                    b"".join(signatures),
                    permit=CSAccounting.PermitInput(
                        bond_increase,
                        2**256 - 1,
                        permit_signature[64],
                        permit_signature[:32],
                        permit_signature[32:64],
                    ),
                    from_=no.manager,
                )

            if no.total_keys - no.withdrawn_keys + keys_count > keys_limit:
                assert ex.value == CSModule.KeysLimitExceeded()
                return "Keys limit exceeded"
            else:
                assert ex.value is None

            if bond_increase > 0:
                assert (
                    CSAccounting.BondDepositedWstETH(
                        no.id, no.manager.address, bond_increase
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSAccounting.BondDepositedWstETH)
                )

        if no.total_keys == no.vetted_keys:
            # optimistic vetting
            no.vetted_keys += keys_count
            assert (
                CSModule.VettedSigningKeysCountChanged(
                    no.id, no.total_keys + keys_count
                )
                in tx.events
            )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSModule.VettedSigningKeysCountChanged)
            )

        no.total_keys += keys_count
        no.bond_shares += shares
        no.keys.extend(public_keys)
        no.signatures.extend(signatures)
        self.shares[self.accounting] += shares
        self.nonce += 1

        self._reenqueue(no.id, depositable_before)

        assert [CSModule.SigningKeyAdded(no.id, k) for k in public_keys] == [
            e for e in tx.events if isinstance(e, CSModule.SigningKeyAdded)
        ]
        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Added {keys_count} keys to NO {no.id}")

    @flow()
    def flow_deposit_eth(self) -> str | None:
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No node operators"

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount
        sender = random_account()

        p = random.random()
        if p < 0.33:
            # native ETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            sender.balance += amount
            shares = ST_ETH.getSharesByPooledEth(amount)

            tx = self.accounting.depositETH_(no.id, value=amount, from_=sender)

            if amount > 0:
                assert (
                    CSAccounting.BondDepositedETH(no.id, sender.address, amount)
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondDepositedETH)
                )
        elif p < 0.66:
            # stETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            shares = ST_ETH.getSharesByPooledEth(amount)

            if amount > 0:
                sender.balance += amount
                ST_ETH.transact(from_=sender, value=amount)

            if random_bool() or sender not in chain.accounts:
                ST_ETH.approve(self.accounting, amount, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(ST_ETH).nonces(sender),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.steth_domain)

            tx = self.accounting.depositStETH_(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=sender,
            )

            if amount > 0:
                assert (
                    CSAccounting.BondDepositedStETH(no.id, sender.address, amount)
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSAccounting.BondDepositedStETH)
                )
        else:
            # wstETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(amount))

            if amount > 0:
                mint_erc20(WST_ETH, sender, amount)

            if random_bool() or sender not in chain.accounts:
                WST_ETH.approve(self.accounting, amount, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(WST_ETH).nonces(sender),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.wsteth_domain)

            tx = self.accounting.depositWstETH_(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=sender,
            )

            if amount > 0:
                assert (
                    CSAccounting.BondDepositedWstETH(no.id, sender.address, amount)
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSAccounting.BondDepositedWstETH)
                )

        self.csm_node_operators[no.id].bond_shares += shares
        self.shares[self.accounting] += shares

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Deposited {amount} to NO {no.id}")

    @flow()
    def flow_no_remove_keys(self) -> str | None:
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if no.total_keys - no.deposited_keys - no.withdrawn_keys > 0
                ]
            )
        except IndexError:
            return "No node operators with keys to remove"

        keys_count = random_int(
            1, no.total_keys - no.deposited_keys - no.withdrawn_keys
        )
        start_index = (
            random_int(
                0, no.total_keys - no.deposited_keys - no.withdrawn_keys - keys_count
            )
            + no.deposited_keys
            + no.withdrawn_keys
        )
        key_removal_charge = self.parameters[no.curve_id].key_removal_charge

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.csm.removeKeys(no.id, start_index, keys_count, from_=no.manager)

        shares = min(
            ST_ETH.getSharesByPooledEth(key_removal_charge * keys_count),
            no.bond_shares,
        )
        no.total_keys -= keys_count
        no.vetted_keys = no.total_keys  # optimistic removal
        no.bond_shares -= shares
        self.shares[self.accounting] -= shares
        self.shares[self.charge_penalty_recipient] += shares
        self.nonce += 1

        removed = []

        # queue remains as is, only keys are removed
        for i in range(keys_count, 0, -1):
            if start_index + i < len(no.keys):
                # when not removing last key, move last key to the removed position
                removed.append(no.keys[start_index + i - 1])
                no.keys[start_index + i - 1] = no.keys.pop()
                no.signatures[start_index + i - 1] = no.signatures.pop()
            else:
                # when removing last key, just pop it
                removed.append(no.keys.pop())
                no.signatures.pop()

        self._reenqueue(no.id, depositable_before)

        assert [e for e in tx.events if isinstance(e, CSModule.SigningKeyRemoved)] == [
            CSModule.SigningKeyRemoved(no.id, key) for key in removed
        ]
        if key_removal_charge * keys_count > 0:
            assert CSModule.KeyRemovalChargeApplied(no.id) in tx.events
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSModule.KeyRemovalChargeApplied)
            )

        if shares > 0:
            assert (
                CSAccounting.BondCharged(
                    no.id,
                    ST_ETH.getPooledEthByShares(
                        ST_ETH.getSharesByPooledEth(key_removal_charge * keys_count)
                    ),
                    ST_ETH.getPooledEthByShares(shares),
                )
                in tx.events
            )
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondCharged)
            )

        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys) in tx.events
        assert (
            CSModule.VettedSigningKeysCountChanged(no.id, no.vetted_keys) in tx.events
        )
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Removed {keys_count} keys from NO {no.id}")

    @flow(max_times=1)
    def flow_update_vetted_tree(self) -> None:
        new_vetted = random.sample(
            list(OrderedSet(chain.accounts) - self.vetted_accounts), k=random_int(1, 25)
        )

        for acc in new_vetted:
            self.vetted_tree.add_leaf(keccak256(abi.encode(acc)))
        len_before = len(self.vetted_accounts)
        self.vetted_accounts.update(new_vetted)
        assert len(self.vetted_accounts) == len_before + len(new_vetted)

        self.vetted_gate.setTreeParams(
            self.vetted_tree.root, "TREE_CID2", from_=self.admin
        )

        logger.info(f"Updated vetted tree with {len(new_vetted)} new accounts")

    @flow()
    def flow_claim_bond_curve(self) -> str | None:
        if not self.vetted_accounts:
            return "No vetted accounts"
        if not self.csm_node_operators:
            return "No node operators"

        sender = random.choice(list(self.vetted_accounts))
        no = random.choice(list(self.csm_node_operators.values()))

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        # temporarily transfer ownership to make the claim possible
        with self._change_manager(no, sender):
            with may_revert(VettedGate.AlreadyConsumed) as ex:
                tx = self.vetted_gate.claimBondCurve(
                    nodeOperatorId=no.id,
                    proof=self.vetted_tree.get_proof(
                        self.vetted_tree.leaves.index(keccak256(abi.encode(sender)))
                    ),
                    from_=sender,
                )

        if sender in self.claimed_vetted_accounts:
            assert ex.value is not None
            return "Already claimed"
        else:
            assert ex.value is None

        assert CSAccounting.BondCurveSet(no.id, VETTED_CURVE_ID) in tx.events
        assert VettedGate.Consumed(sender.address) in tx.events

        no.curve_id = VETTED_CURVE_ID

        self.claimed_vetted_accounts.add(sender)

        self._reenqueue(no.id, depositable_before, update_nonce=True, tx=tx)

        logger.info(f"Claimed vetted bond curve for NO {no.id} with {sender}")

    @flow()
    def flow_report_stealing(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No node operators"

        amount = random_int(0, Wei.from_ether(3), edge_values_prob=0.1)
        block_hash = random_bytes(32)

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount
        stealing_fine = self.parameters[no.curve_id].el_rewards_stealing_additional_fine

        with may_revert(CSModule.InvalidAmount) as e:
            tx = self.csm.reportELRewardsStealingPenalty(
                no.id,
                block_hash,
                amount,
                from_=self.admin,
            )

        if e.value is not None:
            assert amount == 0
            return "Invalid amount"
        else:
            assert amount > 0

        if no.lock_expiry <= tx.block.timestamp:
            no.locked_bond = amount + stealing_fine
        else:
            no.locked_bond += amount + stealing_fine
        no.lock_expiry = tx.block.timestamp + self.bond_lock_period

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        assert (
            CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry)
            in tx.events
        )
        assert (
            CSModule.ELRewardsStealingPenaltyReported(no.id, block_hash, amount)
            in tx.events
        )

        logger.info(f"Reported {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_cancel_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if self._get_actual_locked_bond(no, t)
                ]
            )
        except IndexError:
            return "No NO with locked bond"

        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, locked, edge_values_prob=0.2)

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.csm.cancelELRewardsStealingPenalty(
            no.id,
            amount,
            from_=self.admin,
        )

        no.locked_bond -= amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged)
            )
        else:
            assert (
                CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry)
                in tx.events
            )
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved)
            )
        assert CSModule.ELRewardsStealingPenaltyCancelled(no.id, amount) in tx.events

        logger.info(f"Cancelled {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_settle_stealing_penalty(self):
        depositable_before = {
            no.id: self.csm.getNodeOperator(no.id).depositableValidatorsCount
            for no in self.csm_node_operators.values()
        }

        tx = self.csm.settleELRewardsStealingPenalty(
            list(self.csm_node_operators.keys()), from_=self.admin
        )

        for no in self.csm_node_operators.values():
            if self._get_actual_locked_bond(no, tx.block.timestamp) > 0:
                shares = ST_ETH.getSharesByPooledEth(no.locked_bond)

                # bond curve no longer resets

                shares = min(shares, no.bond_shares)

                self.shares[self.accounting] -= shares
                self.shares[BURNER] += shares
                no.bond_shares -= shares
                no.locked_bond = 0
                no.lock_expiry = 0

                self._reenqueue(no.id, depositable_before[no.id], update_nonce=True)

                assert CSAccounting.BondLockRemoved(no.id) in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) in tx.events
            else:
                assert CSAccounting.BondLockRemoved(no.id) not in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) not in tx.events

        logger.info(f"Settled stealing penalties")

    @flow()
    def flow_compensate_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if self._get_actual_locked_bond(no, t) > 0
                ]
            )
        except IndexError:
            return "No NO with locked bond"

        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, locked, edge_values_prob=0.2)
        no.manager.balance += amount

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.csm.compensateELRewardsStealingPenalty(
            no.id, value=amount, from_=no.manager
        )

        no.locked_bond -= amount
        self.balances[EL_REWARDS_VAULT] += amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged)
            )
        else:
            assert (
                CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry)
                in tx.events
            )
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved)
            )

        assert CSAccounting.BondLockCompensated(no.id, amount) in tx.events

        logger.info(f"Compensated {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_clean_deposit_queue(self):
        depositable_keys = {
            no_id: self.csm.getNodeOperator(no_id).depositableValidatorsCount
            for no_id in range(self.csm.getNodeOperatorsCount())
        }
        max_items = random_int(1, max(len(self.queue), 1))

        tx = self.csm.cleanDepositQueue(max_items, from_=random_account())

        enqueued_keys = defaultdict(int)

        new_queue = deque()
        removed_items = 0
        last_removal_pos = 0
        i = 0
        for queue_index, queue in enumerate(self.queue):
            new_queue = deque()
            for item in queue:
                if i >= max_items:
                    new_queue.append(item)
                    i += 1
                    continue

                if depositable_keys[item.no_id] > enqueued_keys[item.no_id]:
                    enqueued_keys[item.no_id] += item.keys_count
                    new_queue.append(item)
                else:
                    removed_items += 1
                    last_removal_pos = i + 1

                i += 1

            self.queue[queue_index] = new_queue

        assert tx.return_value == (removed_items, last_removal_pos)

        logger.info(f"Cleaned deposit queue")

    @flow()
    def flow_migrate_to_priority_queue(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No node operators"

        with may_revert() as ex:
            tx = self.csm.migrateToPriorityQueue(no.id, from_=random_account())

        queue_priority, queue_max_deposits = self.parameters[no.curve_id].queue_config
        enqueued = self._get_enqueued_keys(no.id)

        if no.used_priority_queue:
            assert ex.value == CSModule.PriorityQueueAlreadyUsed()
            return "Already migrated to priority queue"
        elif queue_priority == QUEUE_LOWEST_PRIORITY:
            assert ex.value == CSModule.NotEligibleForPriorityQueue()
            return "Not eligible for priority queue"
        elif enqueued == 0:
            assert ex.value == CSModule.NoQueuedKeysToMigrate()
            return "No queued keys to migrate"
        elif no.deposited_keys + no.withdrawn_keys >= queue_max_deposits:
            assert ex.value == CSModule.PriorityQueueMaxDepositsUsed()
            return "Priority queue max deposits used"
        else:
            assert ex.value is None

        count = min(
            enqueued,
            max(
                0,
                queue_max_deposits - no.deposited_keys - no.withdrawn_keys,
            ),
        )

        no.used_priority_queue = True

        self.queue[queue_priority].append(QueueItem(no.id, count))
        assert CSModule.BatchEnqueued(queue_priority, no.id, count) in tx.events

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) == tx.events[-1]

        logger.info(f"Migrated NO {no.id} to priority queue")

    def csm_pre_deposit(self) -> tuple[int, dict[int, int]]:
        # CSM sees different number of depositable keys than we do because depositable keys are stored in the contract
        # and not updated on EL stealing retention period end
        depositable_keys = {
            no.id: self.csm.getNodeOperator(no.id).depositableValidatorsCount
            for no in self.csm_node_operators.values()
        }
        t = chain.blocks["pending"].timestamp
        available_keys = sum(
            self._get_depositable_keys(no, t) for no in self.csm_node_operators.values()
        )
        return available_keys, depositable_keys

    def csm_post_deposit(
        self, deposits_count: int, depositable_keys: dict[int, int], tx: TransactionAbc
    ) -> str | None:
        if deposits_count > sum(
            min(depositable_keys[no.id], self._get_enqueued_keys(no.id))
            for no in self.csm_node_operators.values()
        ):
            return "Not enough keys to deposit"
        else:
            assert tx.error is None

        keys = bytearray(b"")
        signatures = bytearray(b"")
        deposited = 0
        events_index = 1  # 1st - StakingRouterETHDeposited

        while deposits_count > deposited:
            queue_index = next(i for i, queue in enumerate(self.queue) if queue)
            item = self.queue[queue_index][0]
            no = self.csm_node_operators[item.no_id]
            keys_count = min(
                item.keys_count,
                deposits_count - deposited,
                depositable_keys[item.no_id],
            )
            if item.keys_count == keys_count:
                # consume the whole item
                keys += b"".join(
                    no.keys[
                        no.deposited_keys
                        + no.withdrawn_keys : no.deposited_keys
                        + no.withdrawn_keys
                        + keys_count
                    ]
                )
                signatures += b"".join(
                    no.signatures[
                        no.deposited_keys
                        + no.withdrawn_keys : no.deposited_keys
                        + no.withdrawn_keys
                        + keys_count
                    ]
                )
                self.queue[queue_index].popleft()
                no.deposited_keys += keys_count
            else:
                # consume part of the item
                keys += b"".join(
                    no.keys[
                        no.deposited_keys
                        + no.withdrawn_keys : no.deposited_keys
                        + no.withdrawn_keys
                        + keys_count
                    ]
                )
                signatures += b"".join(
                    no.signatures[
                        no.deposited_keys
                        + no.withdrawn_keys : no.deposited_keys
                        + no.withdrawn_keys
                        + keys_count
                    ]
                )
                item.keys_count -= keys_count
                no.deposited_keys += keys_count

                if deposited + keys_count != deposits_count:
                    # the rest of the keys of the given validator are not depositable, consume the whole item
                    self.queue[queue_index].popleft()

            deposited += keys_count
            depositable_keys[item.no_id] -= keys_count

            if keys_count > 0:
                assert (
                    CSModule.DepositedSigningKeysCountChanged(
                        item.no_id, no.deposited_keys + no.withdrawn_keys
                    )
                    == tx.events[events_index]
                )
                assert (
                    CSModule.DepositableSigningKeysCountChanged(
                        item.no_id, depositable_keys[item.no_id]
                    )
                    == tx.events[events_index + 1]
                )
                events_index += 2

        if deposits_count != 0:
            self.nonce += 1
            assert CSModule.NonceChanged(self.nonce) == tx.events[events_index]
        else:
            assert not any(e for e in tx.events if isinstance(e, CSModule.NonceChanged))
        events_index += 1

        wc = b"\x01" + b"\x00" * 11 + bytes(self.withdrawal_vault.address)

        for i in range(deposits_count):
            e = tx.events[events_index]
            assert (
                isinstance(e, ExternalEvent)
                and e._event_full_name == "DepositContract.DepositEvent"
                and e.pubkey == keys[i * 48 : i * 48 + 48]
                and e.withdrawal_credentials == wc
                and e.signature == signatures[i * 96 : i * 96 + 96]
            )
            events_index += 1

    @flow()
    def flow_csm_add_consensus_member(self):
        member = random_account()
        quorum = (len(self.consensus_members) + 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            tx = self.hash_consensus.addMember(member, quorum, from_=self.admin)

        if member in self.consensus_members:
            assert e.value is not None
            return "Already added"
        else:
            assert e.value is None
            assert (
                HashConsensus.MemberAdded(
                    member.address, len(self.consensus_members) + 1, quorum
                )
                in tx.events
            )

            if quorum != self.consensus_quorum:
                assert (
                    HashConsensus.QuorumSet(
                        quorum, len(self.consensus_members) + 1, self.consensus_quorum
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, HashConsensus.QuorumSet)
                )

            self.consensus_members.add(member)
            self.consensus_quorum = quorum

            logger.info(f"Added consensus member {member} with quorum {quorum}")

    @flow()
    def flow_csm_remove_consensus_member(self):
        try:
            member = random.choice(list(self.consensus_members))
        except IndexError:
            return "No consensus members"

        quorum = (len(self.consensus_members) - 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            tx = self.hash_consensus.removeMember(member, quorum, from_=self.admin)

        if member in self.consensus_members:
            assert e.value is None
            assert (
                HashConsensus.MemberRemoved(
                    member.address, len(self.consensus_members) - 1, quorum
                )
                in tx.events
            )

            if quorum != self.consensus_quorum:
                assert (
                    HashConsensus.QuorumSet(
                        quorum, len(self.consensus_members) - 1, self.consensus_quorum
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, HashConsensus.QuorumSet)
                )

            self.consensus_members.remove(member)
            self.consensus_quorum = quorum

            logger.info(f"Removed consensus member {member} with quorum {quorum}")
        else:
            assert e.value is not None
            return "Not a member"

    @flow()
    def flow_submit_oracle_data(self):
        ref_slot = get_frame_info(
            chain.blocks["pending"].timestamp, self.initial_epoch
        )[0]
        if ref_slot == self.last_report_ref_slot:
            return "Already reported"
        if len(self.consensus_members) == 0:
            return "No consensus members"
        if len(self.csm_node_operators) == 0:
            return "No node operators"

        consensus_version = 1
        distributed = random_int(0, Wei.from_ether(1))

        self.admin.balance += distributed
        ST_ETH.transact(from_=self.admin, value=distributed)
        shares = ST_ETH.getSharesByPooledEth(distributed)
        self.shares[self.admin] += shares

        reports: List[CSFeeOracle.ReportData] = []
        reward_trees: List[MerkleTree] = []
        distributions: List[List[int]] = []
        node_operators: List[List[int]] = []
        strikes: list[dict[int, dict[int, int]]] = []
        strikes_trees: list[MerkleTree] = []
        # number of pre-generated reports can be adjusted but it will make harder to reach consensus
        for _ in range(3):
            # randomly distribute rewards among N node operators
            distributed = random_int(0, shares)
            strikes_count = random_int(0, 10)
            rebate = random_int(0, shares - distributed)
            N = random_int(0, len(self.csm_node_operators))
            if N == 0 or distributed < N:
                distributed = 0
                distributions.append([])
                node_operators.append([])
            elif N == 1:
                no = random.choice(list(self.csm_node_operators.values()))
                distributions.append([distributed])
                node_operators.append([no.id])
            else:
                cuts = sorted(random.sample(range(1, distributed), N - 1))
                distribution = (
                    [cuts[0]]
                    + [cuts[i] - cuts[i - 1] for i in range(1, N - 1)]
                    + [distributed - cuts[-1]]
                )
                distributions.append(distribution)
                node_operators.append(
                    random.sample(list(self.csm_node_operators.keys()), N)
                )

            rewards_tree = MerkleTree()
            for no in self.csm_node_operators.values():
                try:
                    index = node_operators[-1].index(no.id)
                    rewards_tree.add_leaf(
                        keccak256(
                            abi.encode(
                                uint(no.id),
                                uint(no.total_rewards + distributions[-1][index]),
                            )
                        )
                    )
                except ValueError:
                    rewards_tree.add_leaf(
                        keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                    )

            # prevent empty proof issues
            if len(rewards_tree.leaves) == 1:
                rewards_tree.add_leaf(rewards_tree.leaves[0])

            strikes_tree = MerkleTree()
            deposited_nos = [
                no for no in self.csm_node_operators.values() if no.deposited_keys > 0
            ]
            if not deposited_nos:
                strikes_count = 0

            extra_strikes: dict[int, dict[int, int]] = defaultdict(dict)

            for _ in range(strikes_count):
                no = random.choice(deposited_nos)
                key_index = random_int(
                    no.withdrawn_keys, no.withdrawn_keys + no.deposited_keys - 1
                )

                if no.id not in extra_strikes:
                    extra_strikes[no.id] = {}
                if key_index not in extra_strikes[no.id]:
                    extra_strikes[no.id][key_index] = 0
                extra_strikes[no.id][key_index] += 1

            for no in self.csm_node_operators.values():
                for key_index in set(no.key_strikes.keys()).union(
                    extra_strikes[no.id].keys()
                ):
                    s = no.key_strikes[key_index]

                    if no.id in extra_strikes and key_index in extra_strikes[no.id]:
                        strikes_tree.add_leaf(
                            keccak256(
                                abi.encode(
                                    uint(no.id),
                                    no.keys[key_index],
                                    s + [uint(extra_strikes[no.id][key_index])],
                                )
                            )
                        )
                    else:
                        strikes_tree.add_leaf(
                            keccak256(abi.encode(uint(no.id), no.keys[key_index], s))
                        )

            strikes.append(extra_strikes)
            strikes_trees.append(strikes_tree)

            strikes_tree_root = (
                strikes_tree.root if strikes_tree.leaves else random_bytes(32)
            )
            strikes_tree_cid = strikes_tree_root.hex()

            reports.append(
                CSFeeOracle.ReportData(
                    consensus_version,
                    ref_slot,
                    rewards_tree.root,
                    random_string(32, 32),  # treeCid
                    random_string(32, 32),  # logCid
                    distributed,
                    rebate,
                    strikes_tree_root,
                    strikes_tree_cid,
                )
            )
            reward_trees.append(rewards_tree)

        votes = {keccak256(abi.encode(report)): OrderedSet([]) for report in reports}

        # while not consensus reached
        while True:
            sender = random.choice(self.consensus_members)

            frame_info = get_frame_info(
                chain.blocks["pending"].timestamp, self.initial_epoch
            )
            if frame_info[0] != ref_slot:
                # got into a new frame
                ref_slot = frame_info[0]
                for report in reports:
                    report.refSlot = ref_slot

                votes = {
                    keccak256(abi.encode(report)): OrderedSet([]) for report in reports
                }

            # sender must vote for different report if already voted
            try:
                current_report_hash = next(
                    report_hash
                    for report_hash, voters in votes.items()
                    if sender in voters
                )
                other_reports = [
                    report_hash
                    for report_hash in votes.keys()
                    if report_hash != current_report_hash
                ]
                if len(other_reports) == 0:
                    continue

                report_hash = random.choice(other_reports)
            except StopIteration:
                report_hash = random.choice(list(votes.keys()))

            with may_revert(CSFeeOracle.ProcessingDeadlineMissed) as ex:
                tx = self.hash_consensus.submitReport(
                    ref_slot,
                    report_hash,
                    consensus_version,
                    from_=sender,
                )

            # the error may only happen if we are within the last possible (deadline) slot
            if ex.value is not None:
                t = ex.value.tx.block.timestamp
                assert t > slot_to_timestamp(frame_info[1]) and t < slot_to_timestamp(
                    frame_info[1] + 1
                )
                continue

            assert (
                HashConsensus.ReportReceived(frame_info[0], sender.address, report_hash)
                in tx.events
            )

            for voters in votes.values():
                if sender in voters:
                    voters.remove(sender)
            votes[report_hash].add(sender)

            if any(len(voters) >= self.consensus_quorum for voters in votes.values()):
                assert (
                    HashConsensus.ConsensusReached(
                        frame_info[0],
                        report_hash,
                        max(len(voters) for voters in votes.values()),
                    )
                    in tx.events
                )
                assert (
                    CSFeeOracle.ReportSubmitted(
                        frame_info[0], report_hash, slot_to_timestamp(frame_info[1])
                    )
                    in tx.events
                )
                break
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, HashConsensus.ConsensusReached)
                )
                assert not any(
                    e for e in tx.events if isinstance(e, CSFeeOracle.ReportSubmitted)
                )

        report_hash = next(
            report_hash
            for report_hash, voters in votes.items()
            if len(voters) >= self.consensus_quorum
        )
        report = next(
            report for report in reports if keccak256(abi.encode(report)) == report_hash
        )
        index = reports.index(report)

        ST_ETH.transferShares(
            self.fee_distributor, report.distributed + report.rebate, from_=self.admin
        )
        self.shares[self.admin] -= report.distributed + report.rebate

        sender = random.choice(list(self.consensus_members) + [self.admin])

        with may_revert(CSFeeDistributor.InvalidReportData) as ex:
            tx = self.fee_oracle.submitReportData(
                report,
                2,
                from_=sender,
            )

        if report.distributed == 0 and report.rebate > 0:
            assert ex.value is not None
            # "burn" the shares
            ST_ETH.transferShares(
                Account(1),
                report.distributed + report.rebate,
                from_=self.fee_distributor,
            )
            return "Invalid report data"
        else:
            assert ex.value is None

        if report.distributed > 0:
            self.rewards_tree = reward_trees[index]

            for no, cut in zip(node_operators[index], distributions[index]):
                self.csm_node_operators[no].total_rewards += cut

        self.strikes_tree = strikes_trees[index]
        for no_id in strikes[index].keys():
            for key_index, s in strikes[index][no_id].items():
                self.csm_node_operators[no_id].key_strikes[key_index].append(uint(s))

                assert (
                    keccak256(
                        abi.encode(
                            uint(no_id),
                            self.csm_node_operators[no_id].keys[key_index],
                            self.csm_node_operators[no_id].key_strikes[key_index],
                        )
                    )
                    in self.strikes_tree.leaves
                )

        self.shares[self.fee_distributor] += report.distributed
        self.shares[self.rebate_recipient] += report.rebate

        self.last_report_ref_slot = ref_slot

        self.distribution_history.append(
            CSFeeDistributor.DistributionData(
                ref_slot,
                report.treeRoot,
                report.treeCid,
                report.logCid,
                report.distributed,
                report.rebate,
            )
        )

        assert CSFeeOracle.ProcessingStarted(ref_slot, report_hash) in tx.events
        if report.distributed > 0:
            assert (
                CSFeeDistributor.DistributionDataUpdated(
                    self.shares[self.fee_distributor], report.treeRoot, report.treeCid
                )
                in tx.events
            )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSFeeDistributor.DistributionDataUpdated)
            )
        assert CSFeeDistributor.DistributionLogUpdated(report.logCid) in tx.events
        assert self.fee_oracle.getConsensusReport() == (report_hash, ref_slot, slot_to_timestamp(frame_info[1]), True)

        logger.info(
            f"Submitted oracle data for ref slot {ref_slot} with {report.distributed} stETH shares distributed"
        )

    @flow()
    def flow_pull_rewards(self):
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                    in self.rewards_tree._leaves
                ]
            )
        except IndexError:
            return "No rewards"

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.accounting.pullFeeRewards(
            no.id,
            no.total_rewards,
            self.rewards_tree.get_proof(
                self.rewards_tree._leaves.index(
                    keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                )
            ),
            from_=random_account(),
        )
        claimed = no.total_rewards - no.claimed_rewards
        no.bond_shares += claimed
        no.claimed_rewards = no.total_rewards
        self.shares[self.fee_distributor] -= claimed
        self.shares[self.accounting] += claimed

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        if claimed > 0:
            assert CSFeeDistributor.OperatorFeeDistributed(no.id, claimed) in tx.events
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSFeeDistributor.OperatorFeeDistributed)
            )

        logger.info(f"Pulled {claimed} stETH shares for NO {no.id}")

    @flow()
    def flow_claim_rewards(self):
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                    in self.rewards_tree._leaves
                ]
            )
        except IndexError:
            return "No rewards"
        sender = random.choice([no.manager, no.rewards_account])
        t = chain.blocks["pending"].timestamp

        proof = self.rewards_tree.get_proof(
            self.rewards_tree._leaves.index(
                keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
            )
        )
        if len(proof) == 0:
            # rewards don't get pulled with empty proof
            claimable_shares = self._get_claimable_bond_shares(no, t)
            pulled_shares = 0
        else:
            claimable_shares = self._get_claimable_bond_shares_with_pull(no, t)
            pulled_shares = no.total_rewards - no.claimed_rewards
        shares_to_claim = random_int(0, claimable_shares + 10, edge_values_prob=0.1)

        shares_before = ST_ETH.sharesOf(self.accounting)
        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        with may_revert((CSAccounting.NothingToClaim, ExternalError)) as ex:
            if p < 0.33:
                # unstETH
                balance_before = 0
                tx = self.accounting.claimRewardsUnstETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = (
                    shares_before + pulled_shares - ST_ETH.sharesOf(self.accounting)
                )
            elif p < 0.66:
                # stETH
                balance_before = ST_ETH.sharesOf(no.rewards_account)
                tx = self.accounting.claimRewardsStETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                e = [
                    e
                    for e in tx.raw_events
                    if isinstance(e, UnknownEvent)
                    and e.topics[0]
                    == bytes.fromhex(
                        "9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb"
                    )
                ][-1]
                claimed_shares = abi.decode(e.data, [uint])

                assert (
                    CSAccounting.BondClaimedStETH(
                        no.id,
                        no.rewards_account.address,
                        ST_ETH.getPooledEthByShares(claimed_shares),
                    )
                    in tx.events
                )
            else:
                # wstETH
                balance_before = WST_ETH.balanceOf(no.rewards_account)
                tx = self.accounting.claimRewardsWstETH(
                    no.id,
                    shares_to_claim,
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = (
                    shares_before + pulled_shares - ST_ETH.sharesOf(self.accounting)
                )

                assert (
                    CSAccounting.BondClaimedWstETH(
                        no.id, no.rewards_account.address, claimed_shares
                    )
                    in tx.events
                )

        if isinstance(ex.value, CSAccounting.NothingToClaim):
            assert (
                min(shares_to_claim, claimable_shares) == 0
                or p < 0.66
                and ST_ETH.getSharesByPooledEth(
                    ST_ETH.getPooledEthByShares(shares_to_claim)
                )
                == 0
            )
            return "Nothing to claim"
        elif isinstance(ex.value, ExternalError):
            s = ST_ETH.getPooledEthByShares(
                ST_ETH.getSharesByPooledEth(
                    ST_ETH.getPooledEthByShares(min(shares_to_claim, claimable_shares))
                )
            )
            if p < 0.33 and s < 100:
                assert (
                    ex.value._error_full_name
                    == "WithdrawalQueueERC721.RequestAmountTooSmall"
                )
                return "Request amount too small"
            elif p < 0.33 and s > 1000 * 10**18:
                assert (
                    ex.value._error_full_name
                    == "WithdrawalQueueERC721.RequestAmountTooLarge"
                )
                return "Request amount too large"
            else:
                raise Exception("Unexpected error")
        assert ex.value is None

        # pull part
        if len(proof) != 0:
            no.bond_shares += pulled_shares
            no.claimed_rewards = no.total_rewards
            self.shares[self.fee_distributor] -= pulled_shares
            self.shares[self.accounting] += pulled_shares

            if pulled_shares > 0:
                assert (
                    CSFeeDistributor.OperatorFeeDistributed(no.id, pulled_shares)
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSFeeDistributor.OperatorFeeDistributed)
                )

        # claim part
        print(f"error: {claimed_shares - shares_to_claim}")
        assert claimed_shares <= min(shares_to_claim, claimable_shares)
        assert abs(claimed_shares - shares_to_claim) <= 11
        no.bond_shares -= claimed_shares

        self.shares[self.accounting] -= claimed_shares
        if p < 0.33:
            last_withdrawal_id = abi.decode(
                UNST_ETH.call(abi.encode_with_signature("getLastRequestId()")), [uint]
            )
            assert (
                UNST_ETH.getWithdrawalStatus([last_withdrawal_id])[0].amountOfShares
                == claimed_shares
            )
        elif p < 0.66:
            if no.rewards_account != self.accounting:
                assert (
                    ST_ETH.sharesOf(no.rewards_account)
                    == balance_before + claimed_shares
                )
            else:
                assert (
                    ST_ETH.sharesOf(no.rewards_account)
                    == balance_before + pulled_shares
                )
            self.shares[no.rewards_account] += claimed_shares
        else:
            assert (
                WST_ETH.balanceOf(no.rewards_account) == balance_before + claimed_shares
            )

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Claimed {claimed_shares} stETH shares for NO {no.id}")

    @flow()
    def flow_update_target_validators_limit(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No NO"
        mode = random_int(0, 2)
        limit = random_int(0, 100)

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.csm.updateTargetValidatorsLimits(
            no.id, mode, limit, from_=STAKING_ROUTER
        )

        if mode == 0:
            limit = 0

        no.target_limit = limit
        no.target_limit_mode = mode

        self._reenqueue(no.id, depositable_before)

        # updated even if depositable didn't change
        self.nonce += 1

        assert CSModule.TargetValidatorsCountChanged(no.id, mode, limit) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated target validators limit for NO {no.id}")

    @flow()
    def flow_update_exited_validators_count(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No NO"
        count = random_int(0, no.withdrawn_keys - no.exited_keys)

        tx = self.csm.updateExitedValidatorsCount(
            no.id.to_bytes(8, "big"),
            (no.exited_keys + count).to_bytes(16, "big"),
            from_=STAKING_ROUTER,
        )

        no.exited_keys += count
        self.nonce += 1

        if count > 0:
            assert (
                CSModule.ExitedSigningKeysCountChanged(no.id, no.exited_keys)
                in tx.events
            )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSModule.ExitedSigningKeysCountChanged)
            )

        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated exited validators count for NO {no.id}")

    @flow()
    def flow_decrease_vetted_signing_keys_count(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No NO"
        count = random_int(no.deposited_keys + no.withdrawn_keys, no.vetted_keys)

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert(CSModule.InvalidVetKeysPointer) as e:
            tx = self.csm.decreaseVettedSigningKeysCount(
                no.id.to_bytes(8, "big"),
                count.to_bytes(16, "big"),
                from_=STAKING_ROUTER,
            )

        if count == no.vetted_keys:
            assert e.value is not None
            return "Vetted keys same"
        assert e.value is None

        no.vetted_keys = count
        self._reenqueue(no.id, depositable_before)
        self.nonce += 1

        assert CSModule.VettedSigningKeysCountChanged(no.id, count) in tx.events
        assert CSModule.VettedSigningKeysCountDecreased(no.id) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Decreased vetted signing keys count for NO {no.id} to {count}")

    @flow()
    def flow_unsafe_update_validators_count(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No NO"
        exited = random_int(0, no.withdrawn_keys - no.exited_keys)

        tx = self.csm.unsafeUpdateValidatorsCount(
            no.id,
            exited,
            from_=STAKING_ROUTER,
        )

        if exited != no.exited_keys:
            no.exited_keys = exited
            assert CSModule.ExitedSigningKeysCountChanged(no.id, exited) in tx.events
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSModule.ExitedSigningKeysCountChanged)
            )

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated stuck and exited validators count for NO {no.id}")

    @flow()
    def flow_process_historical_withdrawal_proof(self):
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if no.deposited_keys + no.withdrawn_keys > 0
                ]
            )
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)
        slashed = random_bool()
        amount = (
            random_int(
                1,
                (
                    Wei.from_ether(32)
                    if not slashed
                    else Wei.from_ether(32) - Wei.from_ether(1) // 128
                ),
                max_prob=0.2,
            )
            // 10**9
            * 10**9
        )  # in wei, truncate to gwei

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        old_state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)

        validator = Validator(
            no.keys[index],
            b"\x01" + 11 * b"\x00" + bytes(LIDO_LOCATOR.withdrawalVault()),
            random_int(0, 2**64 - 1),
            slashed,
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, slot // SLOTS_PER_EPOCH),
        )
        validator_root = hash_validator(validator)

        validator_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validator_leaves = [validator_root] + [random_bytes(32) for _ in range(1023)]
        random.shuffle(validator_leaves)
        validator_index = validator_leaves.index(validator_root)

        for leaf in validator_leaves:
            validator_tree.add_leaf(leaf)

        old_state_tree.add_leaf(validator_tree.root)

        withdrawal = Withdrawal(
            random_int(0, 2**64 - 1),
            validator_index,
            LIDO_LOCATOR.withdrawalVault(),
            amount // 10**9,  # in gwei
        )
        withdrawal_root = hash_withdrawal(withdrawal)
        withdrawal_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        withdrawal_leaves = [withdrawal_root] + [random_bytes(32) for _ in range(15)]
        random.shuffle(withdrawal_leaves)
        withdrawal_offset = withdrawal_leaves.index(withdrawal_root)

        for leaf in withdrawal_leaves:
            withdrawal_tree.add_leaf(leaf)

        old_state_tree.add_leaf(withdrawal_tree.root)
        old_state_tree.add_leaf(random_bytes(32))  # historical summaries root
        assert len(old_state_tree.leaves) == 3

        witness = CSVerifier.WithdrawalWitness(
            withdrawal_offset,
            withdrawal.index,
            validator_index,
            amount // 10**9,  # in gwei
            validator.withdrawalCredentials,
            validator.effectiveBalance,
            validator.slashed,
            validator.activationEligibilityEpoch,
            validator.activationEpoch,
            validator.exitEpoch,
            validator.withdrawableEpoch,
            withdrawal_tree.get_proof(withdrawal_offset) + old_state_tree.get_proof(1),
            validator_tree.get_proof(validator_index) + old_state_tree.get_proof(0),
        )

        old_block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            old_state_tree.root,
            random_bytes(32),
        )

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        state_tree.add_leaf(random_bytes(32))  # validator tree root
        state_tree.add_leaf(random_bytes(32))  # withdrawal tree root

        historical_block_roots_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        historical_block_roots_leaves = [random_bytes(32) for _ in range(SLOTS_PER_HISTORICAL_ROOT)]
        historical_block_roots_index = (old_block_header.slot - CAPELLA_SLOT) % SLOTS_PER_HISTORICAL_ROOT
        historical_block_roots_leaves[historical_block_roots_index] = hash_beacon_block_header(old_block_header)
        for leaf in historical_block_roots_leaves:
            historical_block_roots_tree.add_leaf(leaf)
        assert len(historical_block_roots_tree.leaves) == SLOTS_PER_HISTORICAL_ROOT

        # a single historical summary
        historical_summary_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        historical_summary_tree.add_leaf(historical_block_roots_tree.root)
        historical_summary_tree.add_leaf(random_bytes(32))  # states root

        # all historical summaries
        historical_summaries_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        # don't generate all HISTORICAL_SUMMARIES_COUNT leaves randomly, because it's too slow
        historical_summaries_leaves = [random_bytes(32) for _ in range(8192)] + [
            b"\x00" * 32 for _ in range(HISTORICAL_SUMMARIES_COUNT - 8192)
        ]
        historical_summaries_index = (old_block_header.slot - CAPELLA_SLOT) // SLOTS_PER_HISTORICAL_ROOT
        historical_summaries_leaves[historical_summaries_index] = historical_summary_tree.root
        for leaf in historical_summaries_leaves:
            historical_summaries_tree.add_leaf(leaf)
        assert len(historical_summaries_tree.leaves) == HISTORICAL_SUMMARIES_COUNT

        state_tree.add_leaf(historical_summaries_tree.root)
        assert len(state_tree.leaves) == 3

        block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            state_tree.root,
            random_bytes(32),
        )

        root = hash_beacon_block_header(block_header)
        tx = Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").transact(
            root, from_="0xfffffffffffffffffffffffffffffffffffffffe"
        )
        assert (
            Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").call(
                tx.block.timestamp.to_bytes(32, "big")
            )
            == root
        )

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert(CSVerifier.PartialWithdrawal) as e:
            tx = self.verifier.processHistoricalWithdrawalProof(
                CSVerifier.ProvableBeaconBlockHeader(
                    block_header,
                    tx.block.timestamp,
                ),
                CSVerifier.HistoricalHeaderWitness(
                    old_block_header,
                    historical_block_roots_tree.get_proof(historical_block_roots_index)
                    + historical_summary_tree.get_proof(0)
                    + historical_summaries_tree.get_proof(historical_summaries_index)
                    + state_tree.get_proof(2),
                ),
                witness,
                no.id,
                index,
                from_=random_account(),
            )

        if not slashed and amount < Wei.from_ether(8):
            assert e.value == CSVerifier.PartialWithdrawal()
            return "Partial withdrawal"
        elif no.withdrawn[index]:
            assert len(tx.events) == 0
            return "Already submitted"

        assert e.value is None
        assert (
            CSModule.WithdrawalSubmitted(no.id, index, amount, no.keys[index])
            in tx.events
        )

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = Wei.from_ether(32)  # in wei
        penalties = (no.strikes_penalties[index] or 0) + (
            no.exit_delay_penalties[index] or 0
        )
        withdrawal_request_fee = no.withdrawal_request_fees[index] or 0
        if (
            no.strikes_penalties[index] is not None
            or no.exit_delay_penalties[index] is not None
        ) and withdrawal_request_fee > 0:
            shares = min(
                ST_ETH.getSharesByPooledEth(withdrawal_request_fee),
                no.bond_shares,
            )
            no.bond_shares -= shares

            self.shares[self.accounting] -= shares
            self.shares[self.charge_penalty_recipient] += shares

            if shares > 0:
                assert (
                    CSAccounting.BondCharged(
                        no.id,
                        ST_ETH.getPooledEthByShares(
                            ST_ETH.getSharesByPooledEth(withdrawal_request_fee)
                        ),
                        ST_ETH.getPooledEthByShares(shares),
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondCharged)
                )
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondCharged)
            )

        if amount - penalties < max_amount:
            # steth burned
            shares = min(
                ST_ETH.getSharesByPooledEth(max_amount - (amount - penalties)),
                no.bond_shares,
            )
            no.bond_shares -= shares

            self.shares[self.accounting] -= shares
            self.shares[BURNER] += shares

            if shares > 0:
                assert (
                    CSAccounting.BondBurned(
                        no.id,
                        ST_ETH.getPooledEthByShares(
                            ST_ETH.getSharesByPooledEth(
                                max_amount - (amount - penalties)
                            )
                        ),
                        ST_ETH.getPooledEthByShares(shares),
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondBurned)
                )
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondBurned)
            )

        no.withdrawn[index] = True

        self._reenqueue(no.id, depositable_before)

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Processed historical withdrawal proof for NO {no.id}")

    @flow()
    def flow_process_withdrawal_proof(self):
        try:
            no = random.choice(
                [
                    no
                    for no in self.csm_node_operators.values()
                    if no.deposited_keys + no.withdrawn_keys > 0
                ]
            )
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)
        slashed = random_bool()
        amount = (
            random_int(
                1,
                (
                    Wei.from_ether(32)
                    if not slashed
                    else Wei.from_ether(32) - Wei.from_ether(1) // 128
                ),
                max_prob=0.2,
            )
            // 10**9
            * 10**9
        )  # in wei, truncate to gwei

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        validator = Validator(
            no.keys[index],
            b"\x01" + 11 * b"\x00" + bytes(LIDO_LOCATOR.withdrawalVault()),
            random_int(0, 2**64 - 1),
            slashed,
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, slot // SLOTS_PER_EPOCH),
        )
        validator_root = hash_validator(validator)

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)

        validator_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validator_leaves = [validator_root] + [random_bytes(32) for _ in range(1023)]
        random.shuffle(validator_leaves)
        validator_index = validator_leaves.index(validator_root)

        for leaf in validator_leaves:
            validator_tree.add_leaf(leaf)

        state_tree.add_leaf(validator_tree.root)

        withdrawal = Withdrawal(
            random_int(0, 2**64 - 1),
            validator_index,
            LIDO_LOCATOR.withdrawalVault(),
            amount // 10**9,  # in gwei
        )
        withdrawal_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        withdrawal_root = hash_withdrawal(withdrawal)
        withdrawal_leaves = [withdrawal_root] + [random_bytes(32) for _ in range(15)]
        random.shuffle(withdrawal_leaves)
        withdrawal_offset = withdrawal_leaves.index(withdrawal_root)

        for leaf in withdrawal_leaves:
            withdrawal_tree.add_leaf(leaf)

        state_tree.add_leaf(withdrawal_tree.root)

        state_tree.add_leaf(random_bytes(32))  # historical summaries root
        assert len(state_tree.leaves) == 3

        witness = CSVerifier.WithdrawalWitness(
            withdrawal_offset,
            withdrawal.index,
            validator_index,
            amount // 10**9,  # in gwei
            validator.withdrawalCredentials,
            validator.effectiveBalance,
            validator.slashed,
            validator.activationEligibilityEpoch,
            validator.activationEpoch,
            validator.exitEpoch,
            validator.withdrawableEpoch,
            withdrawal_tree.get_proof(withdrawal_offset) + state_tree.get_proof(1),
            validator_tree.get_proof(validator_index) + state_tree.get_proof(0),
        )

        block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            state_tree.root,
            random_bytes(32),
        )

        root = hash_beacon_block_header(block_header)
        tx = Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").transact(
            root, from_="0xfffffffffffffffffffffffffffffffffffffffe"
        )
        assert (
            Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").call(
                tx.block.timestamp.to_bytes(32, "big")
            )
            == root
        )

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert(CSVerifier.PartialWithdrawal) as e:
            tx = self.verifier.processWithdrawalProof(
                CSVerifier.ProvableBeaconBlockHeader(
                    block_header,
                    tx.block.timestamp,
                ),
                witness,
                no.id,
                index,
                from_=random_account(),
            )

        if not slashed and amount < Wei.from_ether(8):
            assert e.value == CSVerifier.PartialWithdrawal()
            return "Partial withdrawal"
        elif no.withdrawn[index]:
            assert len(tx.events) == 0
            return "Already submitted"

        assert e.value is None
        assert (
            CSModule.WithdrawalSubmitted(no.id, index, amount, no.keys[index])
            in tx.events
        )

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = Wei.from_ether(32)  # in wei
        penalties = (no.strikes_penalties[index] or 0) + (
            no.exit_delay_penalties[index] or 0
        )
        withdrawal_request_fee = no.withdrawal_request_fees[index] or 0
        if (
            no.strikes_penalties[index] is not None
            or no.exit_delay_penalties[index] is not None
        ) and withdrawal_request_fee > 0:
            shares = min(
                ST_ETH.getSharesByPooledEth(withdrawal_request_fee),
                no.bond_shares,
            )
            no.bond_shares -= shares

            self.shares[self.accounting] -= shares
            self.shares[self.charge_penalty_recipient] += shares

            if shares > 0:
                assert (
                    CSAccounting.BondCharged(
                        no.id,
                        ST_ETH.getPooledEthByShares(
                            ST_ETH.getSharesByPooledEth(withdrawal_request_fee)
                        ),
                        ST_ETH.getPooledEthByShares(shares),
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondCharged)
                )
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondCharged)
            )

        if amount - penalties < max_amount:
            # steth burned
            shares = min(
                ST_ETH.getSharesByPooledEth(max_amount - (amount - penalties)),
                no.bond_shares,
            )
            no.bond_shares -= shares

            self.shares[self.accounting] -= shares
            self.shares[BURNER] += shares

            if shares > 0:
                assert (
                    CSAccounting.BondBurned(
                        no.id,
                        ST_ETH.getPooledEthByShares(
                            ST_ETH.getSharesByPooledEth(
                                max_amount - (amount - penalties)
                            )
                        ),
                        ST_ETH.getPooledEthByShares(shares),
                    )
                    in tx.events
                )
            else:
                assert not any(
                    e for e in tx.events if isinstance(e, CSAccounting.BondBurned)
                )
        else:
            assert not any(
                e for e in tx.events if isinstance(e, CSAccounting.BondBurned)
            )

        no.withdrawn[index] = True

        self._reenqueue(no.id, depositable_before)

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Processed withdrawal proof for NO {no.id}")

    @flow(max_times=10)
    def flow_add_bond_curve(self):
        curve = random_bond_curve()

        tx = self.accounting.addBondCurve(curve, from_=self.admin)

        assert len(self.curves) == tx.return_value
        self.curves.append(curve)

        self.parameters[tx.return_value] = Parameters()

        logger.info(f"Added bond curve {len(self.curves) - 1}")

    @flow()
    def flow_update_bond_curve(self):
        curve_id = random_int(0, len(self.curves) - 1)
        curve = random_bond_curve()

        tx = self.accounting.updateBondCurve(curve_id, curve, from_=self.admin)

        self.curves[curve_id] = curve

        logger.info(f"Updated bond curve {curve_id}")

    @flow()
    def flow_set_bond_curve(self):
        try:
            no = random.choice(list(self.csm_node_operators.values()))
        except IndexError:
            return "No node operators"

        curve_id = random_int(0, len(self.curves) - 1)

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.accounting.setBondCurve(no.id, curve_id, from_=self.admin)

        no.curve_id = curve_id

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Set bond curve {curve_id} for NO {no.id}")

    @flow()
    def flow_start_referral_season(self):
        curve_id = random_int(0, len(self.curves) - 1)
        threshold = random_int(1, 2)

        with may_revert() as ex:
            tx = self.vetted_gate.startNewReferralProgramSeason(
                curve_id,
                threshold,
                from_=self.admin,
            )

        if self.vetted_season_active:
            assert ex.value == VettedGate.ReferralProgramIsActive()
            return "Season active"
        if curve_id == DEFAULT_CURVE_ID:
            assert ex.value == VettedGate.InvalidCurveId()
            return "Invalid curve id"
        else:
            assert ex.value is None

        self.vetted_season_active = True
        self.referral_season_id += 1
        self.referral_season_threshold = threshold
        self.referral_season_curve_id = curve_id

        self.vetted_referrals.clear()
        self.claimed_referrers.clear()

        assert (
            VettedGate.ReferralProgramSeasonStarted(
                self.referral_season_id, curve_id, threshold
            )
            in tx.events
        )

        logger.info(
            f"Started referral season with curve {curve_id} and threshold {threshold}"
        )

    @flow()
    def flow_claim_referrer_bond_curve(self):
        if not self.vetted_accounts:
            return "No vetted accounts"
        if not self.csm_node_operators:
            return "No node operators"

        sender = random.choice(list(self.vetted_accounts))
        no = random.choice(list(self.csm_node_operators.values()))

        depositable_before = self.csm.getNodeOperator(no.id).depositableValidatorsCount

        # temporarily transfer ownership to make the claim possible
        with self._change_manager(no, sender):
            with may_revert() as ex:
                tx = self.vetted_gate.claimReferrerBondCurve(
                    no.id,
                    self.vetted_tree.get_proof(
                        self.vetted_tree.leaves.index(keccak256(abi.encode(sender)))
                    ),
                    from_=sender,
                )

        if not self.vetted_season_active:
            assert ex.value == VettedGate.ReferralProgramIsNotActive()
            return "Season not active"
        elif self.vetted_referrals[sender] < self.referral_season_threshold:
            assert ex.value == VettedGate.NotEnoughReferrals()
            return "Not enough referrals"
        elif sender in self.claimed_referrers:
            assert ex.value == VettedGate.AlreadyConsumed()
            return "Already consumed"
        else:
            assert ex.value is None

        assert (
            VettedGate.ReferrerConsumed(sender.address, self.referral_season_id)
            in tx.events
        )
        assert (
            CSAccounting.BondCurveSet(no.id, self.referral_season_curve_id) in tx.events
        )

        no.curve_id = self.referral_season_curve_id

        self.claimed_referrers.add(sender)

        self._reenqueue(no.id, depositable_before, update_nonce=True, tx=tx)

        logger.info(f"Claimed referrer bond curve for NO {no.id}")

    @flow(weight=30)
    def flow_end_referral_season(self):

        with may_revert() as ex:
            tx = self.vetted_gate.endCurrentReferralProgramSeason(from_=self.admin)

        if not self.vetted_season_active:
            assert ex.value == VettedGate.ReferralProgramIsNotActive()
            return "Season not active"
        else:
            assert ex.value is None

        self.vetted_season_active = False

        assert (
            VettedGate.ReferralProgramSeasonEnded(self.referral_season_id) in tx.events
        )

        logger.info(f"Ended referral season {self.referral_season_id}")

    @flow()
    def flow_set_rebate_recipient(self):
        recipient = random_account()

        tx = self.fee_distributor.setRebateRecipient(recipient, from_=self.admin)
        assert CSFeeDistributor.RebateRecipientSet(recipient.address) in tx.events

        self.rebate_recipient = recipient

        logger.info(f"Set rebate recipient to {recipient}")

    @flow()
    def flow_process_bad_performance_proof(self):
        nos: list[tuple[int, int]] = []

        for no in self.csm_node_operators.values():
            strikes_threshold = self.parameters[no.curve_id].strikes_info[1]
            for deposited_key in range(
                no.withdrawn_keys, no.withdrawn_keys + no.deposited_keys
            ):
                if (
                    not no.withdrawn[deposited_key]
                    and sum(no.key_strikes[deposited_key]) >= strikes_threshold
                ):
                    nos.append((no.id, deposited_key))

        if not nos:
            return "No node operators with bad performance"

        nos = random.sample(nos, random_int(1, min(10, len(nos))))

        refund_recipient = random_account()

        leaves = [
            keccak256(
                abi.encode(
                    uint(no_id),
                    self.csm_node_operators[no_id].keys[key_index],
                    self.csm_node_operators[no_id].key_strikes[key_index],
                )
            )
            for no_id, key_index in nos
        ]
        key_strikes = [
            CSStrikes.KeyStrikes(
                no_id, key_index, self.csm_node_operators[no_id].key_strikes[key_index]
            )
            for no_id, key_index in nos
        ]
        key_strikes.sort(
            key=lambda x: self.strikes_tree.leaves.index(
                keccak256(
                    abi.encode(
                        uint(x.nodeOperatorId),
                        self.csm_node_operators[x.nodeOperatorId].keys[x.keyIndex],
                        self.csm_node_operators[x.nodeOperatorId].key_strikes[
                            x.keyIndex
                        ],
                    )
                )
            )
        )
        leaves.sort(key=lambda x: self.strikes_tree.leaves.index(x))

        proof = self.strikes_tree.get_multiproof(
            [self.strikes_tree.leaves.index(leaf) for leaf in leaves]
        )

        withdrawal_request_fee = abi.decode(
            Account("0x00000961Ef480Eb55e80D19ad83579A64c007002").call(), [uint256]
        )
        sender = random_account()
        value = random_int(
            withdrawal_request_fee * len(nos),
            (withdrawal_request_fee + random_int(1, 1_000)) * len(nos),
            min_prob=0.33,
        )
        value = value - value % len(nos)

        sender.balance += value

        current_exit_limit = self._calculate_current_exit_limit(
            self.tw_limits, chain.blocks["pending"].timestamp
        )

        with may_revert() as ex:
            tx = self.strikes.processBadPerformanceProof(
                key_strikes,
                proof[0],
                proof[1],
                refund_recipient,
                from_=sender,
                value=value,
            )

        if len(key_strikes) > current_exit_limit:
            # exit requests are actually processed one by one
            assert ex.value == TriggerableWithdrawalsGateway.ExitRequestsLimitExceeded(1, 0)
            sender.balance -= value
            return "Exit requests limit exceeded"
        else:
            assert ex.value is None

        self.balances[refund_recipient] += value - withdrawal_request_fee * len(nos)

        for no_id, key_index in nos:
            no = self.csm_node_operators[no_id]
            penalty = self.parameters[no.curve_id].bad_performance_penalty
            pubkey = no.keys[key_index]

            if no.strikes_penalties[key_index] is None:
                no.strikes_penalties[key_index] = penalty

                assert (
                    CSExitPenalties.StrikesPenaltyProcessed(no_id, pubkey, penalty)
                ) in tx.events
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSExitPenalties.StrikesPenaltyProcessed)
                    and e.nodeOperatorId == no_id
                    and e.pubkey == pubkey
                )

            self.csm_on_validator_exit_triggered(
                withdrawal_request_fee,
                no_id,
                pubkey,
                1,
                tx,
            )

        self._update_tw_exit_limits(current_exit_limit, len(key_strikes), tx.block.timestamp)

        logger.info(f"Processed bad performance proof for {len(nos)} keys")

    def csm_on_validator_exit_triggered(
        self, withdrawal_request_fee: int, no_id: int, pubkey: bytes, exit_type: int, tx: TransactionAbc
    ):
        # 0 - voluntary exit, 1 - bad performance, 2 - veb(o) exit
        if exit_type == 0:
            return

        no = self.csm_node_operators[no_id]
        key_index = no.keys.index(pubkey)

        if no.withdrawal_request_fees[key_index] is None:
            actual_fee = min(
                withdrawal_request_fee,
                self.parameters[no.curve_id].max_withdrawal_request_fee,
            )
            no.withdrawal_request_fees[key_index] = actual_fee

            assert (
                CSExitPenalties.TriggeredExitFeeRecorded(
                    no_id, exit_type, pubkey, withdrawal_request_fee, actual_fee
                )
                in tx.events
            )
        else:
            assert not any(
                e
                for e in tx.events
                if isinstance(e, CSExitPenalties.TriggeredExitFeeRecorded)
                and e.nodeOperatorId == no_id
                and e.pubkey == pubkey
            )

    @flow()
    def flow_voluntary_eject(self):
        nos: dict[int, list[int]] = defaultdict(list)

        for no in self.csm_node_operators.values():
            for deposited_key in range(
                no.withdrawn_keys, no.withdrawn_keys + no.deposited_keys
            ):
                if not no.withdrawn[deposited_key]:
                    nos[no.id].append(deposited_key)

        if not nos:
            return "No node operators with deposited keys"

        no_id = random.choice(list(nos.keys()))
        no = self.csm_node_operators[no_id]
        keys = sorted(nos[no_id])

        # Find consecutive sequences
        sequences = []
        current_seq = [keys[0]]

        for i in range(1, len(keys)):
            if keys[i] == current_seq[-1] + 1:
                current_seq.append(keys[i])
            else:
                sequences.append(current_seq)
                current_seq = [keys[i]]
        sequences.append(current_seq)

        # Choose a random sequence
        chosen_seq = random.choice(sequences)
        start_key = chosen_seq[0]
        keys_count = random_int(0, len(chosen_seq))

        refund_recipient = random_account()
        sender = no.manager if no.extended_permissions else no.rewards_account

        withdrawal_request_fee = abi.decode(
            Account("0x00000961Ef480Eb55e80D19ad83579A64c007002").call(), [uint256]
        )
        value = random_int(
            withdrawal_request_fee * keys_count,
            withdrawal_request_fee * keys_count + random_int(1, 1_000),
            min_prob=0.33,
        )

        sender.balance += value

        current_exit_limit = self._calculate_current_exit_limit(
            self.tw_limits, chain.blocks["pending"].timestamp
        )

        with may_revert() as ex:
            tx = self.ejector.voluntaryEject(
                no_id, start_key, keys_count, refund_recipient, from_=sender, value=value
            )

        if value == 0:
            assert ex.value == TriggerableWithdrawalsGateway.ZeroArgument("msg.value")
            return "Zero value"
        elif keys_count == 0:
            assert ex.value == TriggerableWithdrawalsGateway.ZeroArgument("validatorsData")
            sender.balance -= value
            return "Zero keys to eject"
        elif keys_count > current_exit_limit:
            assert ex.value == TriggerableWithdrawalsGateway.ExitRequestsLimitExceeded(
                keys_count, current_exit_limit
            )
            sender.balance -= value
            return "Exit requests limit exceeded"
        else:
            assert ex.value is None

        for key_index in range(keys_count):
            pubkey = no.keys[start_key + key_index]
            self.csm_on_validator_exit_triggered(
                withdrawal_request_fee,
                no_id,
                pubkey,
                0,
                tx,
            )

        self.balances[refund_recipient] += value - withdrawal_request_fee * keys_count

        self._update_tw_exit_limits(current_exit_limit, keys_count, tx.block.timestamp)

        logger.info(f"Voluntary ejected {keys_count} keys for NO {no_id}")

    @flow()
    def flow_voluntary_eject_by_array(self):
        nos: dict[int, list[int]] = defaultdict(list)

        for no in self.csm_node_operators.values():
            for deposited_key in range(
                no.withdrawn_keys, no.withdrawn_keys + no.deposited_keys
            ):
                if not no.withdrawn[deposited_key]:
                    nos[no.id].append(deposited_key)

        if not nos:
            return "No node operators with deposited keys"

        no_id = random.choice(list(nos.keys()))
        no = self.csm_node_operators[no_id]
        keys = random.sample(nos[no.id], random_int(0, len(nos[no.id])))

        refund_recipient = random_account()
        sender = no.manager if no.extended_permissions else no.rewards_account

        withdrawal_request_fee = abi.decode(
            Account("0x00000961Ef480Eb55e80D19ad83579A64c007002").call(), [uint256]
        )
        value = random_int(
            withdrawal_request_fee * len(keys),
            withdrawal_request_fee * len(keys) + random_int(1, 1_000),
            min_prob=0.33,
        )

        sender.balance += value

        current_exit_limit = self._calculate_current_exit_limit(
            self.tw_limits, chain.blocks["pending"].timestamp
        )

        with may_revert() as ex:
            tx = self.ejector.voluntaryEjectByArray(
                no_id, keys, refund_recipient, from_=sender, value=value
            )

        if value == 0:
            assert ex.value == TriggerableWithdrawalsGateway.ZeroArgument("msg.value")
            return "Zero value"
        elif len(keys) == 0:
            assert ex.value == TriggerableWithdrawalsGateway.ZeroArgument("validatorsData")
            sender.balance -= value
            return "Zero keys to eject"
        elif len(keys) > current_exit_limit:
            assert ex.value == TriggerableWithdrawalsGateway.ExitRequestsLimitExceeded(
                len(keys), current_exit_limit
            )
            sender.balance -= value
            return "Exit requests limit exceeded"
        else:
            assert ex.value is None

        for key_index in keys:
            pubkey = no.keys[key_index]
            self.csm_on_validator_exit_triggered(
                withdrawal_request_fee,
                no_id,
                pubkey,
                0,
                tx,
            )

        self.balances[refund_recipient] += value - withdrawal_request_fee * len(keys)

        self._update_tw_exit_limits(current_exit_limit, len(keys), tx.block.timestamp)

        logger.info(f"Voluntary ejected {len(keys)} keys for NO {no_id}")

    def csm_on_validator_exit_delay(self, no_id: int, pubkey: bytes, eligible_to_exit: int, penalty_applicable: bool, tx: TransactionAbc):
        no = self.csm_node_operators[no_id]
        key_index = no.keys.index(pubkey)

        exit_delay_penalty = self.parameters[no.curve_id].exit_delay_penalty

        if eligible_to_exit <= self.parameters[no.curve_id].allowed_exit_delay:
            assert tx.error == CSExitPenalties.ValidatorExitDelayNotApplicable()
            assert not penalty_applicable
            return "Validator exit delay not applicable"
        elif no.exit_delay_penalties[key_index] is not None:
            assert not any(
                e for e in tx.events
                if isinstance(e, CSExitPenalties.ValidatorExitDelayProcessed)
                and e.nodeOperatorId == no.id
                and e.pubkey == pubkey
            )
            assert not penalty_applicable
            # return None so that it's not handled as an error (revert)
            return

        assert penalty_applicable

        if tx.error is None:
            assert (
                CSExitPenalties.ValidatorExitDelayProcessed(
                    no.id,
                    no.keys[key_index],
                    exit_delay_penalty,
                )
                in tx.events
            )

            no.exit_delay_penalties[key_index] = exit_delay_penalty

    @flow()
    def flow_update_depositable_validators_count(self):
        try:
            no_id = random.choice(list(self.csm_node_operators.keys()))
        except IndexError:
            return "No node operators"

        depositable_before = self.csm.getNodeOperator(
            no_id
        ).depositableValidatorsCount

        tx = self.csm.updateDepositableValidatorsCount(no_id, from_=random_account())

        self._reenqueue(no_id, depositable_before, update_nonce=True)

        logger.info(f"Updated depositable validators count for NO {no_id}")

    @flow()
    def flow_set_default_key_removal_charge(self):
        charge = random_int(0, Wei.from_ether(0.05), min_prob=0.05)

        tx = self.parameters_registry.setDefaultKeyRemovalCharge(
            charge, from_=self.admin
        )
        assert CSParametersRegistry.DefaultKeyRemovalChargeSet(charge) in tx.events

        DEFAULT_PARAMETERS.keyRemovalCharge = charge

        logger.info(f"Set default key removal charge to {charge}")

    @flow()
    def flow_set_key_removal_charge(self):
        curve_id = random.choice(list(self.parameters.keys()))
        charge = random_int(0, Wei.from_ether(0.05), min_prob=0.05)

        tx = self.parameters_registry.setKeyRemovalCharge(
            curve_id, charge, from_=self.admin
        )
        assert CSParametersRegistry.KeyRemovalChargeSet(curve_id, charge) in tx.events

        self.parameters[curve_id].key_removal_charge = charge

        logger.info(f"Set key removal charge for curve {curve_id} to {charge}")

    @flow()
    def flow_unset_key_removal_charge(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetKeyRemovalCharge(curve_id, from_=self.admin)
        assert CSParametersRegistry.KeyRemovalChargeUnset(curve_id) in tx.events

        self.parameters[curve_id].key_removal_charge = None

        logger.info(f"Unset key removal charge for curve {curve_id}")

    @flow()
    def flow_set_default_el_rewards_stealing_additional_fine(self):
        fine = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setDefaultElRewardsStealingAdditionalFine(
            fine, from_=self.admin
        )
        assert (
            CSParametersRegistry.DefaultElRewardsStealingAdditionalFineSet(fine)
            in tx.events
        )

        DEFAULT_PARAMETERS.elRewardsStealingAdditionalFine = fine

        logger.info(f"Set default EL rewards stealing additional fine to {fine}")

    @flow()
    def flow_set_el_rewards_stealing_additional_fine(self):
        curve_id = random.choice(list(self.parameters.keys()))
        fine = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setElRewardsStealingAdditionalFine(
            curve_id, fine, from_=self.admin
        )
        assert (
            CSParametersRegistry.ElRewardsStealingAdditionalFineSet(curve_id, fine)
            in tx.events
        )

        self.parameters[curve_id].el_rewards_stealing_additional_fine = fine

        logger.info(
            f"Set EL rewards stealing additional fine for curve {curve_id} to {fine}"
        )

    @flow()
    def flow_unset_el_rewards_stealing_additional_fine(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetElRewardsStealingAdditionalFine(
            curve_id, from_=self.admin
        )
        assert (
            CSParametersRegistry.ElRewardsStealingAdditionalFineUnset(curve_id)
            in tx.events
        )

        self.parameters[curve_id].el_rewards_stealing_additional_fine = None

        logger.info(f"Unset EL rewards stealing additional fine for curve {curve_id}")

    @flow()
    def flow_set_default_keys_limit(self):
        limit = random_int(0, 1_000, edge_values_prob=0.05)

        tx = self.parameters_registry.setDefaultKeysLimit(limit, from_=self.admin)
        assert CSParametersRegistry.DefaultKeysLimitSet(limit) in tx.events

        DEFAULT_PARAMETERS.keysLimit = limit

        logger.info(f"Set default keys limit to {limit}")

    @flow()
    def flow_set_keys_limit(self):
        curve_id = random.choice(list(self.parameters.keys()))
        limit = random_int(0, 1_000, edge_values_prob=0.05)

        tx = self.parameters_registry.setKeysLimit(curve_id, limit, from_=self.admin)
        assert CSParametersRegistry.KeysLimitSet(curve_id, limit) in tx.events

        self.parameters[curve_id].keys_limit = limit

        logger.info(f"Set keys limit for curve {curve_id} to {limit}")

    @flow()
    def flow_unset_keys_limit(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetKeysLimit(curve_id, from_=self.admin)
        assert CSParametersRegistry.KeysLimitUnset(curve_id) in tx.events

        self.parameters[curve_id].keys_limit = None

        logger.info(f"Unset keys limit for curve {curve_id}")

    @flow()
    def flow_set_default_strikes_params(self):
        lifetime = random_int(0, uint32.max, edge_values_prob=0.01)  # unused
        threshold = random_int(0, 4, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setDefaultStrikesParams(
                lifetime, threshold, from_=self.admin
            )

        if lifetime == 0 or threshold == 0:
            assert ex.value == CSParametersRegistry.InvalidStrikesParams()
            return "Invalid strikes params"
        else:
            assert ex.value is None

        assert (
            CSParametersRegistry.DefaultStrikesParamsSet(lifetime, threshold)
            in tx.events
        )
        DEFAULT_PARAMETERS.strikesLifetime = lifetime
        DEFAULT_PARAMETERS.strikesThreshold = threshold

        logger.info(
            f"Set default strikes params to lifetime {lifetime} and threshold {threshold}"
        )

    @flow()
    def flow_set_strikes_params(self):
        curve_id = random.choice(list(self.parameters.keys()))
        lifetime = random_int(0, uint32.max, edge_values_prob=0.01)  # unused
        threshold = random_int(0, 4, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setStrikesParams(
                curve_id, lifetime, threshold, from_=self.admin
            )

        if lifetime == 0 or threshold == 0:
            assert ex.value == CSParametersRegistry.InvalidStrikesParams()
            return "Invalid strikes params"
        else:
            assert ex.value is None

        assert (
            CSParametersRegistry.StrikesParamsSet(curve_id, lifetime, threshold)
            in tx.events
        )

        self.parameters[curve_id].strikes_info = (lifetime, threshold)

        logger.info(
            f"Set strikes params for curve {curve_id} to lifetime {lifetime} and threshold {threshold}"
        )

    @flow()
    def flow_unset_strikes_params(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetStrikesParams(curve_id, from_=self.admin)
        assert CSParametersRegistry.StrikesParamsUnset(curve_id) in tx.events

        self.parameters[curve_id].strikes_info = (0, 0)

        logger.info(f"Unset strikes params for curve {curve_id}")

    @flow()
    def flow_set_default_bad_performance_penalty(self):
        penalty = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setDefaultBadPerformancePenalty(
            penalty, from_=self.admin
        )
        assert (
            CSParametersRegistry.DefaultBadPerformancePenaltySet(penalty) in tx.events
        )

        DEFAULT_PARAMETERS.badPerformancePenalty = penalty

        logger.info(f"Set default bad performance penalty to {penalty}")

    @flow()
    def flow_set_bad_performance_penalty(self):
        curve_id = random.choice(list(self.parameters.keys()))
        penalty = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setBadPerformancePenalty(
            curve_id, penalty, from_=self.admin
        )
        assert (
            CSParametersRegistry.BadPerformancePenaltySet(curve_id, penalty)
            in tx.events
        )

        self.parameters[curve_id].bad_performance_penalty = penalty

        logger.info(f"Set bad performance penalty for curve {curve_id} to {penalty}")

    @flow()
    def flow_unset_bad_performance_penalty(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetBadPerformancePenalty(
            curve_id, from_=self.admin
        )
        assert CSParametersRegistry.BadPerformancePenaltyUnset(curve_id) in tx.events

        self.parameters[curve_id].bad_performance_penalty = None

        logger.info(f"Unset bad performance penalty for curve {curve_id}")

    @flow()
    def flow_set_default_queue_config(self):
        priority = random_int(0, QUEUE_LOWEST_PRIORITY)
        max_deposits = random_int(0, 1_000, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setDefaultQueueConfig(
                priority, max_deposits, from_=self.admin
            )

        if priority == QUEUE_LOWEST_PRIORITY - 1:
            assert ex.value == CSParametersRegistry.QueueCannotBeUsed()
            return "Queue cannot be used"
        elif max_deposits == 0:
            assert ex.value == CSParametersRegistry.ZeroMaxDeposits()
            return "Zero max deposits"
        else:
            assert ex.value is None

        assert (
            CSParametersRegistry.DefaultQueueConfigSet(priority, max_deposits)
            in tx.events
        )

        DEFAULT_PARAMETERS.defaultQueuePriority = priority
        DEFAULT_PARAMETERS.defaultQueueMaxDeposits = max_deposits

        logger.info(
            f"Set default queue config to priority {priority} and max deposits {max_deposits}"
        )

    @flow()
    def flow_set_queue_config(self):
        curve_id = random.choice(list(self.parameters.keys()))
        priority = random_int(0, QUEUE_LOWEST_PRIORITY)
        max_deposits = random_int(0, 1_000, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setQueueConfig(
                curve_id, priority, max_deposits, from_=self.admin
            )

        if priority == QUEUE_LOWEST_PRIORITY - 1:
            assert ex.value == CSParametersRegistry.QueueCannotBeUsed()
            return "Queue cannot be used"
        elif max_deposits == 0:
            assert ex.value == CSParametersRegistry.ZeroMaxDeposits()
            return "Zero max deposits"
        else:
            assert ex.value is None

        assert (
            CSParametersRegistry.QueueConfigSet(curve_id, priority, max_deposits)
            in tx.events
        )

        self.parameters[curve_id].queue_config = (priority, max_deposits)

        logger.info(
            f"Set queue config for curve {curve_id} to priority {priority} and max deposits {max_deposits}"
        )

    @flow()
    def flow_unset_queue_config(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetQueueConfig(curve_id, from_=self.admin)
        assert CSParametersRegistry.QueueConfigUnset(curve_id) in tx.events

        self.parameters[curve_id].queue_config = (0, 0)

        logger.info(f"Unset queue config for curve {curve_id}")

    @flow()
    def flow_set_default_allowed_exit_delay(self):
        delay = random_int(0, 1_000, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setDefaultAllowedExitDelay(
                delay, from_=self.admin
            )

        if delay == 0:
            assert ex.value == CSParametersRegistry.InvalidAllowedExitDelay()
            return "Invalid allowed exit delay"
        else:
            assert ex.value is None

        assert CSParametersRegistry.DefaultAllowedExitDelaySet(delay) in tx.events

        DEFAULT_PARAMETERS.defaultAllowedExitDelay = delay

        logger.info(f"Set default allowed exit delay to {delay}")

    @flow()
    def flow_set_allowed_exit_delay(self):
        curve_id = random.choice(list(self.parameters.keys()))
        delay = random_int(0, 1_000, edge_values_prob=0.01)

        with may_revert() as ex:
            tx = self.parameters_registry.setAllowedExitDelay(
                curve_id, delay, from_=self.admin
            )

        if delay == 0:
            assert ex.value == CSParametersRegistry.InvalidAllowedExitDelay()
            return "Invalid allowed exit delay"
        else:
            assert ex.value is None

        assert CSParametersRegistry.AllowedExitDelaySet(curve_id, delay) in tx.events

        self.parameters[curve_id].allowed_exit_delay = delay

        logger.info(f"Set allowed exit delay for curve {curve_id} to {delay}")

    @flow()
    def flow_unset_allowed_exit_delay(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetAllowedExitDelay(curve_id, from_=self.admin)
        assert CSParametersRegistry.AllowedExitDelayUnset(curve_id) in tx.events

        self.parameters[curve_id].allowed_exit_delay = 0

        logger.info(f"Unset allowed exit delay for curve {curve_id}")

    @flow()
    def flow_set_default_exit_delay_penalty(self):
        penalty = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setDefaultExitDelayPenalty(
            penalty, from_=self.admin
        )
        assert CSParametersRegistry.DefaultExitDelayPenaltySet(penalty) in tx.events

        DEFAULT_PARAMETERS.defaultExitDelayPenalty = penalty

        logger.info(f"Set default exit delay penalty to {penalty}")

    @flow()
    def flow_set_exit_delay_penalty(self):
        curve_id = random.choice(list(self.parameters.keys()))
        penalty = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setExitDelayPenalty(
            curve_id, penalty, from_=self.admin
        )
        assert CSParametersRegistry.ExitDelayPenaltySet(curve_id, penalty) in tx.events

        self.parameters[curve_id].exit_delay_penalty = penalty

        logger.info(f"Set exit delay penalty for curve {curve_id} to {penalty}")

    @flow()
    def flow_unset_exit_delay_penalty(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetExitDelayPenalty(curve_id, from_=self.admin)
        assert CSParametersRegistry.ExitDelayPenaltyUnset(curve_id) in tx.events

        self.parameters[curve_id].exit_delay_penalty = None

    @flow()
    def flow_set_default_max_withdrawal_request_fee(self):
        fee = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setDefaultMaxWithdrawalRequestFee(
            fee, from_=self.admin
        )
        assert CSParametersRegistry.DefaultMaxWithdrawalRequestFeeSet(fee) in tx.events

        DEFAULT_PARAMETERS.defaultMaxWithdrawalRequestFee = fee

        logger.info(f"Set default max withdrawal request fee to {fee}")

    @flow()
    def flow_set_max_withdrawal_request_fee(self):
        curve_id = random.choice(list(self.parameters.keys()))
        fee = random_int(0, Wei.from_ether(0.1), min_prob=0.05)

        tx = self.parameters_registry.setMaxWithdrawalRequestFee(
            curve_id, fee, from_=self.admin
        )
        assert (
            CSParametersRegistry.MaxWithdrawalRequestFeeSet(curve_id, fee) in tx.events
        )

        self.parameters[curve_id].max_withdrawal_request_fee = fee

        logger.info(f"Set max withdrawal request fee for curve {curve_id} to {fee}")

    @flow()
    def flow_unset_max_withdrawal_request_fee(self):
        curve_id = random.choice(list(self.parameters.keys()))

        tx = self.parameters_registry.unsetMaxWithdrawalRequestFee(
            curve_id, from_=self.admin
        )
        assert CSParametersRegistry.MaxWithdrawalRequestFeeUnset(curve_id) in tx.events

        self.parameters[curve_id].max_withdrawal_request_fee = None

        logger.info(f"Unset max withdrawal request fee for curve {curve_id}")

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_balances(self):
        assert self.balances[self.csm] == 0

        for acc, balance in self.balances.items():
            assert acc.balance == balance

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_shares(self):
        assert self.shares[self.csm] == 0

        for acc, shares in self.shares.items():
            assert ST_ETH.sharesOf(acc) == shares

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_locked_bond(self):
        t = chain.blocks["latest"].timestamp
        for no in self.csm_node_operators.values():
            assert self._get_actual_locked_bond(
                no, t
            ) == self.accounting.getActualLockedBond(no.id)

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_distribution_history(self):
        for i, dist in enumerate(self.distribution_history):
            assert dist == self.fee_distributor.getHistoricalDistributionData(i)
        assert self.fee_distributor.getHistoricalDistributionData(
            len(self.distribution_history)
        ) == CSFeeDistributor.DistributionData(
            refSlot=0,
            treeRoot=b"\x00" * 32,
            treeCid="",
            logCid="",
            distributed=0,
            rebate=0,
        )

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_node_operators(self):
        with chain.snapshot_and_revert():
            for no in self.csm_node_operators.values():
                info = self.csm.getNodeOperator(no.id)
                assert self._get_enqueued_keys(no.id) == info.enqueuedCount
                assert info.usedPriorityQueue == no.used_priority_queue

                # workaround for depositableValidatorsCount is being updated after bond lock retention period end
                self.csm.updateDepositableValidatorsCount(no.id)

            t = chain.blocks["latest"].timestamp
            depositable_sum = 0
            deposited_sum = 0
            exited_sum = 0

            for no in self.csm_node_operators.values():
                assert b"".join(no.keys) == self.csm.getSigningKeys(
                    no.id, 0, no.total_keys
                )
                assert (
                    b"".join(no.keys),
                    b"".join(no.signatures),
                ) == self.csm.getSigningKeysWithSignatures(no.id, 0, no.total_keys)
                info = self.csm.getNodeOperator(no.id)
                assert no.total_keys == info.totalAddedKeys
                assert no.withdrawn_keys == info.totalWithdrawnKeys
                assert no.stuck_keys == info.stuckValidatorsCount
                assert no.target_limit == info.targetLimit
                assert no.target_limit_mode == info.targetLimitMode
                assert no.manager.address == info.managerAddress
                assert no.rewards_account.address == info.rewardAddress
                assert (
                    self._get_depositable_keys(no, t) == info.depositableValidatorsCount
                )
                assert (
                    no.deposited_keys + no.withdrawn_keys == info.totalDepositedKeys
                )  # CSM counts withdrawn keys as deposited
                assert no.exited_keys == info.totalExitedKeys
                assert no.vetted_keys == info.totalVettedKeys
                assert (
                    self.csm.getNodeOperatorNonWithdrawnKeys(no.id)
                    == no.total_keys - no.withdrawn_keys
                )
                # enqueued keys already checked before workaround

                assert self._get_claimable_bond_shares(
                    no, t
                ) == self.accounting.getClaimableBondShares(no.id)

                leaf = keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                try:
                    leaf_index = self.rewards_tree.leaves.index(leaf)
                    proof = self.rewards_tree.get_proof(leaf_index)
                    claimable_with_pull = self._get_claimable_bond_shares_with_pull(no, t)
                    assert self.accounting.getClaimableRewardsAndBondShares(
                        no.id,
                        no.total_rewards,
                        proof,
                    ) == claimable_with_pull

                    with chain.snapshot_and_revert():
                        with may_revert() as ex:
                            assert self.accounting.claimRewardsStETH(
                                no.id,
                                uint.max,
                                no.total_rewards,
                                proof,
                                from_=no.manager,
                            ).return_value == claimable_with_pull

                        if claimable_with_pull == 0:
                            assert ex.value == CSAccounting.NothingToClaim()
                        else:
                            assert ex.value is None
                except ValueError:
                    pass

                unbonded = (
                    no.total_keys
                    - no.withdrawn_keys
                    - self._get_keys_by_eth(no, t, False)
                )
                assert self.accounting.getUnbondedKeysCount(no.id) == max(
                    no.total_keys
                    - no.withdrawn_keys
                    - self._get_keys_by_eth(no, t, True),
                    0,
                )
                assert self.accounting.getUnbondedKeysCountToEject(no.id) == max(
                    unbonded, 0
                )

                summary = self.csm.getNodeOperatorSummary(no.id)
                if unbonded > no.total_keys - no.deposited_keys - no.withdrawn_keys:
                    target_limit_mode = 2

                    if no.target_limit_mode == 2:
                        target_limit = min(
                            no.target_limit,
                            no.total_keys - no.withdrawn_keys - unbonded,
                        )
                    else:
                        target_limit = no.total_keys - no.withdrawn_keys - unbonded
                else:
                    target_limit_mode = no.target_limit_mode
                    target_limit = no.target_limit

                assert summary == (
                    target_limit_mode,
                    target_limit,
                    no.stuck_keys,
                    0,
                    0,
                    no.exited_keys,
                    no.deposited_keys + no.withdrawn_keys,
                    self._get_depositable_keys(no, t),
                )

                depositable_sum += info.depositableValidatorsCount
                deposited_sum += info.totalDepositedKeys
                exited_sum += info.totalExitedKeys

                for key in range(no.total_keys):
                    assert no.withdrawn[key] == self.csm.isValidatorWithdrawn(
                        no.id, key
                    )

                    assert self.exit_penalties.getExitPenaltyInfo(
                        no.id, no.keys[key]
                    ) == ExitPenaltyInfo(
                        delayPenalty=MarkedUint248(
                            value=no.exit_delay_penalties[key] or 0,
                            isValue=no.exit_delay_penalties[key] is not None,
                        ),
                        strikesPenalty=MarkedUint248(
                            value=no.strikes_penalties[key] or 0,
                            isValue=no.strikes_penalties[key] is not None,
                        ),
                        withdrawalRequestFee=MarkedUint248(
                            value=no.withdrawal_request_fees[key] or 0,
                            isValue=no.withdrawal_request_fees[key] is not None,
                        ),
                    )

                assert self.accounting.getBondSummary(no.id) == (
                    ST_ETH.getPooledEthByShares(no.bond_shares),
                    self._get_total_bond(
                        no.total_keys - no.withdrawn_keys, self.curves[no.curve_id]
                    )
                    + self._get_actual_locked_bond(no, t),
                )
                assert self.accounting.getBondSummaryShares(no.id) == (
                    no.bond_shares,
                    ST_ETH.getSharesByPooledEth(
                        self._get_total_bond(
                            no.total_keys - no.withdrawn_keys, self.curves[no.curve_id]
                        )
                        + self._get_actual_locked_bond(no, t)
                    ),
                )

            assert self.csm.getStakingModuleSummary() == (
                exited_sum,
                deposited_sum,
                depositable_sum,
            )

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_bond_shares(self):
        for no in self.csm_node_operators.values():
            assert no.bond_shares == self.accounting.getBondShares(no.id)

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_nonce(self):
        assert self.nonce == self.csm.getNonce()

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_total_bond_shares(self):
        assert self.accounting.totalBondShares() == sum(
            no.bond_shares for no in self.csm_node_operators.values()
        )

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_queue(self):
        for priority in range(QUEUE_LOWEST_PRIORITY + 1):
            head, tail = self.csm.depositQueuePointers(priority)
            current = head
            i = 0

            while current != tail:
                item = self.csm.depositQueueItem(priority, current)
                no_id = item >> (256 - 64)
                keys_count = (item >> (256 - 64 - 64)) & (2**64 - 1)

                assert self.queue[priority][i] == QueueItem(no_id, keys_count)

                current = item & (2**128 - 1)
                i += 1

            assert self.csm.depositQueueItem(priority, tail) == 0
            assert len(self.queue[priority]) == i

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_vetted_referrals(self):
        for acc in chain.accounts:
            assert self.vetted_gate.isConsumed(acc) == (
                acc in self.claimed_vetted_accounts
            )
            assert self.vetted_gate.getReferralsCount(acc) == self.vetted_referrals[acc]
