from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from ordered_set import OrderedSet

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.tw.contracts._0_8_9.oracle.AccountingOracle import (
    AccountingOracle,
)
from pytypes.tw.contracts._0_8_9.DepositSecurityModule import DepositSecurityModule
from pytypes.tw.contracts._0_8_9.StakingRouter import StakingRouter
from pytypes.tw.contracts._0_8_9.LidoLocator import LidoLocator
from pytypes.tw.contracts._0_8_9.oracle.HashConsensus import HashConsensus
from pytypes.tw.contracts._0_8_9.oracle.ValidatorsExitBusOracle import (
    ValidatorsExitBusOracle,
)
from pytypes.tw.contracts._0_8_9.WithdrawalVault import WithdrawalVault
from pytypes.tw.contracts._0_8_9.TriggerableWithdrawalsGateway import (
    TriggerableWithdrawalsGateway,
)
from pytypes.tw.contracts._0_8_25.ValidatorExitDelayVerifier import (
    ValidatorExitDelayVerifier,
    ProvableBeaconBlockHeader,
    ExitRequestData,
    ValidatorWitness,
    HistoricalHeaderWitness,
    GIndices,
)
from pytypes.tw.contracts._0_8_9.proxy.OssifiableProxy import OssifiableProxy
from pytypes.tw.contracts._0_6_12.interfaces.IStETH import IStETH
from pytypes.tw.contracts.common.lib.MinFirstAllocationStrategy import (
    MinFirstAllocationStrategy,
)
from pytypes.tw.contracts._0_8_4.WithdrawalsManagerProxy import WithdrawalsManagerProxy

from pytypes.tw.contracts.common.lib.BeaconTypes import Validator, BeaconBlockHeader

from ..merkle_tree import MerkleTree
from .nor import NorFuzzTest
from .csm import CSMFuzzTest
from .common import *

ORIGINAL_ADMIN = Account("0x3e40d73eb977dc6a537af587d48316fee66e9c8c")

DEPOSIT_CONTRACT = Account("0x00000000219ab540356cBB839Cbe05303d7705Fa")
EL_REWARDS_VAULT = Account("0x388C818CA8B9251b393131C08a736A67ccB19297")
LEGACY_ORACLE = Account("0x442af784A788A5bd6F42A01Ebe9F287a871243fb")
LIDO = IStETH("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
ORACLE_REPORT_SANITY_CHECKER = Account("0x6232397ebac4f5772e53285B26c47914E9461E75")
POST_TOKEN_REBASE_RECEIVER = Account("0xe6793B9e4FbA7DE0ee833F9D02bba7DB5EB27823")
BURNER = Account("0xD15a672319Cf0352560eE76d9e89eAB0889046D3")
TREASURY = Account("0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")
WITHDRAWAL_QUEUE = Account("0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1")
ORACLE_DAEMON_CONFIG = Account("0xbf05A929c3D7885a6aeAd833a992dA6E5ac23b09")
DEPOSIT_SECURITY_MODULE = Account("0xfFA96D84dEF2EA035c7AB153D8B991128e3d72fD")
STAKING_ROUTER = Account("0xFdDf38947aFB03C621C71b06C9C70bce73f12999")
LOCATOR = Account("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
ACCOUNTING_ORACLE = Account("0x852deD011285fe67063a08005c71a85690503Cee")
VALIDATORS_EXIT_BUS_ORACLE = Account("0x0De4Ea0184c2ad0BacA7183356Aea5B8d5Bf5c6e")
WITHDRAWAL_VAULT = Account("0xB9D7934878B5FB9610B3fE8A5e441e8fad7E293f")
NODE_OPERATORS_REGISTRY = Account("0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5")
PAUSE_INTENT_VALIDITY_BLOCKS = 10
MAX_OPERATORS_PER_UNVETTING = 10
SHARD_COMMITTEE_PERIOD_IN_SECONDS = 256 * SLOTS_PER_EPOCH * SECONDS_PER_SLOT
HISTORICAL_SUMMARIES_COUNT = 2**16

MAX_EXIT_REQUESTS_LIMIT = 100
EXITS_PER_FRAME = 10
FAST_LANE_LENGTH_SLOTS = 0

MAX_WITHDRAWAL_EXCESS = 700

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class HashConsensusInfo:
    members: OrderedSet[Account]
    quorum: int
    last_report_ref_slot: int
    initial_epoch: int


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


@dataclass
class ExitLimitsInfo:
    max_exits: int
    available_exits: int
    last_timestamp: int
    exits_per_frame: int
    frame_duration: int


class TriggerableWithdrawalsFuzzTest(NorFuzzTest, CSMFuzzTest):
    locator: LidoLocator
    accounting_oracle: AccountingOracle
    staking_router: StakingRouter
    validators_exit_bus_oracle: ValidatorsExitBusOracle
    withdrawal_vault: WithdrawalVault
    triggerable_withdrawals_gateway: TriggerableWithdrawalsGateway
    validator_exit_delay_verifier: ValidatorExitDelayVerifier
    accounting_hash_consensus: HashConsensus
    vebo_hash_consensus: HashConsensus

    admin: Account
    withdrawal_credentials: bytes
    consensus_info: dict[HashConsensus, HashConsensusInfo]

    # VEBO reports are auto-submitted
    total_exit_requests_submitted: int
    vebo_reports: dict[
        bytes, tuple[bytes, int]
    ]  # report hash -> (data, delivery timestamp)
    veb_reports: dict[
        bytes, tuple[bytes, int]
    ]  # report hash -> (data, delivery timestamp)
    submitted_veb_reports: OrderedSet[bytes]  # report hashes
    tw_limits: ExitLimitsInfo
    veb_limits: ExitLimitsInfo
    max_veb_validators_per_report: int

    initial_epoch: int

    nor_id: int
    csm_id: int

    def pre_sequence(self) -> None:
        self.initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)

        MinFirstAllocationStrategy.deploy()

        self.admin = random_account()
        self.withdrawal_credentials = random_bytes(32)
        self.vebo_reports = {}
        self.veb_reports = {}
        self.submitted_veb_reports = OrderedSet([])

        self.accounting_oracle = AccountingOracle(ACCOUNTING_ORACLE)
        self.staking_router = StakingRouter(STAKING_ROUTER)
        self.validators_exit_bus_oracle = ValidatorsExitBusOracle(
            VALIDATORS_EXIT_BUS_ORACLE
        )
        self.total_exit_requests_submitted = (
            self.validators_exit_bus_oracle.getTotalRequestsProcessed()
        )
        self.withdrawal_vault = WithdrawalVault(WITHDRAWAL_VAULT)
        self.triggerable_withdrawals_gateway = TriggerableWithdrawalsGateway.deploy(
            self.admin,
            LOCATOR,
            MAX_EXIT_REQUESTS_LIMIT,
            EXITS_PER_FRAME,
            SECONDS_PER_FRAME,
        )
        self.tw_limits = ExitLimitsInfo(
            MAX_EXIT_REQUESTS_LIMIT,
            MAX_EXIT_REQUESTS_LIMIT,
            chain.txs[-1].block.timestamp,
            EXITS_PER_FRAME,
            SECONDS_PER_FRAME,
        )
        self.triggerable_withdrawals_gateway.grantRole(
            self.triggerable_withdrawals_gateway.ADD_FULL_WITHDRAWAL_REQUEST_ROLE(),
            self.validators_exit_bus_oracle,
            from_=self.admin,
        )
        self.triggerable_withdrawals_gateway.grantRole(
            self.triggerable_withdrawals_gateway.TW_EXIT_LIMIT_MANAGER_ROLE(),
            self.admin,
            from_=self.admin,
        )

        first_supported_slot = (
            chain.blocks["latest"].timestamp - GENESIS_TIME
        ) // SECONDS_PER_SLOT

        historical_summaries_pow = int(math.log2(HISTORICAL_SUMMARIES_COUNT))
        if 2**historical_summaries_pow != HISTORICAL_SUMMARIES_COUNT:
            raise ValueError(
                f"HISTORICAL_SUMMARIES_COUNT must be a power of 2, got {HISTORICAL_SUMMARIES_COUNT}"
            )
        historical_summary_index = 0b11 << historical_summaries_pow
        historical_summary_gi = historical_summary_index.to_bytes(
            31, "big"
        ) + historical_summaries_pow.to_bytes(1, "big")

        # simplified beacon state:
        # | 16 x validator | historical summaries (HISTORICAL_SUMMARIES_COUNT) |
        self.validator_exit_delay_verifier = ValidatorExitDelayVerifier.deploy(
            LOCATOR,
            GIndices(
                # where to search for the first validator within the state tree
                # 0b10 0000
                bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000002004"
                ),
                bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000002004"
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
            SLOTS_PER_HISTORICAL_ROOT,
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            SHARD_COMMITTEE_PERIOD_IN_SECONDS,
        )

        OssifiableProxy(LOCATOR).proxy__changeAdmin(self.admin, from_=ORIGINAL_ADMIN)
        OssifiableProxy(STAKING_ROUTER).proxy__changeAdmin(
            self.admin, from_=ORIGINAL_ADMIN
        )
        OssifiableProxy(ACCOUNTING_ORACLE).proxy__changeAdmin(
            self.admin, from_=ORIGINAL_ADMIN
        )
        OssifiableProxy(VALIDATORS_EXIT_BUS_ORACLE).proxy__changeAdmin(
            self.admin, from_=ORIGINAL_ADMIN
        )
        WithdrawalsManagerProxy(WITHDRAWAL_VAULT).proxy_changeAdmin(
            self.admin, from_=WithdrawalsManagerProxy(WITHDRAWAL_VAULT).proxy_getAdmin()
        )

        OssifiableProxy(STAKING_ROUTER).proxy__upgradeToAndCall(
            StakingRouter.deploy(DEPOSIT_CONTRACT),
            abi.encode_call(StakingRouter.finalizeUpgrade_v3, []),
            False,
            from_=self.admin,
        )
        WithdrawalsManagerProxy(WITHDRAWAL_VAULT).proxy_upgradeTo(
            WithdrawalVault.deploy(
                LIDO, TREASURY, self.triggerable_withdrawals_gateway
            ),
            b"",
            from_=self.admin,
        )
        OssifiableProxy(ACCOUNTING_ORACLE).proxy__upgradeTo(
            AccountingOracle.deploy(
                LOCATOR,
                LIDO,
                LEGACY_ORACLE,
                SECONDS_PER_SLOT,
                GENESIS_TIME,
            ),
            from_=self.admin,
        )

        self.accounting_hash_consensus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            ACCOUNTING_ORACLE,
        )
        accounting_initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        self.accounting_hash_consensus.updateInitialEpoch(
            accounting_initial_epoch, from_=self.admin
        )
        self.accounting_hash_consensus.grantRole(
            self.accounting_hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(),
            self.admin,
            from_=self.admin,
        )

        self.accounting_oracle.grantRole(
            self.accounting_oracle.DEFAULT_ADMIN_ROLE(),
            self.admin,
            from_=ORIGINAL_ADMIN,
        )
        self.accounting_oracle.grantRole(
            self.accounting_oracle.MANAGE_CONSENSUS_CONTRACT_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.accounting_oracle.setConsensusContract(
            self.accounting_hash_consensus, from_=self.admin
        )

        self.staking_router.grantRole(
            self.staking_router.DEFAULT_ADMIN_ROLE(),
            self.admin,
            from_=ORIGINAL_ADMIN,
        )
        self.staking_router.grantRole(
            self.staking_router.STAKING_MODULE_MANAGE_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.staking_router.grantRole(
            self.staking_router.REPORT_VALIDATOR_EXIT_TRIGGERED_ROLE(),
            self.triggerable_withdrawals_gateway,
            from_=self.admin,
        )
        self.staking_router.grantRole(
            self.staking_router.REPORT_VALIDATOR_EXITING_STATUS_ROLE(),
            self.validator_exit_delay_verifier,
            from_=self.admin,
        )

        self.max_veb_validators_per_report = 10
        OssifiableProxy(VALIDATORS_EXIT_BUS_ORACLE).proxy__upgradeToAndCall(
            ValidatorsExitBusOracle.deploy(SECONDS_PER_SLOT, GENESIS_TIME, LOCATOR),
            abi.encode_call(
                ValidatorsExitBusOracle.finalizeUpgrade_v2,
                [
                    self.max_veb_validators_per_report,
                    MAX_EXIT_REQUESTS_LIMIT,
                    EXITS_PER_FRAME,
                    SECONDS_PER_FRAME,
                ],
            ),
            False,
            from_=self.admin,
        )
        self.veb_limits = ExitLimitsInfo(
            MAX_EXIT_REQUESTS_LIMIT,
            MAX_EXIT_REQUESTS_LIMIT,
            chain.txs[-1].block.timestamp,
            EXITS_PER_FRAME,
            SECONDS_PER_FRAME,
        )

        OssifiableProxy(LOCATOR).proxy__upgradeTo(
            LidoLocator.deploy(
                LidoLocator.Config(
                    accountingOracle=self.accounting_oracle.address,
                    depositSecurityModule=DEPOSIT_SECURITY_MODULE.address,
                    elRewardsVault=EL_REWARDS_VAULT.address,
                    legacyOracle=LEGACY_ORACLE.address,
                    lido=LIDO.address,
                    oracleReportSanityChecker=ORACLE_REPORT_SANITY_CHECKER.address,
                    postTokenRebaseReceiver=POST_TOKEN_REBASE_RECEIVER.address,
                    burner=BURNER.address,
                    stakingRouter=self.staking_router.address,
                    treasury=TREASURY.address,
                    validatorsExitBusOracle=self.validators_exit_bus_oracle.address,
                    withdrawalQueue=WITHDRAWAL_QUEUE.address,
                    withdrawalVault=self.withdrawal_vault.address,
                    oracleDaemonConfig=ORACLE_DAEMON_CONFIG.address,
                    validatorExitDelayVerifier=self.validator_exit_delay_verifier.address,
                    triggerableWithdrawalsGateway=self.triggerable_withdrawals_gateway.address,
                )
            ),
            from_=self.admin,
        )
        self.locator = LidoLocator(LOCATOR)

        self.vebo_hash_consensus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            self.validators_exit_bus_oracle,
        )
        vebo_initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        self.vebo_hash_consensus.updateInitialEpoch(
            vebo_initial_epoch, from_=self.admin
        )
        self.vebo_hash_consensus.grantRole(
            self.vebo_hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(),
            self.admin,
            from_=self.admin,
        )

        self.validators_exit_bus_oracle.grantRole(
            self.validators_exit_bus_oracle.DEFAULT_ADMIN_ROLE(),
            self.admin,
            from_=ORIGINAL_ADMIN,
        )
        self.validators_exit_bus_oracle.grantRole(
            self.validators_exit_bus_oracle.MANAGE_CONSENSUS_CONTRACT_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.validators_exit_bus_oracle.grantRole(
            self.validators_exit_bus_oracle.SUBMIT_DATA_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.validators_exit_bus_oracle.grantRole(
            self.validators_exit_bus_oracle.SUBMIT_REPORT_HASH_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.validators_exit_bus_oracle.grantRole(
            self.validators_exit_bus_oracle.EXIT_REQUEST_LIMIT_MANAGER_ROLE(),
            self.admin,
            from_=self.admin,
        )
        self.validators_exit_bus_oracle.setConsensusContract(
            self.vebo_hash_consensus, from_=self.admin
        )

        self.consensus_info = {
            self.accounting_hash_consensus: HashConsensusInfo(
                members=OrderedSet([]),
                quorum=0,
                last_report_ref_slot=0,
                initial_epoch=accounting_initial_epoch,
            ),
            self.vebo_hash_consensus: HashConsensusInfo(
                members=OrderedSet([]),
                quorum=0,
                last_report_ref_slot=0,
                initial_epoch=vebo_initial_epoch,
            ),
        }

        NorFuzzTest.pre_sequence(self)
        CSMFuzzTest.pre_sequence(self)

        self.triggerable_withdrawals_gateway.grantRole(
            self.triggerable_withdrawals_gateway.ADD_FULL_WITHDRAWAL_REQUEST_ROLE(),
            self.ejector,
            from_=self.admin,
        )

    def post_invariants(self) -> None:
        time_delta = random_int(60 * 60, 5 * 60 * 60)
        chain.mine(lambda t: t + time_delta)

        # change EIP-7002 dynamic fee
        chain.chain_interface.set_storage_at(
            "0x00000961Ef480Eb55e80D19ad83579A64c007002",
            0,
            abi.encode(uint(random_int(1, MAX_WITHDRAWAL_EXCESS))),
        )

    def _random_exit_requests(self, count: int) -> bytes:
        ops: list[tuple[int, int, bytes]] = []
        for module in [self.csm_id, self.nor_id]:
            for op in self.nor_operators.values() if module == self.nor_id else self.csm_node_operators.values():
                if op.deposited_keys - op.exited_keys > 0:
                    ops.extend(
                        (module, op.id, op.keys[i])
                        for i in range(op.deposited_keys)
                        if not op.withdrawn[i]
                    )

        random.shuffle(ops)

        count = min(count, len(ops))

        reported = random.sample(ops, count)
        reported.sort()
        val_indexes = random.sample(range(16), count)
        val_indexes.sort()
        # 24b: moduleId | 40b: nodeOpId | 64b: valIndex | 48B: pubkey
        payload = b"".join(
            int.to_bytes(module, 3)
            + int.to_bytes(op, 5)
            + int.to_bytes(val_index, 8)
            + key
            for (module, op, key), val_index in zip(reported, val_indexes)
        )

        return payload

    def _calculate_current_exit_limit(
        self, info: ExitLimitsInfo, timestamp: uint
    ) -> int:
        if info.max_exits == 0:
            return uint.max
        if (
            timestamp - info.last_timestamp < info.frame_duration
            or info.exits_per_frame == 0
        ):
            return info.available_exits

        frames_passed = (timestamp - info.last_timestamp) // info.frame_duration
        restored_limit = frames_passed * info.exits_per_frame

        new_limit = info.available_exits + restored_limit
        if new_limit > info.max_exits:
            new_limit = info.max_exits

        return new_limit

    def _unpack_exit_request(
        self, payload: bytes, index: int
    ) -> tuple[int, int, int, bytes]:
        data = payload[index * 64 : (index + 1) * 64]
        module_id = int.from_bytes(data[0:3], "big")
        node_op_id = int.from_bytes(data[3:8], "big")
        val_index = int.from_bytes(data[8:16], "big")
        pubkey = data[16:64]
        return module_id, node_op_id, val_index, pubkey

    @flow()
    def flow_add_consensus_member(self):
        member = random_account()
        hash_consensus = random.choice(
            [
                self.accounting_hash_consensus,
                self.vebo_hash_consensus,
            ]
        )
        info = self.consensus_info[hash_consensus]
        quorum = (len(info.members) + 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            tx = hash_consensus.addMember(member, quorum, from_=self.admin)

        if member in info.members:
            assert e.value is not None
            return "Already added"
        else:
            assert e.value is None
            assert (
                HashConsensus.MemberAdded(member.address, len(info.members) + 1, quorum)
                in tx.events
            )

            if quorum != info.quorum:
                assert (
                    HashConsensus.QuorumSet(quorum, len(info.members) + 1, info.quorum)
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, HashConsensus.QuorumSet)
                )

            info.members.add(member)
            info.quorum = quorum

            logger.info(f"Added consensus member {member} with quorum {quorum}")

    @flow()
    def flow_remove_consensus_member(self):
        hash_consensus = random.choice(
            [
                self.accounting_hash_consensus,
                self.vebo_hash_consensus,
            ]
        )
        info = self.consensus_info[hash_consensus]
        try:
            member = random.choice(list(info.members))
        except IndexError:
            return "No consensus members"

        quorum = (len(info.members) - 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            tx = hash_consensus.removeMember(member, quorum, from_=self.admin)

        if member in info.members:
            assert e.value is None
            assert (
                HashConsensus.MemberRemoved(
                    member.address, len(info.members) - 1, quorum
                )
                in tx.events
            )

            if quorum != info.quorum:
                assert (
                    HashConsensus.QuorumSet(quorum, len(info.members) - 1, info.quorum)
                    in tx.events
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, HashConsensus.QuorumSet)
                )

            info.members.remove(member)
            info.quorum = quorum

            logger.info(f"Removed consensus member {member} with quorum {quorum}")
        else:
            assert e.value is not None
            return "Not a member"

    @flow()
    def flow_deposit(self):
        module_id = random.choice([self.nor_id, self.csm_id])

        if module_id == self.nor_id:
            available_keys = self.nor_pre_deposit()
        if module_id == self.csm_id:
            available_keys, depositable = self.csm_pre_deposit()

        if available_keys == 0:
            return "No available keys"

        count = min(random_int(0, 10), available_keys)
        value = count * Wei.from_ether(32)

        LIDO.balance += value

        with may_revert() as ex:
            tx = self.staking_router.deposit(
                count, module_id, b"", from_=LIDO, value=value
            )
        if ex.value is not None:
            tx = ex.value.tx

        if module_id == self.nor_id:
            self.nor_post_deposit(count, tx)
        else:
            self.csm_post_deposit(count, depositable, tx)

        logger.info(f"Deposited {count} keys for module {module_id}")

    @flow()
    def flow_submit_vebo_data(self):
        info = self.consensus_info[self.vebo_hash_consensus]
        ref_slot = get_frame_info(
            chain.blocks["pending"].timestamp, info.initial_epoch
        )[0]
        if ref_slot == info.last_report_ref_slot:
            return "Already reported"
        if len(info.members) == 0:
            return "No consensus members"
        if len(self.nor_operators) == 0 and len(self.csm_node_operators) == 0:
            return "No node operators"

        CONSENSUS_VERSION = 3

        reports: list[ValidatorsExitBusOracle.ReportData] = []
        # number of pre-generated reports can be adjusted but it will make harder to reach consensus
        for _ in range(3):
            payload = self._random_exit_requests(random_int(0, 10))

            reports.append(
                ValidatorsExitBusOracle.ReportData(
                    CONSENSUS_VERSION, ref_slot, len(payload) // 64, 1, payload
                )
            )

        votes = {keccak256(abi.encode(report)): OrderedSet([]) for report in reports}
        consensus_info = self.consensus_info[self.vebo_hash_consensus]

        # while not consensus reached
        while True:
            sender = random.choice(consensus_info.members)

            frame_info = get_frame_info(
                chain.blocks["pending"].timestamp, consensus_info.initial_epoch
            )
            if frame_info[0] != ref_slot:
                # got into a new frame, reset votes
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

            with may_revert(ValidatorsExitBusOracle.ProcessingDeadlineMissed) as ex:
                tx = self.vebo_hash_consensus.submitReport(
                    ref_slot,
                    report_hash,
                    CONSENSUS_VERSION,
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

            if any(len(voters) >= consensus_info.quorum for voters in votes.values()):
                assert (
                    HashConsensus.ConsensusReached(
                        frame_info[0],
                        report_hash,
                        max(len(voters) for voters in votes.values()),
                    )
                    in tx.events
                )
                assert (
                    ValidatorsExitBusOracle.ReportSubmitted(
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
                    e
                    for e in tx.events
                    if isinstance(e, ValidatorsExitBusOracle.ReportSubmitted)
                )

        report_hash = next(
            report_hash
            for report_hash, voters in votes.items()
            if len(voters) >= consensus_info.quorum
        )
        report = next(
            report for report in reports if keccak256(abi.encode(report)) == report_hash
        )
        index = reports.index(report)

        assert (
            self.validators_exit_bus_oracle.getProcessingState()
            == ValidatorsExitBusOracle.ProcessingState(
                currentFrameRefSlot=frame_info[0],
                processingDeadlineTime=slot_to_timestamp(frame_info[1]),
                dataHash=report_hash,
                dataSubmitted=False,
                dataFormat=0,
                requestsCount=0,
                requestsSubmitted=0,
            )
        )

        sender = random.choice(list(consensus_info.members) + [self.admin])
        with may_revert(ValidatorsExitBusOracle.ProcessingDeadlineMissed) as ex:
            tx = self.validators_exit_bus_oracle.submitReportData(
                report, 2, from_=sender
            )

        if ex.value is not None:
            t = ex.value.tx.block.timestamp
            assert t > slot_to_timestamp(frame_info[1]) and t < slot_to_timestamp(
                frame_info[1] + 1
            )
            return "Processing deadline missed"

        assert [
            e
            for e in tx.events
            if isinstance(e, ValidatorsExitBusOracle.ValidatorExitRequest)
        ] == [
            ValidatorsExitBusOracle.ValidatorExitRequest(
                module_id,
                node_op_id,
                val_index,
                pubkey,
                tx.block.timestamp,
            )
            for i in range(reports[index].requestsCount)
            for module_id, node_op_id, val_index, pubkey in [
                self._unpack_exit_request(reports[index].data, i)
            ]
        ]
        assert (
            self.validators_exit_bus_oracle.getProcessingState()
            == ValidatorsExitBusOracle.ProcessingState(
                currentFrameRefSlot=frame_info[0],
                processingDeadlineTime=slot_to_timestamp(frame_info[1]),
                dataHash=report_hash,
                dataSubmitted=True,
                dataFormat=1,
                requestsCount=report.requestsCount,
                requestsSubmitted=report.requestsCount,
            )
        )

        requests_hash = keccak256(abi.encode(report.data, uint(1)))
        if requests_hash in self.vebo_reports:
            delivery_timestamp = self.vebo_reports[requests_hash][1]
        elif (
            requests_hash in self.veb_reports
            and self.veb_reports[requests_hash][1] != 0
        ):
            delivery_timestamp = self.veb_reports[requests_hash][1]
        else:
            delivery_timestamp = tx.block.timestamp
        assert (
            self.validators_exit_bus_oracle.getDeliveryTimestamp(requests_hash)
            == delivery_timestamp
        )

        self.total_exit_requests_submitted += report.requestsCount

        # actually using a different report hash - the one that is used as a mapping key
        self.vebo_reports[requests_hash] = (report.data, delivery_timestamp)
        consensus_info.last_report_ref_slot = frame_info[0]

        logger.info(f"Submitted vebo exit data for {report.requestsCount} validators")

    @flow()
    def flow_submit_exit_requests_hash(self):
        payload = self._random_exit_requests(random_int(0, 11))

        hash = keccak256(abi.encode(payload, uint(1)))
        with may_revert() as ex:
            tx = self.validators_exit_bus_oracle.submitExitRequestsHash(
                hash, from_=self.admin
            )

        if hash in self.veb_reports or hash in self.vebo_reports:
            assert ex.value == ValidatorsExitBusOracle.ExitHashAlreadySubmitted()
            return "Hash already submitted"
        else:
            assert ex.value is None

        assert ValidatorsExitBusOracle.RequestsHashSubmitted(hash) in tx.events

        self.veb_reports[hash] = (payload, 0)

        logger.info(f"Submitted exit requests hash {hash}")

    @flow()
    def flow_submit_exit_requests_data(self):
        try:
            hash = random.choice(list(self.veb_reports.keys()))
        except IndexError:
            return "No submitted exit requests hash"

        report, _ = self.veb_reports[hash]
        limit = self._calculate_current_exit_limit(
            self.veb_limits, chain.blocks["pending"].timestamp
        )

        with may_revert() as ex:
            tx = self.validators_exit_bus_oracle.submitExitRequestsData(
                ValidatorsExitBusOracle.ExitRequestsData(report, uint(1)),
                from_=self.admin,
            )

        if hash in self.vebo_reports or hash in self.submitted_veb_reports:
            assert ex.value == ValidatorsExitBusOracle.RequestsAlreadyDelivered()
            return "Requests already delivered"
        elif len(report) == 0:
            assert ex.value == ValidatorsExitBusOracle.InvalidRequestsDataLength()
            return "Invalid requests data length"
        elif len(report) // 64 > self.max_veb_validators_per_report:
            assert ex.value == ValidatorsExitBusOracle.TooManyExitRequestsInReport(
                len(report) // 64, self.max_veb_validators_per_report
            )
            return "Too many exit requests in report"
        elif len(report) // 64 > limit:
            assert ex.value == ValidatorsExitBusOracle.ExitRequestsLimitExceeded(
                len(report) // 64, limit
            )
            return "Exit requests limit exceeded"
        else:
            assert ex.value is None

        assert (
            self.validators_exit_bus_oracle.getDeliveryTimestamp(hash)
            == tx.block.timestamp
        )

        self.submitted_veb_reports.add(hash)
        self.veb_reports[hash] = (report, tx.block.timestamp)
        self.total_exit_requests_submitted += len(report) // 64

        if self.veb_limits.max_exits != 0:
            self.veb_limits.available_exits = limit - len(report) // 64
            # only add whole frames
            whole_frames = (
                chain.blocks["pending"].timestamp - self.veb_limits.last_timestamp
            ) // self.veb_limits.frame_duration
            self.veb_limits.last_timestamp += (
                whole_frames * self.veb_limits.frame_duration
            )

        logger.info(f"Submitted exit requests data for {len(report) // 64} validators")

    @flow()
    def flow_trigger_exits(self):
        try:
            report, _ = random.choice(
                list(self.vebo_reports.values())
                + [r for r in self.veb_reports.values() if r[1] != 0]
            )
        except IndexError:
            return "No VEBO or VEB report"

        if len(report) == 0:
            return "No requests"

        refund_recipient = random_account()
        sender = random_account()

        report_len = len(report) // 64

        indexes = random.sample(range(report_len), random_int(1, report_len))
        indexes.sort()

        withdrawal_request_fee = abi.decode(
            Account("0x00000961Ef480Eb55e80D19ad83579A64c007002").call(), [uint256]
        )
        value = len(indexes) * withdrawal_request_fee

        sender.balance += value

        current_exit_limit = self._calculate_current_exit_limit(
            self.tw_limits, chain.blocks["pending"].timestamp
        )

        with may_revert() as ex:
            tx = self.validators_exit_bus_oracle.triggerExits(
                ValidatorsExitBusOracle.ExitRequestsData(report, 1),
                indexes,
                refund_recipient,
                from_=sender,
                value=value,
            )

        if len(indexes) > current_exit_limit:
            assert ex.value == TriggerableWithdrawalsGateway.ExitRequestsLimitExceeded(
                len(indexes), current_exit_limit
            )
            sender.balance -= value
            return "Exit requests limit exceeded"
        else:
            assert ex.value is None

        self.balances[refund_recipient] += value - withdrawal_request_fee * len(indexes)

        exited: list[tuple[int, int, int, bytes]] = []
        for index in indexes:
            module_id, node_op_id, val_index, pubkey = self._unpack_exit_request(
                report, index
            )
            assert self.validators_exit_bus_oracle.unpackExitRequest(
                report, 1, index
            ) == (pubkey, node_op_id, module_id, val_index)
            exited.append((module_id, node_op_id, val_index, pubkey))

        assert [
            e
            for e in tx.events
            if isinstance(e, WithdrawalVault.WithdrawalRequestAdded)
        ] == [
            WithdrawalVault.WithdrawalRequestAdded(request=pubkey + int.to_bytes(0, 8))
            for _, _, _, pubkey in exited
        ]

        self.nor_post_trigger_exits(withdrawal_request_fee, exited, tx)
        for module_id, node_op_id, val_index, pubkey in exited:
            if module_id == self.csm_id:
                self.csm_on_validator_exit_triggered(withdrawal_request_fee, node_op_id, pubkey, 2, tx)

        self._update_tw_exit_limits(current_exit_limit, len(indexes), tx.block.timestamp)

        logger.info(f"Triggered exits for {len(exited)} validators")

    def _update_tw_exit_limits(self, current_exit_limit: int, count: int, timestamp: int) -> None:
        if self.tw_limits.max_exits != 0:
            self.tw_limits.available_exits = current_exit_limit - count
            # only add whole frames
            whole_frames = (
                timestamp - self.tw_limits.last_timestamp
            ) // self.tw_limits.frame_duration
            self.tw_limits.last_timestamp += (
                whole_frames * self.tw_limits.frame_duration
            )

    @flow()
    def flow_set_exit_request_limit(self):
        limit = random_int(0, MAX_EXIT_REQUESTS_LIMIT)
        exits_per_frame = random_int(0, limit)
        frame_duration = random_int(1, SECONDS_PER_FRAME, edge_values_prob=0.01)

        target = random.choice(
            [self.triggerable_withdrawals_gateway, self.validators_exit_bus_oracle]
        )

        tx = target.setExitRequestLimit(
            limit, exits_per_frame, frame_duration, from_=self.admin
        )

        if target == self.triggerable_withdrawals_gateway:
            assert (
                TriggerableWithdrawalsGateway.ExitRequestsLimitSet(
                    limit, exits_per_frame, frame_duration
                )
                in tx.events
            )
        else:
            assert (
                ValidatorsExitBusOracle.ExitRequestsLimitSet(
                    limit, exits_per_frame, frame_duration
                )
                in tx.events
            )

        limits = (
            self.tw_limits
            if target == self.triggerable_withdrawals_gateway
            else self.veb_limits
        )

        if limits.max_exits == 0:
            limits.available_exits = limit
        else:
            available = self._calculate_current_exit_limit(limits, tx.block.timestamp)
            used_exits = limits.max_exits - available
            if used_exits > limit:
                limits.available_exits = 0
            else:
                limits.available_exits = limit - used_exits

        limits.exits_per_frame = exits_per_frame
        limits.frame_duration = frame_duration
        limits.max_exits = limit
        limits.last_timestamp = tx.block.timestamp

        logger.info(
            f"Set exit request limit to {limit}, {exits_per_frame}, {frame_duration} for {target}"
        )

    @flow()
    def flow_set_max_veb_validators_per_report(self):
        limit = random_int(1, 100)

        self.validators_exit_bus_oracle.setMaxValidatorsPerReport(
            limit, from_=self.admin
        )
        self.max_veb_validators_per_report = limit

        logger.info(f"Set max VEBO validators per report to {limit}")

    @flow()
    def flow_verify_validator_exit_delay(self):
        try:
            report, report_delivery_timestamp = random.choice(
                list(self.vebo_reports.values())
                + [r for r in self.veb_reports.values() if r[1] != 0]
            )
        except IndexError:
            return "No exit request report"

        try:
            indexes = random.sample(range(len(report) // 64), random_int(0, 16))
        except ValueError:
            return "No exit request in report"

        # val_index -> (module_id, node_op_id, pubkey, exit_request_index)
        nos: dict[int, tuple[int, int, bytes, int]] = {}
        for index in indexes:
            module_id, node_op_id, val_index, pubkey = self._unpack_exit_request(
                report, index
            )
            nos[val_index] = (module_id, node_op_id, pubkey, index)

        current_epoch = timestamp_to_epoch(chain.blocks["latest"].timestamp)

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validators: dict[int, tuple[Validator, int]] = {}
        for val_index, (module_id, _, pubkey, exit_request_index) in nos.items():
            validator = Validator(
                pubkey=pubkey,
                withdrawalCredentials=b"\x01"
                + b"\x00" * 11
                + bytes(WITHDRAWAL_VAULT.address),
                effectiveBalance=random_int(0, 2**64 - 1),
                slashed=random_bool(),
                activationEligibilityEpoch=random_int(0, 2**64 - 1),
                activationEpoch=random_int(self.initial_epoch, current_epoch),
                exitEpoch=uint64.max,
                withdrawableEpoch=random_int(0, 2**64 - 1),
            )
            validators[val_index] = (validator, exit_request_index)

        # validator leaves
        validators_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        for i in range(16):
            if i in validators:
                validators_tree.add_leaf(hash_validator(validators[i][0]))
            else:
                validators_tree.add_leaf(random_bytes(32))

        state_tree.add_leaf(validators_tree.root)
        state_tree.add_leaf(random_bytes(32))  # historical summaries root
        assert len(state_tree.leaves) == 2

        witnesses: list[ValidatorWitness] = []
        for validator_index, (validator, exit_request_index) in validators.items():
            witness = ValidatorWitness(
                exitRequestIndex=exit_request_index,
                withdrawalCredentials=validator.withdrawalCredentials,
                effectiveBalance=validator.effectiveBalance,
                slashed=validator.slashed,
                activationEligibilityEpoch=validator.activationEligibilityEpoch,
                activationEpoch=validator.activationEpoch,
                withdrawableEpoch=validator.withdrawableEpoch,
                validatorProof=validators_tree.get_proof(validator_index) + state_tree.get_proof(0),
            )
            witnesses.append(witness)

        block_header = BeaconBlockHeader(
            timestamp_to_slot(chain.blocks["latest"].timestamp),
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

        random.shuffle(witnesses)

        proof_slot_timestamp = slot_to_timestamp(block_header.slot)
        penalty_applicable = []
        for w in witnesses:
            module_id, node_op_id, _, pubkey = self._unpack_exit_request(
                report, w.exitRequestIndex
            )
            activation_time = w.activationEpoch * SLOTS_PER_EPOCH * SECONDS_PER_SLOT + GENESIS_TIME + SHARD_COMMITTEE_PERIOD_IN_SECONDS
            eligible_to_exit = max(proof_slot_timestamp - max(
                activation_time,
                report_delivery_timestamp,
            ), 0)
            if module_id == self.csm_id:
                penalty_applicable.append(self.csm.isValidatorExitDelayPenaltyApplicable(
                    node_op_id,
                    proof_slot_timestamp,
                    pubkey,
                    eligible_to_exit,
                ))
            else:
                penalty_applicable.append(self.nor.isValidatorExitDelayPenaltyApplicable(
                    node_op_id,
                    proof_slot_timestamp,
                    pubkey,
                    eligible_to_exit,
                ))

        t = chain.blocks["pending"].timestamp

        with may_revert() as ex:
            tx = self.validator_exit_delay_verifier.verifyValidatorExitDelay(
                ProvableBeaconBlockHeader(block_header, tx.block.timestamp),
                witnesses,
                ExitRequestData(report, 1),
                from_=random_account(),
            )
        if ex.value is not None:
            tx = ex.value.tx

        for w, p in zip(witnesses, penalty_applicable):
            module_id, node_op_id, _, pubkey = self._unpack_exit_request(
                report, w.exitRequestIndex
            )
            activation_time = w.activationEpoch * SLOTS_PER_EPOCH * SECONDS_PER_SLOT + GENESIS_TIME + SHARD_COMMITTEE_PERIOD_IN_SECONDS

            if activation_time > t:
                assert (
                    ex.value
                    == ValidatorExitDelayVerifier.ExitIsNotEligibleOnProvableBeaconBlock(
                        proof_slot_timestamp,
                        activation_time,
                    )
                )
                return f"Exit is not eligible"

            eligible_to_exit = proof_slot_timestamp - max(
                activation_time,
                report_delivery_timestamp,
            )

            if module_id == self.csm_id:
                error = self.csm_on_validator_exit_delay(node_op_id, pubkey, eligible_to_exit, p, tx)
                if error is not None:
                    return error
            else:
                error = self.nor_on_validator_exit_delay(node_op_id, pubkey, eligible_to_exit, p, proof_slot_timestamp, tx)
                if error is not None:
                    return error

        assert tx.error is None

        logger.info(f"Verified exit delay for {len(witnesses)} validators")

    @flow()
    def flow_verify_historical_validator_exit_delay(self):
        try:
            report, report_delivery_timestamp = random.choice(
                list(self.vebo_reports.values())
                + [r for r in self.veb_reports.values() if r[1] != 0]
            )
        except IndexError:
            return "No exit request report"

        try:
            indexes = random.sample(range(len(report) // 64), random_int(0, 16))
        except ValueError:
            return "No exit request in report"

        # val_index -> (module_id, node_op_id, pubkey, exit_request_index)
        nos: dict[int, tuple[int, int, bytes, int]] = {}
        for index in indexes:
            module_id, node_op_id, val_index, pubkey = self._unpack_exit_request(
                report, index
            )
            nos[val_index] = (module_id, node_op_id, pubkey, index)

        current_epoch = timestamp_to_epoch(chain.blocks["latest"].timestamp)

        old_state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validators: dict[int, tuple[Validator, int]] = {}
        for val_index, (module_id, _, pubkey, exit_request_index) in nos.items():
            validator = Validator(
                pubkey=pubkey,
                withdrawalCredentials=b"\x01"
                + b"\x00" * 11
                + bytes(WITHDRAWAL_VAULT.address),
                effectiveBalance=random_int(0, 2**64 - 1),
                slashed=random_bool(),
                activationEligibilityEpoch=random_int(0, 2**64 - 1),
                activationEpoch=random_int(self.initial_epoch, current_epoch),
                exitEpoch=uint64.max,
                withdrawableEpoch=random_int(0, 2**64 - 1),
            )
            validators[val_index] = (validator, exit_request_index)

        # validator leaves
        validators_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        for i in range(16):
            if i in validators:
                validators_tree.add_leaf(hash_validator(validators[i][0]))
            else:
                validators_tree.add_leaf(random_bytes(32))

        old_state_tree.add_leaf(validators_tree.root)
        old_state_tree.add_leaf(random_bytes(32))  # historical summaries root
        assert len(old_state_tree.leaves) == 2

        witnesses: list[ValidatorWitness] = []
        for validator_index, (validator, exit_request_index) in validators.items():
            witness = ValidatorWitness(
                exitRequestIndex=exit_request_index,
                withdrawalCredentials=validator.withdrawalCredentials,
                effectiveBalance=validator.effectiveBalance,
                slashed=validator.slashed,
                activationEligibilityEpoch=validator.activationEligibilityEpoch,
                activationEpoch=validator.activationEpoch,
                withdrawableEpoch=validator.withdrawableEpoch,
                validatorProof=validators_tree.get_proof(validator_index) + old_state_tree.get_proof(0),
            )
            witnesses.append(witness)

        old_block_header = BeaconBlockHeader(
            timestamp_to_slot(chain.blocks["latest"].timestamp),
            random_int(0, 2**64 - 1),
            random_bytes(32),
            old_state_tree.root,
            random_bytes(32),
        )

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        state_tree.add_leaf(random_bytes(32))  # validator tree root

        historical_block_roots_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        historical_block_roots_leaves: List = [
            random_bytes(32) for _ in range(SLOTS_PER_HISTORICAL_ROOT)
        ]
        historical_block_roots_index = (
            old_block_header.slot - CAPELLA_SLOT
        ) % SLOTS_PER_HISTORICAL_ROOT
        historical_block_roots_leaves[historical_block_roots_index] = (
            hash_beacon_block_header(old_block_header)
        )
        for leaf in historical_block_roots_leaves:
            historical_block_roots_tree.add_leaf(leaf)
        assert len(historical_block_roots_tree.leaves) == SLOTS_PER_HISTORICAL_ROOT

        # a single historical summary
        historical_summary_tree = MerkleTree(
            "sha256", hash_leaves=False, sort_pairs=False
        )
        historical_summary_tree.add_leaf(
            historical_block_roots_tree.root
        )  # blocks root
        historical_summary_tree.add_leaf(random_bytes(32))  # states root

        # all historical summaries
        historical_summaries_tree = MerkleTree(
            "sha256", hash_leaves=False, sort_pairs=False
        )
        # don't generate all HISTORICAL_SUMMARIES_COUNT leaves randomly, because it's too slow
        historical_summaries_leaves: List = [random_bytes(32) for _ in range(8192)] + [
            b"\x00" * 32 for _ in range(HISTORICAL_SUMMARIES_COUNT - 8192)
        ]
        historical_summaries_index = (
            old_block_header.slot - CAPELLA_SLOT
        ) // SLOTS_PER_HISTORICAL_ROOT
        historical_summaries_leaves[historical_summaries_index] = (
            historical_summary_tree.root
        )
        for leaf in historical_summaries_leaves:
            historical_summaries_tree.add_leaf(leaf)
        assert len(historical_summaries_tree.leaves) == HISTORICAL_SUMMARIES_COUNT

        state_tree.add_leaf(historical_summaries_tree.root)
        assert len(state_tree.leaves) == 2

        block_header = BeaconBlockHeader(
            timestamp_to_slot(chain.blocks["latest"].timestamp),
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

        random.shuffle(witnesses)

        proof_slot_timestamp = slot_to_timestamp(block_header.slot)
        penalty_applicable = []
        for w in witnesses:
            module_id, node_op_id, _, pubkey = self._unpack_exit_request(
                report, w.exitRequestIndex
            )
            activation_time = w.activationEpoch * SLOTS_PER_EPOCH * SECONDS_PER_SLOT + GENESIS_TIME + SHARD_COMMITTEE_PERIOD_IN_SECONDS
            eligible_to_exit = max(proof_slot_timestamp - max(
                activation_time,
                report_delivery_timestamp,
            ), 0)
            if module_id == self.csm_id:
                penalty_applicable.append(self.csm.isValidatorExitDelayPenaltyApplicable(
                    node_op_id,
                    proof_slot_timestamp,
                    pubkey,
                    eligible_to_exit,
                ))
            else:
                penalty_applicable.append(self.nor.isValidatorExitDelayPenaltyApplicable(
                    node_op_id,
                    proof_slot_timestamp,
                    pubkey,
                    eligible_to_exit,
                ))

        t = chain.blocks["pending"].timestamp

        with may_revert() as ex:
            tx = self.validator_exit_delay_verifier.verifyHistoricalValidatorExitDelay(
                ProvableBeaconBlockHeader(block_header, tx.block.timestamp),
                HistoricalHeaderWitness(
                    old_block_header,
                    random_bytes(32),
                    historical_block_roots_tree.get_proof(historical_block_roots_index)
                    + historical_summary_tree.get_proof(0)
                    + historical_summaries_tree.get_proof(historical_summaries_index)
                    + state_tree.get_proof(1),
                ),
                witnesses,
                ExitRequestData(report, 1),
                from_=random_account(),
            )
        if ex.value is not None:
            tx = ex.value.tx

        for w, p in zip(witnesses, penalty_applicable):
            module_id, node_op_id, _, pubkey = self._unpack_exit_request(
                report, w.exitRequestIndex
            )
            activation_time = w.activationEpoch * SLOTS_PER_EPOCH * SECONDS_PER_SLOT + GENESIS_TIME + SHARD_COMMITTEE_PERIOD_IN_SECONDS

            if activation_time > t:
                assert (
                    ex.value
                    == ValidatorExitDelayVerifier.ExitIsNotEligibleOnProvableBeaconBlock(
                        proof_slot_timestamp,
                        activation_time,
                    )
                )
                return f"Exit is not eligible"

            eligible_to_exit = proof_slot_timestamp - max(
                activation_time,
                report_delivery_timestamp,
            )

            if module_id == self.csm_id:
                error = self.csm_on_validator_exit_delay(node_op_id, pubkey, eligible_to_exit, p, tx)
                if error is not None:
                    return error
            else:
                error = self.nor_on_validator_exit_delay(node_op_id, pubkey, eligible_to_exit, p, proof_slot_timestamp, tx)
                if error is not None:
                    return error

        assert tx.error is None

        logger.info(f"Verified historical exit delay for {len(witnesses)} validators")

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_exit_request_limit_full_info(self):
        t = chain.blocks["latest"].timestamp
        assert self.triggerable_withdrawals_gateway.getExitRequestLimitFullInfo() == (
            self.tw_limits.max_exits,
            self.tw_limits.exits_per_frame,
            self.tw_limits.frame_duration,
            self.tw_limits.available_exits,
            self._calculate_current_exit_limit(self.tw_limits, t),
        )
        assert self.validators_exit_bus_oracle.getExitRequestLimitFullInfo() == (
            self.veb_limits.max_exits,
            self.veb_limits.exits_per_frame,
            self.veb_limits.frame_duration,
            self.veb_limits.available_exits,
            self._calculate_current_exit_limit(self.veb_limits, t),
        )

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_total_vebo_requests(self):
        assert (
            self.validators_exit_bus_oracle.getTotalRequestsProcessed()
            == self.total_exit_requests_submitted
        )

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_max_veb_validators_per_report(self):
        assert (
            self.validators_exit_bus_oracle.getMaxValidatorsPerReport()
            == self.max_veb_validators_per_report
        )
