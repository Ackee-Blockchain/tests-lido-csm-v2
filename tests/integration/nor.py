from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.migrated.aragon.os.contracts.acl.ACL import ACL
from pytypes.tw.contracts._0_8_9.StakingRouter import StakingRouter
from pytypes.tw.contracts.common.lib.MinFirstAllocationStrategy import MinFirstAllocationStrategy
from pytypes.migrated.nos.NodeOperatorsRegistry import NodeOperatorsRegistry

from .common import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


LIDO_LOCATOR = Account("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")


def deploy_nor():
    mfs = MinFirstAllocationStrategy.deploy()
    nor_code = (Path(__file__).parent.parent.parent / "bin" / "NodeOperatorsRegistry.bin").read_text()
    nor_code = nor_code.replace("__tw/contracts/common/lib/MinFirstAllo__", str(mfs.address)[2:])
    nor = chain.deploy(bytes.fromhex(nor_code))
    nor.pytypes_resolver = NodeOperatorsRegistry
    return NodeOperatorsRegistry(nor)


@dataclass
class NorOperator:
    id: int
    name: str
    reward_address: Account
    active: bool
    vetted_keys: int
    exited_keys: int
    added_keys: int  # all keys (including deposited)
    deposited_keys: int  # including withdrawn (exited)
    keys: list[bytes]
    signatures: list[bytes]
    withdrawn: dict[int, bool]  # validator key index -> withdrawn


class NorFuzzTest:
    # from tw
    admin: Account
    staking_router: StakingRouter
    nor_id: int

    # self-managed
    nor_operators: dict[int, NorOperator]
    nor_exit_delay_threshold: int
    nor_exit_delay_reported: dict[bytes, bool]  # validator pubkey -> reported
    nor_no_id: int
    nor: NodeOperatorsRegistry

    def pre_sequence(self) -> None:
        self.nor_exit_delay_threshold = random.randint(1, 1000)

        self._deploy_or_upgrade()

        self.nor_operators = {}
        self.nor_exit_delay_reported = defaultdict(bool)

        self._migrate_forked_node_operators()
        self.nor_no_id = len(self.nor_operators)

    def _deploy_or_upgrade(self):
        self.nor = NodeOperatorsRegistry(0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5)

        self.nor.kernel().setApp(
            keccak256(b"base"),
            self.nor.appId(),
            NodeOperatorsRegistry.deploy(),
            from_=Account("0x2e59A20f205bB85a89C53f1936454680651E618e"),
        )
        self.nor.finalizeUpgrade_v4(self.nor_exit_delay_threshold)

        kernel_acl = ACL(self.nor.kernel().acl())

        kernel_acl.grantPermission(
            self.admin,
            self.nor,
            self.nor.MANAGE_NODE_OPERATOR_ROLE(),
            from_=Account("0x2e59A20f205bB85a89C53f1936454680651E618e"),
        )
        kernel_acl.grantPermission(
            self.admin,
            self.nor,
            self.nor.SET_NODE_OPERATOR_LIMIT_ROLE(),
            from_=Account("0x2e59A20f205bB85a89C53f1936454680651E618e"),
        )
        kernel_acl.grantPermission(
            self.staking_router,
            self.nor,
            self.nor.STAKING_ROUTER_ROLE(),
            from_=Account("0x2e59A20f205bB85a89C53f1936454680651E618e"),
        )

        all_modules = self.staking_router.getStakingModules()
        self.nor_id = next(m.id for m in all_modules if m.stakingModuleAddress == self.nor.address)

    def _migrate_forked_node_operators(self):
        total_node_operators = self.nor.getNodeOperatorsCount()
        for no_id in range(total_node_operators):
            no = self.nor.getNodeOperator(no_id, True)

            total_keys = self.nor.getTotalSigningKeyCount(no_id)
            pubkeys = bytearray()
            signatures = bytearray()
            for i in range(0, total_keys, 100):
                pubkeys_batch, signatures_batch, _ = self.nor.getSigningKeys(no_id, i, min(100, total_keys - i))
                pubkeys.extend(pubkeys_batch)
                signatures.extend(signatures_batch)
            assert len(pubkeys) == total_keys * 48
            assert len(signatures) == total_keys * 96

            self.nor_operators[no_id] = NorOperator(
                id=no_id,
                name=no[1],
                reward_address=Account(no[2]),
                active=no[0],
                vetted_keys=no[3],
                exited_keys=no[4],
                added_keys=no[5],
                deposited_keys=no[6],
                keys=[pubkeys[i : i + 48] for i in range(0, len(pubkeys), 48)],
                signatures=[signatures[i : i + 96] for i in range(0, len(signatures), 96)],
                withdrawn=defaultdict(bool),  # this info is not available in NOR
            )
            print("vetted_keys", no[3], "exited_keys", no[4], "deposited_keys", no[6])
            logger.info(f"Migrated node operator {no_id + 1}/{total_node_operators}")

    def nor_pre_deposit(self) -> int:
        return sum(
            op.vetted_keys - op.deposited_keys
            for op in self.nor_operators.values()
        )

    def nor_post_deposit(self, count: int, tx: TransactionAbc):
        # do not try to simulate MinFirstAllocationStrategy logic, just collect data from events
        deposited = 0
        for e in tx.events:
            if isinstance(e, NodeOperatorsRegistry.DepositedSigningKeysCountChanged):
                op = self.nor_operators[e.nodeOperatorId]
                if e.depositedValidatorsCount != op.deposited_keys:
                    deposited += e.depositedValidatorsCount - op.deposited_keys
                    op.deposited_keys = e.depositedValidatorsCount

        assert deposited == count

    def nor_post_trigger_exits(self, withdrawal_request_fee: int, exited: list[tuple[int, int, int, bytes]], tx: TransactionAbc):
        assert [
            e
            for e in tx.events
            if isinstance(e, NodeOperatorsRegistry.ValidatorExitTriggered)
        ] == [
            NodeOperatorsRegistry.ValidatorExitTriggered(
                nodeOperatorId=op_id,
                publicKey=pubkey,
                withdrawalRequestPaidFee=withdrawal_request_fee,
                exitType=2,
            )
            for module_id, op_id, _, pubkey in exited
            if module_id == self.nor_id
        ]

    def nor_on_validator_exit_delay(self, node_op_id: int, pubkey: bytes, eligible_to_exit: int, penalty_applicable: bool, proof_timestamp: int, tx: TransactionAbc) -> str | None:
        if eligible_to_exit < self.nor_exit_delay_threshold:
            assert tx.error == Error("EXIT_DELAY_BELOW_THRESHOLD")
            assert not penalty_applicable
            return f"Exit delay below threshold"

        if tx.error is None:
            if pubkey not in self.nor_exit_delay_reported:
                self.nor_exit_delay_reported[pubkey] = True
                assert NodeOperatorsRegistry.ValidatorExitStatusUpdated(
                    node_op_id,
                    pubkey,
                    eligible_to_exit,
                    proof_timestamp,
                ) in tx.events
                assert penalty_applicable
            else:
                assert not any(
                    e for e in tx.events
                    if isinstance(e, NodeOperatorsRegistry.ValidatorExitStatusUpdated)
                    and e.nodeOperatorId == node_op_id
                    and e.publicKey == pubkey
                )
                assert not penalty_applicable

    @flow()
    def flow_nor_add_node_operator(self):
        if len(self.nor_operators) >= 200:
            return "Too many node operators"

        name = random_string(1, 10)
        reward_address = random_account()

        tx = self.nor.addNodeOperator(name, reward_address, from_=self.admin)

        assert (
            NodeOperatorsRegistry.NodeOperatorAdded(
                self.nor_no_id, name, reward_address.address, 0
            )
            in tx.events
        )

        self.nor_operators[self.nor_no_id] = NorOperator(
            self.nor_no_id,
            name,
            reward_address,
            True,
            0,
            0,
            0,
            0,
            [],
            [],
            defaultdict(bool),
        )
        self.nor_no_id += 1

        logger.info(
            f"Added node operator {self.nor_no_id} with name {name} and reward address {reward_address}"
        )

    @flow()
    def flow_nor_activate_node_operator(self):
        try:
            operator = random.choice(
                [op for op in self.nor_operators.values() if not op.active]
            )
        except IndexError:
            return "No inactive node operators"

        tx = self.nor.activateNodeOperator(operator.id, from_=self.admin)

        assert (
            NodeOperatorsRegistry.NodeOperatorActiveSet(operator.id, True) in tx.events
        )

        operator.active = True

        logger.info(f"Activated node operator {operator.id}")

    @flow()
    def flow_nor_deactivate_node_operator(self):
        try:
            operator = random.choice(
                [op for op in self.nor_operators.values() if op.active]
            )
        except IndexError:
            return "No active node operators"

        tx = self.nor.deactivateNodeOperator(operator.id, from_=self.admin)

        assert (
            NodeOperatorsRegistry.NodeOperatorActiveSet(operator.id, False) in tx.events
        )

        operator.active = False
        operator.vetted_keys = operator.deposited_keys

        logger.info(f"Deactivated node operator {operator.id}")

    @flow()
    def flow_nor_set_node_operator_name(self):
        try:
            operator = random.choice(list(self.nor_operators.values()))
        except IndexError:
            return "No node operators"

        name = random_string(1, 10)
        with may_revert() as ex:
            tx = self.nor.setNodeOperatorName(operator.id, name, from_=self.admin)

        if name == operator.name:
            assert ex.value == Error("VALUE_IS_THE_SAME")
            return "Name is the same"
        else:
            assert ex.value is None

        assert NodeOperatorsRegistry.NodeOperatorNameSet(operator.id, name) in tx.events

        operator.name = name

        logger.info(f"Set node operator {operator.id} name to {name}")

    @flow()
    def flow_nor_set_node_operator_reward_address(self):
        try:
            operator = random.choice(list(self.nor_operators.values()))
        except IndexError:
            return "No node operators"

        reward_address = random_account()
        with may_revert() as ex:
            tx = self.nor.setNodeOperatorRewardAddress(
                operator.id, reward_address, from_=self.admin
            )

        if reward_address == operator.reward_address:
            assert ex.value == Error("VALUE_IS_THE_SAME")
            return "Reward address is the same"
        else:
            assert ex.value is None

        assert (
            NodeOperatorsRegistry.NodeOperatorRewardAddressSet(
                operator.id, reward_address.address
            )
            in tx.events
        )

        operator.reward_address = reward_address

        logger.info(
            f"Set node operator {operator.id} reward address to {reward_address}"
        )

    @flow()
    def flow_nor_set_node_operator_staking_limit(self):
        try:
            operator = random.choice(list(self.nor_operators.values()))
        except IndexError:
            return "No node operators"

        staking_limit = random.randint(0, 100)
        with may_revert() as ex:
            tx = self.nor.setNodeOperatorStakingLimit(
                operator.id, staking_limit, from_=self.admin
            )

        if not operator.active:
            assert ex.value == Error("WRONG_OPERATOR_ACTIVE_STATE")
            return "Node operator is not active"
        else:
            assert ex.value is None

        operator.vetted_keys = min(
            operator.added_keys, max(operator.deposited_keys, staking_limit)
        )

        logger.info(f"Set node operator {operator.id} staking limit to {staking_limit}")

    @flow()
    def flow_nor_add_signing_keys(self):
        try:
            operator = random.choice(list(self.nor_operators.values()))
        except IndexError:
            return "No node operators"

        count = random_int(1, 10)
        pubkeys = [random_bytes(48) for _ in range(count)]
        signatures = [random_bytes(96) for _ in range(count)]

        with may_revert() as ex:
            tx = self.nor.addSigningKeys(
                operator.id,
                count,
                b"".join(pubkeys),
                b"".join(signatures),
                from_=operator.reward_address,
            )

        if not operator.active:
            assert ex.value == Error("APP_AUTH_FAILED")
            return "Node operator is not active"
        else:
            assert ex.value is None

        operator.added_keys += count
        operator.keys.extend(pubkeys)
        operator.signatures.extend(signatures)

        logger.info(f"Added {count} signing keys to node operator {operator.id}")

    @invariant(period=DEFAULT_INVARIANT_PERIOD)
    def invariant_nor_operators(self):
        for operator in self.nor_operators.values():
            assert self.nor.getNodeOperator(operator.id, True) == (
                operator.active,
                operator.name,
                operator.reward_address.address,
                operator.vetted_keys,
                operator.exited_keys,
                operator.added_keys,
                operator.deposited_keys,
            )
