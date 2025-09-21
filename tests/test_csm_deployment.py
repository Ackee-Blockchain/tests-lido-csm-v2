import wake.deployment
from wake.testing import *

from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSStrikes import CSStrikes
from pytypes.csm.src.CSVerifier import CSVerifier
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.csm.src.lib.NOAddresses import NOAddresses
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.QueueLib import QueueLib
from pytypes.csm.src.CSParametersRegistry import CSParametersRegistry
from pytypes.csm.src.PermissionlessGate import PermissionlessGate
from pytypes.csm.src.VettedGate import VettedGate
from pytypes.csm.src.VettedGateFactory import VettedGateFactory
from pytypes.csm.src.CSExitPenalties import CSExitPenalties
from pytypes.csm.src.CSEjector import CSEjector
from pytypes.csm.src.interfaces.IGateSealFactory import IGateSealFactory
from pytypes.csm.src.interfaces.IGateSeal import IGateSeal
from pytypes.tests.Dummy import Dummy


pre_chain = Chain()
post_chain = wake.deployment.Chain()


@pre_chain.connect(fork="http://localhost:8545@23382310")
@post_chain.connect("http://localhost:8545")
def test_deployment():
    locator = Account("C1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb", chain=pre_chain)
    sender = Account("0x0a0e4961a6b7f5d7b4807df876ae068731102d44", chain=pre_chain)
    owner = Account("3e40d73eb977dc6a537af587d48316fee66e9c8c", chain=pre_chain)
    st_eth = Account("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", chain=pre_chain)
    withdrawal_vault = Account("0xB9D7934878B5FB9610B3fE8A5e441e8fad7E293f", chain=pre_chain)
    reseal_manager = Account("0x7914b5a1539b97Bd0bbd155757F25FD79A522d24", chain=pre_chain)
    lib_creator = Account("0x4e59b44847b379578588920cA78FbF26c0B4956C", chain=pre_chain)

    gate_seal_factory = IGateSealFactory("0x6C82877cAC5a7A739f16Ca0A89c0A328B8764A24", chain=pre_chain)
    gate_seal_factory.pytypes_resolver = IGateSealFactory

    module_proxy = OssifiableProxy("0xdA7dE2ECdDfccC6c3AF10108Db212ACBBf9EA83F", chain=pre_chain)
    fee_distributor_proxy = OssifiableProxy("0xD99CC66fEC647E68294C6477B40fC7E0F6F618D0", chain=pre_chain)
    accounting_proxy = OssifiableProxy("0x4d72BFF1BeaC69925F8Bd12526a39BAAb069e5Da", chain=pre_chain)
    fee_oracle_proxy = OssifiableProxy("0x4D4074628678Bd302921c20573EEa1ed38DdF7FB", chain=pre_chain)
    asset_recoverer_lib = AssetRecovererLib("0xa74528edc289b1a597Faf83fCfF7eFf871Cc01D9", chain=pre_chain)

    queue_lib = QueueLib(
        lib_creator.transact(bytes32(0) + QueueLib.get_creation_code()).return_value.hex(),
        chain=pre_chain
    )
    queue_lib2 = QueueLib("0x6eFF460627b6798C2907409EA2Fdfb287Eaa2e55", chain=post_chain)
    assert queue_lib.code == queue_lib2.code
    assert queue_lib.address == queue_lib2.address

    no_addresses = NOAddresses(
        lib_creator.transact(bytes32(0) + NOAddresses.get_creation_code()).return_value.hex(),
        chain=pre_chain
    )
    no_addresses2 = NOAddresses("0xE4d5a7be8d7c3db15755061053F5a49b6a67fFfc", chain=post_chain)
    assert no_addresses.code == no_addresses2.code
    assert no_addresses.address == no_addresses2.address

    post_chain.default_call_account = Account("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", chain=post_chain)
    pre_chain.default_tx_account = sender
    sender.nonce = 0x19

    pre_chain.mine(lambda t: 1758389397)

    # ---------------------------------------------------------------------

    parameters_registry = CSParametersRegistry.deploy(5, chain=pre_chain)
    parameters_registry2 = CSParametersRegistry("0x25fdc3be9977cd4da679df72a64c8b6bd5216a78", chain=post_chain)
    assert parameters_registry.code == parameters_registry2.code
    assert parameters_registry.address == parameters_registry2.address

    parameters_registry_proxy = OssifiableProxy.deploy(parameters_registry, owner, b"", chain=pre_chain)
    parameters_registry_proxy2 = OssifiableProxy("0x9d28ad303c90df524ba960d7a2dac56dcc31e428", chain=post_chain)
    assert parameters_registry_proxy.code == parameters_registry_proxy2.code
    assert parameters_registry_proxy.address == parameters_registry_proxy2.address

    params_init_data = CSParametersRegistry.InitializationData(
        keyRemovalCharge=0x470de4df820000,
        elRewardsStealingAdditionalFine=0x16345785d8a0000,
        keysLimit=0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        rewardShare=0x16ca,
        performanceLeeway=0x12c,
        strikesLifetime=6,
        strikesThreshold=3,
        defaultQueuePriority=5,
        defaultQueueMaxDeposits=0xffffffff,
        badPerformancePenalty=0x39499a2100d0000,
        attestationsWeight=0x36,
        blocksWeight=8,
        syncWeight=2,
        defaultAllowedExitDelay=0x54600,
        defaultExitDelayPenalty=0x16345785d8a0000,
        defaultMaxWithdrawalRequestFee=0x16345785d8a0000,
    )
    CSParametersRegistry(parameters_registry_proxy).initialize(
        sender,
        params_init_data,
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getKeyRemovalCharge(0) == params_init_data.keyRemovalCharge
    assert CSParametersRegistry(parameters_registry_proxy2).getElRewardsStealingAdditionalFine(0) == params_init_data.elRewardsStealingAdditionalFine
    assert CSParametersRegistry(parameters_registry_proxy2).getKeysLimit(0) == params_init_data.keysLimit
    assert CSParametersRegistry(parameters_registry_proxy2).getRewardShareData(0) == [CSParametersRegistry.KeyNumberValueInterval(1, params_init_data.rewardShare)]
    assert CSParametersRegistry(parameters_registry_proxy2).getPerformanceLeewayData(0) == [CSParametersRegistry.KeyNumberValueInterval(1, params_init_data.performanceLeeway)]
    assert CSParametersRegistry(parameters_registry_proxy2).getStrikesParams(0) == (params_init_data.strikesLifetime, params_init_data.strikesThreshold)
    assert CSParametersRegistry(parameters_registry_proxy2).getQueueConfig(0) == (params_init_data.defaultQueuePriority, params_init_data.defaultQueueMaxDeposits)
    assert CSParametersRegistry(parameters_registry_proxy2).getBadPerformancePenalty(0) == params_init_data.badPerformancePenalty
    assert CSParametersRegistry(parameters_registry_proxy2).getPerformanceCoefficients(0) == (params_init_data.attestationsWeight, params_init_data.blocksWeight, params_init_data.syncWeight)
    assert CSParametersRegistry(parameters_registry_proxy2).getAllowedExitDelay(0) == params_init_data.defaultAllowedExitDelay
    assert CSParametersRegistry(parameters_registry_proxy2).getExitDelayPenalty(0) == params_init_data.defaultExitDelayPenalty
    assert CSParametersRegistry(parameters_registry_proxy2).getMaxWithdrawalRequestFee(0) == params_init_data.defaultMaxWithdrawalRequestFee

    accounting = CSAccounting.deploy(locator, module_proxy, fee_distributor_proxy, 2419200, 31536000, chain=pre_chain, assetRecovererLib=asset_recoverer_lib)
    accounting2 = CSAccounting("0x6f09d2426c7405c5546413e6059f884d2d03f449", chain=post_chain)
    assert accounting.code == accounting2.code
    assert accounting.address == accounting2.address

    permissionless_gate = PermissionlessGate.deploy(module_proxy, sender, chain=pre_chain, assetRecovererLib=asset_recoverer_lib)
    permissionless_gate2 = PermissionlessGate("0xcf33a38111d0b1246a3f38a838fb41d626b454f0", chain=post_chain)
    assert permissionless_gate.code == permissionless_gate2.code
    assert permissionless_gate.address == permissionless_gate2.address

    vetted_gate_impl = VettedGate.deploy(module_proxy, chain=pre_chain, assetRecovererLib=asset_recoverer_lib)
    vetted_gate_impl2 = VettedGate("0x65d4d92cd0eabaa05cd5a46269c24b71c21cfdc4", chain=post_chain)
    assert vetted_gate_impl.code == vetted_gate_impl2.code
    assert vetted_gate_impl.address == vetted_gate_impl2.address

    vetted_gate_factory = VettedGateFactory.deploy(vetted_gate_impl, chain=pre_chain)
    vetted_gate_factory2 = VettedGateFactory("0xfdab48c4d627e500207e9af29c98579d90ea0ad4", chain=post_chain)
    assert vetted_gate_factory.code == vetted_gate_factory2.code
    assert vetted_gate_factory.address == vetted_gate_factory2.address

    tx = vetted_gate_factory.create(
        2,
        bytes.fromhex("91545c42adde0f5d82e4c228f81449eab20349c1d31a8538e0468466f93495c5"),
        "bafkreido7ieacbe6nlhdivxfp2gd5kxovofngf6qdmahih4laihm675e2a",
        sender,
    )
    assert tx.return_value == Address("0xb314d4a76c457c93150d308787939063f4cc67e0")
    vetted_gate_ics_proxy = OssifiableProxy("0xb314d4a76c457c93150d308787939063f4cc67e0", chain=pre_chain)
    vetted_gate_ics_proxy2 = OssifiableProxy("0xb314d4a76c457c93150d308787939063f4cc67e0", chain=post_chain)

    CSParametersRegistry(parameters_registry_proxy).setKeyRemovalCharge(
        2, 0x2386f26fc10000,
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getKeyRemovalCharge(2) == 0x2386f26fc10000

    CSParametersRegistry(parameters_registry_proxy).setElRewardsStealingAdditionalFine(
        2, 0xb1a2bc2ec50000
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getElRewardsStealingAdditionalFine(2) == 0xb1a2bc2ec50000

    CSParametersRegistry(parameters_registry_proxy).setKeysLimit(
        2, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getKeysLimit(2) == 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    CSParametersRegistry(parameters_registry_proxy).setPerformanceLeewayData(
        2, [
            CSParametersRegistry.KeyNumberValueInterval(1, 0x1f4),
            CSParametersRegistry.KeyNumberValueInterval(0x97, 0x12c)
        ]
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getPerformanceLeewayData(2) == [CSParametersRegistry.KeyNumberValueInterval(1, 0x1f4), CSParametersRegistry.KeyNumberValueInterval(0x97, 0x12c)]

    CSParametersRegistry(parameters_registry_proxy).setRewardShareData(
        2, [
            CSParametersRegistry.KeyNumberValueInterval(1, 0x2710),
            CSParametersRegistry.KeyNumberValueInterval(0x11, 0x16ca)
        ]
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getRewardShareData(2) == [CSParametersRegistry.KeyNumberValueInterval(1, 0x2710), CSParametersRegistry.KeyNumberValueInterval(0x11, 0x16ca)]

    CSParametersRegistry(parameters_registry_proxy).setStrikesParams(
        2, 6, 4
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getStrikesParams(2) == (6, 4)

    CSParametersRegistry(parameters_registry_proxy).setQueueConfig(
        2, 0, 10
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getQueueConfig(2) == (0, 10)

    CSParametersRegistry(parameters_registry_proxy).setBadPerformancePenalty(
        2, 0x2631116b55e0000
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getBadPerformancePenalty(2) == 0x2631116b55e0000

    CSParametersRegistry(parameters_registry_proxy).setPerformanceCoefficients(
        2, 0x36, 4, 2
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getPerformanceCoefficients(2) == (0x36, 4, 2)

    CSParametersRegistry(parameters_registry_proxy).setAllowedExitDelay(
        2, 0x69780
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getAllowedExitDelay(2) == 0x69780

    CSParametersRegistry(parameters_registry_proxy).setExitDelayPenalty(
        2, 0xb1a2bc2ec50000
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getExitDelayPenalty(2) == 0xb1a2bc2ec50000

    CSParametersRegistry(parameters_registry_proxy).setMaxWithdrawalRequestFee(
        2, 0x16345785d8a0000
    )
    assert CSParametersRegistry(parameters_registry_proxy2).getMaxWithdrawalRequestFee(2) == 0x16345785d8a0000

    vetted_gate_ics_proxy.proxy__changeAdmin(owner)

    fee_distributor = CSFeeDistributor.deploy(st_eth, accounting_proxy, fee_oracle_proxy, chain=pre_chain, assetRecovererLib=asset_recoverer_lib)
    fee_distributor2 = CSFeeDistributor("0x5dcf7cf7c6645e9e822a379df046a8b0390251a1", chain=post_chain)
    assert fee_distributor.code == fee_distributor2.code
    assert fee_distributor.address == fee_distributor2.address

    dummy = Dummy.deploy(chain=pre_chain)
    dummy2 = Dummy("0x8ff828860a67658c39d89809457a97d81aad418b", chain=post_chain)
    assert dummy.address == dummy2.address

    exit_penalties_proxy = OssifiableProxy.deploy(dummy, sender, b"", chain=pre_chain)
    exit_penalties_proxy2 = OssifiableProxy("0x06cd61045f958a209a0f8d746e103ecc625f4193", chain=post_chain)
    assert exit_penalties_proxy.code == exit_penalties_proxy2.code
    assert exit_penalties_proxy.address == exit_penalties_proxy2.address

    module = CSModule.deploy(
        bytes.fromhex("636f6d6d756e6974792d6f6e636861696e2d7631000000000000000000000000"),
        locator,
        parameters_registry_proxy,
        accounting_proxy,
        exit_penalties_proxy,
        chain=pre_chain,
        nOAddresses=no_addresses,
        assetRecovererLib=asset_recoverer_lib,
        queueLib=queue_lib,
    )
    module2 = CSModule("0x1eb6d4da13ca9566c17f526ae0715325d7a07665", chain=post_chain)
    assert module.code == module2.code
    assert module.address == module2.address

    strikes = CSStrikes.deploy(
        module_proxy,
        fee_oracle_proxy,
        exit_penalties_proxy,
        parameters_registry_proxy,
        chain=pre_chain,
    )
    strikes2 = CSStrikes("0x3e5021424c9e13fc853e523cd68ebbec848956a0", chain=post_chain)
    assert strikes.code == strikes2.code
    assert strikes.address == strikes2.address

    strikes_proxy = OssifiableProxy.deploy(strikes, owner, b"", chain=pre_chain)
    strikes_proxy2 = OssifiableProxy("0xaa328816027f2d32b9f56d190bc9fa4a5c07637f", chain=post_chain)
    assert strikes_proxy.code == strikes_proxy2.code
    assert strikes_proxy.address == strikes_proxy2.address

    fee_oracle = CSFeeOracle.deploy(
        fee_distributor_proxy,
        strikes_proxy,
        12,
        1606824023,
        chain=pre_chain,
        assetRecovererLib=asset_recoverer_lib,
    )
    fee_oracle2 = CSFeeOracle("0xe0b234f99e413e27d9bc31abba9a49a3e570da97", chain=post_chain)
    assert fee_oracle.code == fee_oracle2.code
    assert fee_oracle.address == fee_oracle2.address

    exit_penalties = CSExitPenalties.deploy(
        module_proxy,
        parameters_registry_proxy,
        strikes_proxy,
        chain=pre_chain,
    )
    exit_penalties2 = CSExitPenalties("0xda22fa1cea40d05fe4cd536967afdd839586d546", chain=post_chain)
    assert exit_penalties.code == exit_penalties2.code
    assert exit_penalties.address == exit_penalties2.address

    exit_penalties_proxy.proxy__upgradeTo(exit_penalties)
    exit_penalties_proxy.proxy__changeAdmin(owner)

    ejector = CSEjector.deploy(
        module_proxy,
        strikes_proxy,
        3,
        sender,
        chain=pre_chain,
        assetRecovererLib=asset_recoverer_lib,
    )
    ejector2 = CSEjector("0xc72b58aa02e0e98cf8a4a0e9dce75e763800802c", chain=post_chain)
    assert ejector.code == ejector2.code
    assert ejector.address == ejector2.address

    CSStrikes(strikes_proxy).initialize(sender, ejector)

    verifier = CSVerifier.deploy(
        withdrawal_vault,
        module_proxy,
        32,
        8192,
        CSVerifier.GIndices(
            gIFirstWithdrawalPrev=bytes.fromhex("000000000000000000000000000000000000000000000000000000000161c004"),
            gIFirstWithdrawalCurr=bytes.fromhex("000000000000000000000000000000000000000000000000000000000161c004"),
            gIFirstValidatorPrev=bytes.fromhex("0000000000000000000000000000000000000000000000000096000000000028"),
            gIFirstValidatorCurr=bytes.fromhex("0000000000000000000000000000000000000000000000000096000000000028"),
            gIFirstHistoricalSummaryPrev=bytes.fromhex("000000000000000000000000000000000000000000000000000000b600000018"),
            gIFirstHistoricalSummaryCurr=bytes.fromhex("000000000000000000000000000000000000000000000000000000b600000018"),
            gIFirstBlockRootInSummaryPrev=bytes.fromhex("000000000000000000000000000000000000000000000000000000000040000d"),
            gIFirstBlockRootInSummaryCurr=bytes.fromhex("000000000000000000000000000000000000000000000000000000000040000d"),
        ),
        11649024,
        11649024,
        6209536,
        sender,
        chain=pre_chain,
    )
    verifier2 = CSVerifier("0xdc5fe1782b6943f318e05230d688713a560063dc", chain=post_chain)
    assert verifier.code == verifier2.code
    assert verifier.address == verifier2.address

    # create gate seal
    tx = gate_seal_factory.create_gate_seal(
        Address("0xC52fC3081123073078698F1EAc2f1Dc7Bd71880f"),
        950400,
        [
            module_proxy,
            accounting_proxy,
            fee_oracle_proxy,
            verifier,
            vetted_gate_ics_proxy,
            ejector,
        ],
        1789648283
    )
    gate_seal = IGateSeal(next(e.gateSeal for e in tx.events if isinstance(e, IGateSealFactory.GateSealCreated)), chain=pre_chain)
    gate_seal2 = IGateSeal("0xE1686C2E90eb41a48356c1cC7FaA17629af3ADB3", chain=post_chain)
    assert gate_seal.code == gate_seal2.code
    assert gate_seal.address == gate_seal2.address
    assert gate_seal2.get_sealing_committee() == Address("0xC52fC3081123073078698F1EAc2f1Dc7Bd71880f")
    assert gate_seal2.get_seal_duration_seconds() == 950400
    assert gate_seal2.get_sealables() == [module_proxy.address, accounting_proxy.address, fee_oracle_proxy.address, verifier.address, vetted_gate_ics_proxy.address, ejector.address]
    assert gate_seal2.get_expiry_timestamp() == 1789648283
    assert gate_seal2.is_expired() == False

    verifier.grantRole(verifier.PAUSE_ROLE(), reseal_manager)
    verifier.grantRole(verifier.RESUME_ROLE(), reseal_manager)

    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).PAUSE_ROLE(), reseal_manager)
    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).RESUME_ROLE(), reseal_manager)

    ejector.grantRole(ejector.PAUSE_ROLE(), reseal_manager)
    ejector.grantRole(ejector.RESUME_ROLE(), reseal_manager)
    ejector.grantRole(ejector.PAUSE_ROLE(), gate_seal)
    ejector.grantRole(ejector.DEFAULT_ADMIN_ROLE(), owner)
    ejector.revokeRole(ejector.DEFAULT_ADMIN_ROLE(), sender)

    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).RECOVERER_ROLE(), gate_seal)
    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).DEFAULT_ADMIN_ROLE(), owner)
    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).SET_TREE_ROLE(), Address("0xfe5986e06210ac1ecc1adcafc0cc7f8d63b3f977"))
    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).START_REFERRAL_SEASON_ROLE(), owner)
    VettedGate(vetted_gate_ics_proxy).grantRole(VettedGate(vetted_gate_ics_proxy).END_REFERRAL_SEASON_ROLE(), Address("0xc52fc3081123073078698f1eac2f1dc7bd71880f"))
    VettedGate(vetted_gate_ics_proxy).revokeRole(VettedGate(vetted_gate_ics_proxy).DEFAULT_ADMIN_ROLE(), sender)

    permissionless_gate.grantRole(permissionless_gate.DEFAULT_ADMIN_ROLE(), owner)
    permissionless_gate.revokeRole(permissionless_gate.DEFAULT_ADMIN_ROLE(), sender)

    verifier.grantRole(verifier.PAUSE_ROLE(), gate_seal)
    verifier.grantRole(verifier.DEFAULT_ADMIN_ROLE(), owner)
    verifier.revokeRole(verifier.DEFAULT_ADMIN_ROLE(), sender)

    CSParametersRegistry(parameters_registry_proxy).grantRole(CSParametersRegistry(parameters_registry_proxy).DEFAULT_ADMIN_ROLE(), owner)
    CSParametersRegistry(parameters_registry_proxy).revokeRole(CSParametersRegistry(parameters_registry_proxy).DEFAULT_ADMIN_ROLE(), sender)

    CSStrikes(strikes_proxy).grantRole(CSStrikes(strikes_proxy).DEFAULT_ADMIN_ROLE(), owner)
    CSStrikes(strikes_proxy).revokeRole(CSStrikes(strikes_proxy).DEFAULT_ADMIN_ROLE(), sender)

    assert accounting2.MODULE().address == module_proxy.address
    assert accounting2.FEE_DISTRIBUTOR().address == fee_distributor_proxy.address

    assert not ejector2.hasRole(ejector2.DEFAULT_ADMIN_ROLE(), sender.address)
    assert ejector2.hasRole(ejector2.DEFAULT_ADMIN_ROLE(), owner.address)
    assert ejector2.STAKING_MODULE_ID() == 3
    assert ejector2.MODULE().address == module_proxy.address
    assert ejector2.STRIKES() == strikes_proxy.address

    assert exit_penalties2.MODULE().address == module_proxy.address
    assert exit_penalties2.PARAMETERS_REGISTRY().address == parameters_registry_proxy.address
    assert exit_penalties2.ACCOUNTING().address == accounting_proxy.address
    assert exit_penalties2.STRIKES() == strikes_proxy.address

    assert fee_distributor2.STETH().address == st_eth.address
    assert fee_distributor2.ACCOUNTING() == accounting_proxy.address
    assert fee_distributor2.ORACLE() == fee_oracle_proxy.address

    assert fee_oracle2.FEE_DISTRIBUTOR().address == fee_distributor_proxy.address
    assert fee_oracle2.STRIKES().address == strikes_proxy.address

    assert module2.getType() == bytes.fromhex("636f6d6d756e6974792d6f6e636861696e2d7631000000000000000000000000")
    assert module2.LIDO_LOCATOR().address == locator.address
    assert module2.STETH().address == st_eth.address
    assert module2.PARAMETERS_REGISTRY().address == parameters_registry_proxy.address
    assert module2.ACCOUNTING().address == accounting_proxy.address
    assert module2.EXIT_PENALTIES().address == exit_penalties_proxy.address
    assert module2.FEE_DISTRIBUTOR() == fee_distributor_proxy.address
    assert module2.QUEUE_LOWEST_PRIORITY() == 5
    assert module2.QUEUE_LEGACY_PRIORITY() == 4

    assert parameters_registry2.QUEUE_LOWEST_PRIORITY() == 5
    assert parameters_registry2.QUEUE_LEGACY_PRIORITY() == 4

    assert strikes2.ORACLE() == fee_oracle_proxy.address
    assert strikes2.MODULE().address == module_proxy.address
    assert strikes2.ACCOUNTING().address == accounting_proxy.address
    assert strikes2.EXIT_PENALTIES().address == exit_penalties_proxy.address
    assert strikes2.PARAMETERS_REGISTRY().address == parameters_registry_proxy.address

    assert verifier2.SLOTS_PER_EPOCH() == 32
    assert verifier2.SLOTS_PER_HISTORICAL_ROOT() == 8192
    assert verifier2.GI_FIRST_WITHDRAWAL_PREV() == bytes.fromhex("000000000000000000000000000000000000000000000000000000000161c004")
    assert verifier2.GI_FIRST_WITHDRAWAL_CURR() == bytes.fromhex("000000000000000000000000000000000000000000000000000000000161c004")
    assert verifier2.GI_FIRST_VALIDATOR_PREV() == bytes.fromhex("0000000000000000000000000000000000000000000000000096000000000028")
    assert verifier2.GI_FIRST_VALIDATOR_CURR() == bytes.fromhex("0000000000000000000000000000000000000000000000000096000000000028")
    assert verifier2.GI_FIRST_HISTORICAL_SUMMARY_PREV() == bytes.fromhex("000000000000000000000000000000000000000000000000000000b600000018")
    assert verifier2.GI_FIRST_HISTORICAL_SUMMARY_CURR() == bytes.fromhex("000000000000000000000000000000000000000000000000000000b600000018")
    assert verifier2.GI_FIRST_BLOCK_ROOT_IN_SUMMARY_PREV() == bytes.fromhex("000000000000000000000000000000000000000000000000000000000040000d")
    assert verifier2.GI_FIRST_BLOCK_ROOT_IN_SUMMARY_CURR() == bytes.fromhex("000000000000000000000000000000000000000000000000000000000040000d")
    assert verifier2.FIRST_SUPPORTED_SLOT() == 11649024
    assert verifier2.PIVOT_SLOT() == 11649024
    assert verifier2.CAPELLA_SLOT() == 6209536
    assert verifier2.WITHDRAWAL_ADDRESS() == withdrawal_vault.address
    assert verifier2.MODULE().address == module_proxy.address

    assert permissionless_gate2.CURVE_ID() == 0
    assert permissionless_gate2.MODULE().address == module_proxy.address

    assert VettedGate(vetted_gate_ics_proxy2).MODULE().address == module_proxy.address
    assert VettedGate(vetted_gate_ics_proxy2).ACCOUNTING().address == accounting_proxy.address
    assert VettedGate(vetted_gate_ics_proxy2).curveId() == 2

    assert vetted_gate_factory2.VETTED_GATE_IMPL() == vetted_gate_impl.address
