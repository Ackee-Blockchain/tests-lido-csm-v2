from wake.testing import *


SECONDS_PER_SLOT = 12
SLOTS_PER_EPOCH = 32
EPOCHS_PER_FRAME = 225 * 28
SLOTS_PER_HISTORICAL_ROOT = 2**13
SECONDS_PER_FRAME = EPOCHS_PER_FRAME * SLOTS_PER_EPOCH * SECONDS_PER_SLOT  # 28 days
GENESIS_TIME = 1606824023
CAPELLA_SLOT = 194048 * SLOTS_PER_EPOCH  # 6_209_536

DEFAULT_INVARIANT_PERIOD = 10000


def timestamp_to_slot(timestamp: uint) -> uint:
    return (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT


def timestamp_to_epoch(timestamp: uint) -> uint:
    return timestamp_to_slot(timestamp) // SLOTS_PER_EPOCH


def slot_to_timestamp(slot: uint) -> uint:
    return slot * SECONDS_PER_SLOT + GENESIS_TIME


def get_frame_info(timestamp: uint, initial_epoch: int) -> tuple[uint, uint]:
    epoch = timestamp_to_epoch(timestamp)
    frame_start_epoch = (
        epoch - initial_epoch
    ) // EPOCHS_PER_FRAME * EPOCHS_PER_FRAME + initial_epoch
    frame_start_slot = frame_start_epoch * SLOTS_PER_EPOCH
    next_frame_start_slot = (frame_start_epoch + EPOCHS_PER_FRAME) * SLOTS_PER_EPOCH
    return frame_start_slot - 1, next_frame_start_slot - 1
