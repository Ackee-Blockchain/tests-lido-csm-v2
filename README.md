# Tests for Lido Community Staking Module v2
This repository serves as an example of tests written in a development and testing framework called [Wake](https://github.com/Ackee-Blockchain/wake).

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

## Setup

1. Clone this repository
2. `git submodule update --init --recursive` if not cloned with `--recursive`
3. `cd csm && yarn install && cd ..` to install CSM dependencies

## Running fuzz tests

1. `wake up pytypes` to generate pytypes
2. `wake test tests/csm/test_fuzz.py` to run CSM fuzz test that forks CSM v1 contracts from mainnet and upgrades them to v2
3. `wake test tests/csm/test_no_upgrade_fuzz.py` to run CSM fuzz test that deploys CSM v2 contracts as new

Tested with `wake` version `5.0.0`. Fuzz tests expect a local Ethereum mainnet node running at http://localhost:8545 synchronized to the block `22576118` or later.