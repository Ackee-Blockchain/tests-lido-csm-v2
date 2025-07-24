#!/bin/bash

wake svm use 0.4.24
wake-solc --bin -o bin '@aragon/=tw/node_modules/@aragon/' \
    'tw:contracts/=tw/contracts/' \
    tw/contracts/0.4.24/nos/NodeOperatorsRegistry.sol \
    tw/node_modules/@aragon/os/contracts/kernel/Kernel.sol \
    tw/node_modules/@aragon/os/contracts/acl/ACL.sol \
    --allow-paths "" --optimize --optimize-runs 200 --overwrite --evm-version constantinople
