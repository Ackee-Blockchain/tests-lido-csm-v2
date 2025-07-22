from typing import List, Tuple, Callable
from typing_extensions import Literal

from wake.testing import keccak256
from hashlib import sha256

class MerkleTree:
    _is_ready: bool
    _leaves: List[bytes]
    _levels: List[List[bytes]]
    _hash_func: Callable[[bytes], bytes]
    _hash_leaves: bool
    _sort_pairs: bool

    def __init__(self, hash_func: Literal["keccak256", "sha256"] = "keccak256", hash_leaves: bool = True, sort_pairs: bool = True) -> None:
        self._is_ready = False
        self._leaves = []
        self._levels = []
        self._hash_leaves = hash_leaves
        self._sort_pairs = sort_pairs

        if hash_func == "keccak256":
            self._hash_func = keccak256
        elif hash_func == "sha256":
            self._hash_func = lambda x: sha256(x).digest()
        else:
            raise ValueError("Invalid hash function")

    @property
    def root(self) -> bytes:
        if not self._is_ready:
            self._build_tree()
        return self._levels[-1][0]

    @property
    def values(self) -> Tuple[bytes, ...]:
        return tuple(self._leaves)

    @property
    def leaves(self) -> Tuple[bytes, ...]:
        return tuple(self._leaves)

    def get_proof(self, index: int) -> List[bytes]:
        if not self._is_ready:
            self._build_tree()

        proof = []
        for level in self._levels[:-1]:
            if index % 2 == 0:
                proof.append(level[index + 1])
            else:
                proof.append(level[index - 1])
            index //= 2
        return proof

    def get_multiproof(self, indexes: List[int]) -> Tuple[List[bytes], List[bool]]:
        if not self._is_ready:
            self._build_tree()

        proof = []
        flags = []
        known = indexes
        assert known == sorted(known), "Leaves must be sorted"

        for level in self._levels[:-1]:
            new_known = []
            for i in known:
                if i % 2 == 0:
                    if i + 1 in known:
                        flags.append(True)
                    else:
                        flags.append(False)
                        if i + 1 < len(level):
                            proof.append(level[i + 1])
                        else:
                            proof.append(level[i])
                else:
                    if i - 1 in known:
                        pass  # already processed
                    else:
                        flags.append(False)
                        proof.append(level[i - 1])
                if len(new_known) == 0 or new_known[-1] != i // 2:
                    new_known.append(i // 2)
            known = new_known

        return proof, flags

    def add_leaf(self, leaf: bytes) -> int:
        self._leaves.append(leaf)
        self._is_ready = False
        return len(self._leaves) - 1

    def _build_tree(self) -> None:
        self._levels.clear()

        if self._hash_leaves:
            self._levels.append([self._hash_func(leaf) for leaf in self._leaves])
        else:
            self._levels.append(list(self._leaves))

        while len(self._levels[-1]) > 1:
            self._levels.append(self._build_level(self._levels[-1]))
        self._is_ready = True

    def _build_level(self, level: List[bytes]) -> List[bytes]:
        if len(level) % 2 == 1:
            level.append(level[-1])

        if self._sort_pairs:
            return [
                self._hash_func(level[i] + level[i + 1]) if level[i] < level[i + 1]
                else self._hash_func(level[i + 1] + level[i])
                for i in range(0, len(level), 2)
            ]
        else:
            return [self._hash_func(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
