"""
Mini blokklánc modul a Merkle-gyökerek módosíthatatlan tárolására.

Minden blokk egy kiállítási köteg Merkle-gyökerét tartalmazza.
A blokkokat egyszerű Proof-of-Work-kel bányásszuk: a blokk hash-ének
(hexában) `difficulty` darab nullával kell kezdődnie.
"""

import time
from dataclasses import dataclass, field

from crypto_service import blake_hash

DEFAULT_DIFFICULTY = 3
GENESIS_PREVIOUS_HASH = '0' * 64
GENESIS_MERKLE_ROOT = '0' * 64


@dataclass
class Block:
    """A blokklánc egy blokkja. A hash-ek hexa sztringként vannak tárolva."""

    index: int
    timestamp: float
    previous_hash: str
    merkle_root: str
    nonce: int = 0
    hash: str = field(default='')

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """A blokk fejlécének hash-e (index, időbélyeg, előző hash, gyökér, nonce)."""
        header = (f'{self.index}|{self.timestamp}|{self.previous_hash}|'
                  f'{self.merkle_root}|{self.nonce}')
        return blake_hash(header.encode()).hex()

    def mine(self, difficulty: int) -> None:
        """Proof-of-Work: a nonce növelése, amíg a hash elég nullával nem kezdődik."""
        target = '0' * difficulty
        start = time.perf_counter()
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        elapsed = time.perf_counter() - start
        print(f'  [PoW] Blokk #{self.index} kibányászva: nonce={self.nonce}, '
              f'hash={self.hash[:16]}..., idő={elapsed:.3f} s')


class Blockchain:
    """Egyszerű blokklánc genesis blokkal és PoW-bányászattal."""

    def __init__(self, difficulty: int = DEFAULT_DIFFICULTY) -> None:
        self.difficulty = difficulty
        self.chain: list[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """A genesis (0.) blokk létrehozása és kibányászása."""
        genesis = Block(index=0, timestamp=time.time(),
                        previous_hash=GENESIS_PREVIOUS_HASH,
                        merkle_root=GENESIS_MERKLE_ROOT)
        genesis.mine(self.difficulty)
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, merkle_root: bytes | str) -> Block:
        """Új blokk bányászása a megadott Merkle-gyökérrel.

        Returns:
            Az újonnan láncra fűzött blokk.
        """
        root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        block = Block(index=len(self.chain), timestamp=time.time(),
                      previous_hash=self.last_block.hash, merkle_root=root_hex)
        block.mine(self.difficulty)
        self.chain.append(block)
        return block

    def get_merkle_root(self, block_index: int) -> bytes:
        """A megadott blokkban tárolt Merkle-gyökér bájtként."""
        return bytes.fromhex(self.chain[block_index].merkle_root)

    def is_chain_valid(self) -> bool:
        """A teljes lánc sértetlenségének ellenőrzése.

        Minden blokkra ellenőrzi: a tárolt hash egyezik-e az újraszámolttal,
        teljesül-e a PoW feltétel, és (a genesis kivételével) helyes-e az
        index és az előző blokkra mutató hash.
        """
        target = '0' * self.difficulty
        for i, block in enumerate(self.chain):
            if block.hash != block.calculate_hash():
                return False
            if not block.hash.startswith(target):
                return False
            if i == 0:
                if block.previous_hash != GENESIS_PREVIOUS_HASH:
                    return False
                continue
            previous = self.chain[i - 1]
            if block.index != previous.index + 1:
                return False
            if block.previous_hash != previous.hash:
                return False
        return True
