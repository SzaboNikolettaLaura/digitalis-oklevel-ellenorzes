"""
Merkle-fa modul.

A fa szintjeit egy listában tároljuk: tree[0] a gyökérszint (egyetlen elem),
tree[-1] a levelek szintje. Páratlan elemszámú szinten az utolsó elemet
önmagával párosítjuk (duplikáljuk), ahogy a Bitcoin is teszi.
"""

from crypto_service import blake_hash

MerkleTree = list[list[bytes]]
MerkleProof = list[tuple[bytes, str]]  # (testvér hash, 'left' | 'right')


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Két gyerek-hash összefűzése és hash-elése a szülő csomóponthoz."""
    return blake_hash(left + right)


def build_merkle_tree(leaf_hashes: list[bytes]) -> tuple[MerkleTree, bytes]:
    """Bináris Merkle-fa felépítése iteratívan, alulról felfelé.

    Args:
        leaf_hashes: a levelek (oklevél-hash-ek) listája.

    Returns:
        (a teljes fa szintenként, gyökértől a levelekig; a Merkle-gyökér)
    """
    if not leaf_hashes:
        raise ValueError('Üres levéllistából nem építhető Merkle-fa.')

    level = list(leaf_hashes)
    tree: MerkleTree = [level]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_hash_pair(left, right))
        tree.insert(0, next_level)
        level = next_level
    return tree, tree[0][0]


def get_merkle_proof(leaf_index: int, leaves: list[bytes]) -> MerkleProof:
    """Proof of Inclusion: a testvér-hash-ek listája a levéltől a gyökérig.

    Args:
        leaf_index: a bizonyítandó levél indexe.
        leaves: a fa összes levele (ugyanabban a sorrendben, mint építéskor).

    Returns:
        (testvér hash, oldal) párok listája; az oldal azt mondja meg,
        hogy a testvér a bal ('left') vagy a jobb ('right') oldalon áll.
    """
    if not 0 <= leaf_index < len(leaves):
        raise IndexError(f'Érvénytelen levélindex: {leaf_index}')

    tree, _ = build_merkle_tree(leaves)
    proof: MerkleProof = []
    index = leaf_index
    for level_index in range(len(tree) - 1, 0, -1):
        level = tree[level_index]
        if index % 2 == 0:
            sibling_index, position = index + 1, 'right'
            if sibling_index >= len(level):  # páratlan szint: önmaga a testvér
                sibling_index = index
        else:
            sibling_index, position = index - 1, 'left'
        proof.append((level[sibling_index], position))
        index //= 2
    return proof


def verify_merkle_proof(leaf_hash: bytes, proof: MerkleProof,
                        merkle_root: bytes) -> bool:
    """A gyökér újraszámítása a levélből és a proofból, majd összevetése.

    Returns:
        True, ha a kiszámított gyökér megegyezik a megadott Merkle-gyökérrel.
    """
    current = leaf_hash
    for sibling, position in proof:
        if position == 'left':
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)
    return current == merkle_root


def print_merkle_tree(tree: MerkleTree, prefix_len: int = 8) -> None:
    """A fa kiírása szintenként, a hash-ek első néhány hexa jegyével."""
    for depth, level in enumerate(tree):
        print(f'  {depth}. szint: ' + ' '.join(h.hex()[:prefix_len] for h in level))
