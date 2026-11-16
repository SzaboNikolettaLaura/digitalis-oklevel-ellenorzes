import copy
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import crypto_service as cs
from blockchain import Blockchain
from merkle_tree import (MerkleProof, build_merkle_tree, get_merkle_proof,
                         print_merkle_tree, verify_merkle_proof)

Credential = dict[str, Any]


def section(title: str) -> None:
    print('\n' + '=' * 70)
    print(f' {title}')
    print('=' * 70)


def create_sample_credentials() -> list[Credential]:
    """5 minta-oklevél létrehozása (romániai rendszer: licenc/mesteri, 1–10-es jegy)."""
    data = [
        ('Kovács Anna', 'Számítástechnika', 'Licenc', '2026-07-01', '9,80'),
        ('Szabó Péter', 'Szoftverfejlesztés', 'Mesteri', '2026-07-01', '8,75'),
        ('Nagy Eszter', 'Automatika és alkalmazott informatika', 'Licenc', '2026-07-02', '9,65'),
        ('Tóth Bence', 'Kertészmérnöki', 'Licenc', '2026-07-03', '7,40'),
        ('Fekete Dóra', 'Fordító és tolmács', 'Licenc', '2026-07-03', '8,90'),
    ]
    return [
        {
            'oklevel_azonosito': f'SAPI-2026-{i + 1:04d}',
            'kibocsato': 'Sapientia EMTE',
            'hallgato_neve': name,
            'szak': major,
            'diploma_tipus': degree,
            'kiallitas_datuma': date,
            'minosites': grade,
        }
        for i, (name, major, degree, date, grade) in enumerate(data)
    ]


def verify_credential(credential: Credential, signature: bytes, proof: MerkleProof,
                      block_index: int, public_key: Ed25519PublicKey,
                      chain: Blockchain) -> bool:
    """Munkáltatói oldali teljes ellenőrzés, lépésenként kiírva.

    1. A blokklánc sértetlen-e.
    2. A dokumentum hash-ének újraszámítása.
    3. Az egyetem aláírásának ellenőrzése a publikus kulccsal.
    4. A Merkle-proof ellenőrzése a láncon tárolt gyökérrel szemben.
    """
    chain_ok = chain.is_chain_valid()
    print(f'  [1] Blokklánc sértetlensége:           {"OK" if chain_ok else "HIBA"}')

    doc_hash = cs.hash_document(credential)
    print(f'  [2] Újraszámolt dokumentum-hash:       {doc_hash.hex()[:32]}...')

    sig_ok = cs.verify_signature(public_key, doc_hash, signature)
    print(f'  [3] Digitális aláírás (Ed25519):       {"OK" if sig_ok else "HIBA"}')

    root_on_chain = chain.get_merkle_root(block_index)
    merkle_ok = verify_merkle_proof(doc_hash, proof, root_on_chain)
    print(f'  [4] Merkle-proof a #{block_index} blokk gyökeréhez: '
          f'{"OK" if merkle_ok else "HIBA"}')

    return chain_ok and sig_ok and merkle_ok


def print_result(valid: bool) -> None:
    print(f'\n  >>> EREDMÉNY: {"VALID  ✔" if valid else "INVALID ✘"}')


def main() -> None:
    # Windows konzolon is helyesen jelenjenek meg az ékezetek
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    # ------------------------------------------------------------------
    section('1. EGYETEM OLDAL – Kiállítás')
    # ------------------------------------------------------------------
    print('\n[Egyetem] Ed25519 kulcspár generálása...')
    private_key, public_key = cs.generate_key_pair()
    print(f'  Publikus kulcs: {cs.public_key_to_hex(public_key)}')

    print('\n[Egyetem] 5 minta-oklevél létrehozása, hash-elése és aláírása:')
    credentials = create_sample_credentials()
    doc_hashes: list[bytes] = []
    signatures: list[bytes] = []
    for i, cred in enumerate(credentials):
        doc_hash = cs.hash_document(cred)
        signature = cs.sign_hash(private_key, doc_hash)
        doc_hashes.append(doc_hash)
        signatures.append(signature)
        print(f'  #{i + 1} {cred["hallgato_neve"]:<13} | hash={doc_hash.hex()[:16]}... '
              f'| aláírás={signature.hex()[:16]}...')

    print('\n[Egyetem] Merkle-fa felépítése az oklevél-hash-ekből:')
    tree, merkle_root = build_merkle_tree(doc_hashes)
    print_merkle_tree(tree)
    print(f'  Merkle-gyökér: {merkle_root.hex()}')

    print('\n[Egyetem] Blokklánc inicializálása (genesis blokk) és a gyökér bebányászása:')
    chain = Blockchain(difficulty=3)
    block = chain.add_block(merkle_root)
    print(f'  A Merkle-gyökér a #{block.index} blokkba került. '
          f'Lánc hossza: {len(chain.chain)}, érvényes: {chain.is_chain_valid()}')

    # ------------------------------------------------------------------
    section('2. MUNKÁLTATÓ OLDAL – Sikeres ellenőrzés')
    # ------------------------------------------------------------------
    target_index = 2  # a 3. oklevél (0-tól indexelve)
    presented = credentials[target_index]
    presented_signature = signatures[target_index]
    print(f'\n[Munkáltató] Bemutatott oklevél (#{target_index + 1}):')
    for key, value in presented.items():
        print(f'  {key:<18}: {value}')

    print('\n[Munkáltató] Merkle-proof lekérése az egyetemtől:')
    proof = get_merkle_proof(target_index, doc_hashes)
    for level, (sibling, position) in enumerate(proof):
        print(f'  {level}. lépés: testvér={sibling.hex()[:16]}... ({position})')

    print('\n[Munkáltató] Ellenőrzés:')
    valid = verify_credential(presented, presented_signature, proof,
                              block.index, public_key, chain)
    print_result(valid)

    # ------------------------------------------------------------------
    section('3. HAMISÍTÁSI KÍSÉRLET – Sikertelen ellenőrzés')
    # ------------------------------------------------------------------
    forged = copy.deepcopy(presented)
    forged['hallgato_neve'] = 'Nagy Esztér'  # 1 karakter módosítva (e -> é)
    print(f'\n[Hamisító] Név módosítva: "{presented["hallgato_neve"]}" '
          f'-> "{forged["hallgato_neve"]}"')
    print('[Munkáltató] Ellenőrzés az eredeti aláírással és proof-fal:')
    print_result(verify_credential(forged, presented_signature, proof,
                                   block.index, public_key, chain))

    forged_grade = copy.deepcopy(presented)
    forged_grade['minosites'] = '9,95'  # 1 karakter módosítva (6 -> 9)
    print(f'\n[Hamisító] Minősítés módosítva: "{presented["minosites"]}" '
          f'-> "{forged_grade["minosites"]}"')
    print('[Munkáltató] Ellenőrzés:')
    print_result(verify_credential(forged_grade, presented_signature, proof,
                                   block.index, public_key, chain))

    print('\n[Hamisító] Saját kulccsal újraaláírja a módosított oklevelet:')
    fake_private_key, _ = cs.generate_key_pair()
    resigned = cs.sign_hash(fake_private_key, cs.hash_document(forged))
    print('[Munkáltató] Ellenőrzés az EGYETEM publikus kulcsával:')
    print_result(verify_credential(forged, resigned, proof,
                                   block.index, public_key, chain))

    # ------------------------------------------------------------------
    section('4. BÓNUSZ – A blokklánc manipulálása')
    # ------------------------------------------------------------------
    print('\n[Támadó] A #1 blokk Merkle-gyökerét a hamis oklevél hash-ére cseréli...')
    original_root = chain.chain[block.index].merkle_root
    chain.chain[block.index].merkle_root = cs.hash_document(forged).hex()
    print(f'  is_chain_valid(): {chain.is_chain_valid()}')
    print_result(verify_credential(forged, presented_signature, [],
                                   block.index, public_key, chain))
    chain.chain[block.index].merkle_root = original_root
    print(f'\n[Visszaállítás] Eredeti gyökér visszaírva, '
          f'is_chain_valid(): {chain.is_chain_valid()}')


if __name__ == '__main__':
    main()
