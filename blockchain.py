from nacl.encoding import RawEncoder
from nacl.hash import sha256
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey
import nacl
import os.path

'''
    Copyright (c) 2019 Jonathan Voss

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
    SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
    OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
    CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''


# determines if the block hash has enough preceding null bytes
def meets_difficulty (signature, difficulty=1):
    hash = sha256(signature, encoder=RawEncoder)
    for i in range(0, difficulty):
        if hash[i] > 0:
            return False

    return True

'''
    First 32 bytes: block hash
    Second 64 bytes: block signature
    Third 32 bytes: signer's address/verification key
    Fourth 32 bytes: previous block hash
    Fifth 16 bytes: nonce for meeting difficulty
    Remainder: body

    Parameters: signing_key SigningKey, previous_block bytes(64), body bytes(*), difficulty int(0<x<5)
'''
def create_block (signing_key, previous_block, body, difficulty=1):
    signing_key = SigningKey(signing_key) if type(signing_key) == type('s') or type(signing_key) == type(b's') else signing_key
    previous_block = unpack_block(previous_block) if type(previous_block) == type('s') or type(previous_block) == type(b's') else previous_block
    nonce = nacl.utils.random(16)
    signature = signing_key.sign(previous_block['hash'] + nonce + body)

    # mild PoW
    while not meets_difficulty(signature.signature, difficulty):
        nonce = nacl.utils.random(16)
        signature = signing_key.sign(previous_block['hash'] + nonce + body)

    hash = sha256(signature, encoder=RawEncoder)

    # return the block
    return hash + signature.signature + signing_key.verify_key._key + previous_block['hash'] + nonce + body

'''
    First 32 bytes: block hash
    Second 64 bytes: block signature
    Third 32 bytes: genesis address
    Fourth 32 bytes: address/verification key of node
    Fifth 16 bytes: nonce for meeting difficulty target.
    Final 32 bytes (body): public key of node for ECDHE

    Parameters: genesis_key SigningKey, node_address bytes(64), public_key bytes(32), difficulty int(0<x<5)
'''
def create_genesis_block (genesis_key, node_address, public_key, difficulty=1):
    nonce = nacl.utils.random(16)
    signature = genesis_key.sign(node_address + nonce + public_key)
    difficulty = difficulty if difficulty < 5 and difficulty > 0 else 1

    # mild PoW
    while not meets_difficulty(signature.signature, difficulty):
        nonce = nacl.utils.random(16)
        signature = genesis_key.sign(node_address + nonce + public_key)

    hash = sha256(signature, encoder=RawEncoder)

    # return the genesis block
    return hash + signature.signature + genesis_key.verify_key._key + node_address + nonce + public_key

'''
    First 32 bytes: block hash
    Second 64 bytes: block signature
    Third 32 bytes: signer's address/verification key
    Fourth 32 bytes: previous block hash
    Fifth 16 bytes: nonce
    Remainder: body
'''
def unpack_block (block_bytes):
    if len(block_bytes) < 176:
        raise ValueError('Block must be at least 176 bytes. Supplied block was only ', len(block_bytes), ' bytes long.')
    hash = block_bytes[0:32]
    signature = block_bytes[32:96]
    address = block_bytes[96:128]
    previous_block = block_bytes[128:160]
    nonce = block_bytes[160:176]
    body = block_bytes[176:]
    return {'hash': hash, 'signature': signature, 'address': address, 'previous_block': previous_block, 'nonce': nonce, 'body': body}

'''
    First 32 bytes: block hash
    Second 64 bytes: block signature
    Third 32 bytes: genesis address
    Fourth 32 bytes: address/signing key of node
    Fifth 16 bytes: nonce for meeting difficulty target.
    Final 32 bytes (body): public key of node for ECDHE
'''
def unpack_genesis_block (block_bytes):
    if len(block_bytes) != 208:
        raise ValueError('Genesis block must be exactly 208 bytes. Supplied block was only ', len(block_bytes), ' bytes long.')
    hash = block_bytes[0:32]
    signature = block_bytes[32:96]
    address = block_bytes[96:128]
    node_address = block_bytes[128:160]
    nonce = block_bytes[160:176]
    public_key = block_bytes[176:208]
    return {'hash': hash, 'signature': signature, 'address': address, 'node_address': node_address, 'public_key': public_key, 'nonce': nonce}

def unpack_chain (chain):
    unpacked = [unpack_genesis_block(chain[0])]
    for i in range(1, len(chain)):
        unpacked.append(unpack_block(chain[i]))
    return unpacked

def pack_block (block):
    return block['hash'] + block['signature'] + block['address'] + block['previous_block'] + block['nonce'] + block['body']

def pack_genesis_block (block):
    return block['hash'] + block['signature'] + block['address'] + block['node_address'] + block['nonce'] + block['public_key']

def verify_block (block, difficulty=1):
    try:
        # unpack bytes into a dict
        block = unpack_block(block) if type(block) == type('s') or type(block) == type(b's') else block
        # reject if it does not meet the required difficulty
        if not meets_difficulty(block['signature'], difficulty):
            return False
        # then verify the signature
        verify_key = VerifyKey(block['address']) if type(block['address']) == type('s') or type(block['address']) == type(b's') else block['address']
        verify_key.verify(block['previous_block'] + block['nonce'] + block['body'], block['signature'])
        return True
    except nacl.exceptions.BadSignatureError:
        return False
    except ValueError:
        return False

def verify_genesis_block (block, genesis_address, difficulty=1):
    try:
        # unpack bytes into a dict
        block = unpack_genesis_block(block) if type(block) == type('s') or type(block) == type(b's') else block
        # reject if it is not signed by the genesis address
        if block['address'] != genesis_address:
            return False
        # reject if it does not meet the required difficulty
        if not meets_difficulty(block['signature'], difficulty):
            return False
        # then verify the signature
        verify_key = VerifyKey(block['address']) if type(block['address']) == type('s') or type(block['address']) == type(b's') else block['address']
        verify_key.verify(block['node_address'] + block['nonce'] + block['public_key'], block['signature'])
        return True
    except nacl.exceptions.BadSignatureError:
        return False
    except ValueError:
        return False

def verify_chain (blocks, genesis_address, difficulty=1):
    unpacked = []

    # verify other blocks
    for i in range(0, len(blocks)):
        if i == 0:
            unpacked.append(unpack_genesis_block(blocks[i]) if type(blocks[i]) == type('s') or type(blocks[i]) == type(b's') else blocks[i])
        else:
            unpacked.append(unpack_block(blocks[i]) if type(blocks[i]) == type('s') or type(blocks[i]) == type(b's') else blocks[i])

        # throw it out if its genesis block is invalid
        if i == 0 and not verify_genesis_block(unpacked[0], genesis_address):
            return False

        # throw it out if any non-genesis block has a corrupt or fraudulent signature
        if i > 0 and not verify_block(unpacked[i], difficulty):
            return False

        # throw it out if the current block does not reference previous block
        if i > 0 and unpacked[i]['previous_block'] != unpacked[i-1]['hash']:
            return False

        # throw it out if the previous, non-genesis block's address is not the same as the current one
        if i > 1 and unpacked[i]['address'] != unpacked[i-1]['address']:
            return False

    return True

def save_block_chain (path, name, chain):
    dir = os.path.join(path, name + '_chain')
    if not os.path.isdir(dir):
        os.mkdir(os.path.join('./', dir))

    # save genesis block
    data = pack_genesis_block(chain[0]) if type(chain[0]) == type([]) else chain[0]
    open(os.path.join(dir, '0_block'), 'wb').write(data)

    # save other blocks
    for i in range(1, len(chain)):
        data = pack_block(chain[i]) if type(chain[i]) == type([]) else chain[i]
        open(os.path.join(dir, str(i) + '_block'), 'wb').write(data)

def load_block_chain (path, name):
    dir = os.path.join(path, name + '_chain')
    chain = []
    files = [f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))]
    for i in range(0, len(files)):
        chain.append(open(os.path.join(dir, files[i]), 'rb').read())
    chain = unpack_chain(chain)
    return chain

def setup_node (seed):
    node = {'signing_key': SigningKey(seed), 'seed': seed}
    node['verify_key'] = node['signing_key'].verify_key
    node['address'] = node['verify_key']._key
    node['private_key'] = node['signing_key'].to_curve25519_private_key()
    node['public_key'] = node['verify_key'].to_curve25519_public_key()
    return node
