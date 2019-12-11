from blockchain import BasicBlockChain
from simpleserializer import SimpleSerializer
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from nacl.hash import sha256
from nacl.encoding import RawEncoder
import nacl.utils
import os.path
from binascii import hexlify

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

# set up directories
if not os.path.isdir('_chains'):
    os.mkdir(os.path.join('.', '_chains'))
if not os.path.isdir('_seeds'):
    os.mkdir(os.path.join('.', '_seeds'))

# get genesis seed from storage or create it
if os.path.isfile('_seeds/genesis'):
    genesis = BasicBlockChain.from_seed(open('_seeds/genesis', 'rb').read())
    print('loaded _seeds/genesis from file')
else:
    genesis = BasicBlockChain.from_seed(nacl.utils.random(32))
    open('_seeds/genesis', 'wb').write(genesis.seed)
    print('generated _seeds/genesis and wrote to file')


# create some nodes
if os.path.isfile('_seeds/node1'):
    node1 = BasicBlockChain.from_seed(open('_seeds/node1', 'rb').read())
    print('loaded _seeds/node1 from file')
else:
    node1 = BasicBlockChain.from_seed(nacl.utils.random(32))
    open('_seeds/node1', 'wb').write(node1.seed)
    print('generated _seeds/node1 and wrote to file')

if os.path.isfile('_seeds/node2'):
    node2 = BasicBlockChain.from_seed(open('_seeds/node2', 'rb').read())
    print('loaded _seeds/node2 from file')
else:
    node2 = BasicBlockChain.from_seed(nacl.utils.random(32))
    open('_seeds/node2', 'wb').write(node2.seed)
    print('generated _seeds/node2 and wrote to file')

# load node1 from file system if present
try:
    node1.extend( SimpleSerializer.load_block_chain('_chains', hexlify(node1.address)) )
    print('node1 blockchain loaded from files')

# create blocks if nothing was found
except FileNotFoundError:
    # create genesis block
    node1.append( BasicBlockChain.create_genesis_block(genesis.signing_key, node1.address, node1.public_key) )

    # add a few blocks to each
    node1.add_block(b'Hail Julius Caesar or something.')
    node1.add_block(b'Traitors should be fed to the Teutons!')

    # make node1 chain a bit longer
    for i in range(3, 12):
        node1.add_block(b'Test block ' + bytes(str(i), 'utf-8'))

    print('generated node1 blockchain')

# load node2 from file system if present
try:
    node2.extend( SimpleSerializer.load_block_chain('_chains', hexlify(node2.address)) )
    print('node2 blockchain loaded from files')

# create blocks if nothing was found
except FileNotFoundError:
    node2.append( BasicBlockChain.create_genesis_block(genesis.signing_key, node2.address, node2.public_key) )
    node2.add_block(b'Knives are cool tools of Roman politics.')
    node2.add_block(b'Caesar was the real traitor!')
    print('generated node2 blockchain')


# verify genesis blocks
if BasicBlockChain.verify_genesis_block(node1[0], genesis.address):
    print('Node 1 genesis block verified.')
else:
    print('Node 1 genesis block failed verification.')

if BasicBlockChain.verify_genesis_block(node2[0], genesis.address):
    print('Node 2 genesis block verified.')
else:
    print('Node 2 genesis block failed verification.')

# verify blockchains
if BasicBlockChain.verify_chain(node1, genesis.address):
    print('Node 1 block chain verified.')
else:
    print('Node 1 block chain failed verification.')

if BasicBlockChain.verify_chain(node2, genesis.address):
    print('Node 2 block chain verified.')
else:
    print('Node 2 block chain failed verification.')


# write blockchains to file system
# NB in application, you may want to use a database system instead
SimpleSerializer.save_block_chain('_chains', hexlify(node1.address), node1)
SimpleSerializer.save_block_chain('_chains', hexlify(node2.address), node2)

# load blockchain from file
blockchain = SimpleSerializer.load_block_chain('_chains', hexlify(node1.address))

# verify
if BasicBlockChain.verify_chain(blockchain, genesis.address):
    print('Verified block chain retrieved from file system.')
else:
    print('Failed to verify block chain retrieved from file system.')


# hostile takeover
blockchain.append(BasicBlockChain.create_block(node2.signing_key, node1[1], b'Hostile takeover of node1 chain by node2.'))

# verify
if BasicBlockChain.verify_chain(blockchain, genesis.address):
    print('Hostile takeover of node1 chain by node2 not detected.')
else:
    print('Node2 gtfo of node1\'s blockchain')


# print out the contents of a block chain
print('\nnode1 block chain:')
SimpleSerializer.print_block_chain(node1)

# index stuff
hash = SimpleSerializer.find_block_hash('_chains', hexlify(node1.address), 3)
block = SimpleSerializer.load_block('_chains', hexlify(node1.address), hash)
print('\nhash of node1 block height 3 from file system: ', hash)
print('block from file system:')
SimpleSerializer.print_block(block)

# ecdhe encrypt: node1 -> node2
print('\n***ECDHE***')
message = b'Meet in the bathroom.'
ciphertext = node1.encrypt(node2.public_key, message)
print('\nnode1.public_key: ', hexlify(node1.public_key._public_key))
print('message: ', message)
print('encrypted: ', hexlify(ciphertext))

# ecdhe decrypt
plaintext = node2.decrypt(node1.public_key, ciphertext)
print('decrypted: ', plaintext)

# ephemeral ecdhe encrypt
message = b'No way! It\'s a trap!'
ciphertext = node2.encrypt_sealed(node1.public_key, message)
print('\nmessage: ', message)
print('sealed ciphertext: ', hexlify(ciphertext))

# ephemeral ecdhe decrypt
plaintext = node1.decrypt_sealed(ciphertext)
print('unsealed plaintext: ', plaintext)
