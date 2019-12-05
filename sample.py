import blockchain as bc
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
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

# get genesis file from storage or create it
if os.path.isfile('genesis.seed'):
    genesis = {'seed': open('genesis.seed', 'rb').read()}
else:
    genesis = {'seed': PrivateKey.generate()._private_key}
    open('genesis.seed', 'wb').write(genesis['seed'])

# derive some values
genesis['signing_key'] = SigningKey(genesis['seed'])
genesis['address'] = genesis['signing_key'].verify_key._key


# create some nodes
if os.path.isfile('node1.seed'):
    node1 = bc.setup_node(open('node1.seed', 'rb').read())
else:
    node1 = bc.setup_node(PrivateKey.generate()._private_key)
    open('node1.seed', 'wb').write(node1['seed'])

if os.path.isfile('node2.seed'):
    node2 = bc.setup_node(open('node2.seed', 'rb').read())
else:
    node2 = bc.setup_node(PrivateKey.generate()._private_key)
    open('node2.seed', 'wb').write(node2['seed'])


# create genesis blocks
node1['blockchain'] = [ bc.create_genesis_block(genesis['signing_key'], node1['verify_key']._key, node1['public_key']._public_key) ]
node2['blockchain'] = [ bc.create_genesis_block(genesis['signing_key'], node2['verify_key']._key, node2['public_key']._public_key) ]

# verify genesis blocks
if bc.verify_genesis_block(node1['blockchain'][0], genesis['address']):
    print('Node 1 genesis block verified.')
else:
    print('Node 1 genesis block failed verification.')

if bc.verify_genesis_block(node2['blockchain'][0], genesis['address']):
    print('Node 2 genesis block verified.')
else:
    print('Node 2 genesis block failed verification.')


# add a block to each
node1['blockchain'].append(bc.create_block(node1['signing_key'], node1['blockchain'][0], b'Hail Julius Caesar or something.'))
node2['blockchain'].append(bc.create_block(node2['signing_key'], node2['blockchain'][0], b'Knives are cool tools of Roman politics.'))

# verify blockchains
if bc.verify_chain(node1['blockchain'], genesis['address']):
    print('Node 1 block chain verified.')
else:
    print('Node 1 block chain failed verification.')

if bc.verify_chain(node2['blockchain'], genesis['address']):
    print('Node 2 block chain verified.')
else:
    print('Node 2 block chain failed verification.')


# write blockchains to file
# NB in application, the file name should be the node address in b64 or hex
bc.save_block_chain('.', 'node1', node1['blockchain'])
bc.save_block_chain('.', 'node2', node2['blockchain'])

# load blockchain from file
blockchain = bc.load_block_chain('.', 'node1')

# verify
if bc.verify_chain(blockchain, genesis['address']):
    print('Verified block chain retrieved from file system.')
else:
    print('Failed to verify block chain retrieved from file system.')


# hostile takeover
blockchain.append(bc.create_block(node2['signing_key'], node1['blockchain'][1], b'Hostile takeover of node1 chain by node2.'))

# verify
if bc.verify_chain(blockchain, genesis['address']):
    print('Hostile takeover of node1 chain by node2 not detected.')
else:
    print('Node2 gtfo of node1\'s blockchain')
