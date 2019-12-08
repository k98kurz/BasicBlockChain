import os.path
from blockchain import BasicBlockChain
from binascii import hexlify
import math

class SimpleSerializer():
    @classmethod
    def save_block_chain (cls, path, name, blockchain):
        if not isinstance(blockchain, BasicBlockChain):
            raise TypeError('blockchain argument must be of class BasicBlockChain')

        dir = os.path.join(path, name + '_chain')
        if not os.path.isdir(dir):
            os.mkdir(os.path.join('./', dir))

        # save genesis block
        data = cls.pack_genesis_block(blockchain[0]) if type(blockchain[0]) == type({}) else blockchain[0]
        open(os.path.join(dir, 'genesis'), 'wb').write(data)

        # save other blocks
        for i in range(1, len(blockchain)):
            data = cls.pack_block(blockchain[i]) if type(blockchain[i]) == type({}) else blockchain[i]
            open(os.path.join( dir, str(hexlify(blockchain[i]['hash'])) ), 'wb').write(data)

    @classmethod
    def load_block_chain (cls, path, name):
        dir = os.path.join(path, name + '_chain')
        chain = []
        files = [f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))]
        for i in range(0, len(files)):
            chain.append(open(os.path.join(dir, files[i]), 'rb').read())

        chain = cls.unpack_chain(chain)
        blockchain = BasicBlockChain.from_chain(chain)
        blockchain.sort()

        return blockchain

    '''
        First 32 bytes: block hash
        Second 64 bytes: block signature
        Third 32 bytes: signer's address/verification key
        Fourth 32 bytes: previous block hash
        Fifth 16 bytes: nonce
        Remainder: body
    '''
    @staticmethod
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
    @staticmethod
    def unpack_genesis_block (block_bytes):
        if len(block_bytes) != 208:
            raise ValueError('Genesis block must be exactly 208 bytes. Supplied block was ', len(block_bytes), ' bytes long.')
        hash = block_bytes[0:32]
        signature = block_bytes[32:96]
        address = block_bytes[96:128]
        node_address = block_bytes[128:160]
        nonce = block_bytes[160:176]
        public_key = block_bytes[176:208]
        return {'hash': hash, 'signature': signature, 'address': address, 'node_address': node_address, 'public_key': public_key, 'nonce': nonce}

    @classmethod
    def unpack_chain (cls, chain):
        unpacked = [cls.unpack_genesis_block(chain[0])]
        for i in range(1, len(chain)):
            unpacked.append(cls.unpack_block(chain[i]))
        return unpacked

    @staticmethod
    def pack_block (block):
        return block['hash'] + block['signature'] + block['address'] + block['previous_block'] + block['nonce'] + block['body']

    @staticmethod
    def pack_genesis_block (block):
        return block['hash'] + block['signature'] + block['address'] + block['node_address'] + block['nonce'] + block['public_key']
