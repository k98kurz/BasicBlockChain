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

        # compile index
        index = b''

        # save genesis block
        data = cls.pack_genesis_block(blockchain[0]) if type(blockchain[0]) == type({}) else blockchain[0]
        open(os.path.join(dir, 'genesis'), 'wb').write(data)

        # save other blocks
        for i in range(1, len(blockchain)):
            data = cls.pack_block(blockchain[i]) if type(blockchain[i]) == type({}) else blockchain[i]
            open(os.path.join( dir, str(hexlify(blockchain[i]['hash']), 'utf-8') + '_block' ), 'wb').write(data)
            index += SimpleSerializer.block_index_hex(blockchain[i]) + b'\n'

        # save index
        open(os.path.join(dir, 'index'), 'wb').write(index)

    @staticmethod
    def find_block_hash (path, name, height):
        # load index file
        dir = os.path.join(path, name + '_chain')
        data = open(os.path.join(dir, 'index'), 'rb').read()
        # trim trailing newline
        data = data[:-1] if data[-1:] == b'\n' else data

        # build index
        index = {'0': 'genesis'}
        listed = data.split(b'\n')
        for i in range(0, len(listed)):
            t = listed[i].split(b':')
            index[t[0]] = t[1]

        # return the block hash
        return index[bytes(str(height), 'utf-8')]

    @classmethod
    def load_block (cls, path, name, hash):
        dir = os.path.join(path, name + '_chain')
        block = open(os.path.join(dir, str(hash, 'utf-8') + '_block'), 'rb').read()
        return cls.unpack_block(block)

    @classmethod
    def load_block_chain (cls, path, name):
        dir = os.path.join(path, name + '_chain')
        chain = [open(os.path.join(dir, 'genesis'), 'rb').read()]
        files = [f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))]
        for i in range(0, len(files)):
            if files[i][-6:] == '_block':
                chain.append(open(os.path.join(dir, files[i]), 'rb').read())

        chain = cls.unpack_chain(chain)
        blockchain = BasicBlockChain.from_chain(chain)

        return blockchain

    '''
        First 1 byte: height_length
        Next n bytes: block_height
        Next 32 bytes: block hash
        Next 64 bytes: block signature
        Next 32 bytes: signer's address/verification key
        Next 32 bytes: previous block hash
        Next 16 bytes: nonce
        Remainder: body
    '''
    @classmethod
    def unpack_block (cls, block_bytes):
        if len(block_bytes) < 178:
            raise ValueError('Block must be at least 178 bytes. Supplied block was only ', len(block_bytes), ' bytes long.')

        # parse block_height
        height_length = int.from_bytes(block_bytes[0:1], byteorder='big')
        block_height = int.from_bytes(block_bytes[1:height_length+1], byteorder='big')

        # parse genesis block if this is one
        if block_height == 0:
            return cls.unpack_genesis_block(block_bytes)

        # trim block_bytes parse the rest
        block_bytes = block_bytes[height_length+1:]
        hash = block_bytes[0:32]
        signature = block_bytes[32:96]
        address = block_bytes[96:128]
        previous_block = block_bytes[128:160]
        nonce = block_bytes[160:176]
        body = block_bytes[176:]
        return {'block_height': block_height, 'hash': hash, 'signature': signature, 'address': address, 'previous_block': previous_block, 'nonce': nonce, 'body': body}

    '''
        First 2 bytes: '\x01\x00'
        Next 32 bytes: block hash
        Next 64 bytes: block signature
        Next 32 bytes: genesis address
        Next 32 bytes: address/signing key of node
        Next 16 bytes: nonce for meeting difficulty target.
        Final 32 bytes (body): public key of node for ECDHE
    '''
    @staticmethod
    def unpack_genesis_block (block_bytes):
        if len(block_bytes) != 210:
            raise ValueError('Genesis block must be exactly 210 bytes. Supplied block was ', len(block_bytes), ' bytes long.')
        block_bytes = block_bytes[2:] # discard block_height info which is always b'\x01\x00'
        hash = block_bytes[0:32]
        signature = block_bytes[32:96]
        address = block_bytes[96:128]
        node_address = block_bytes[128:160]
        nonce = block_bytes[160:176]
        public_key = block_bytes[176:208]
        return {'block_height': 0, 'hash': hash, 'signature': signature, 'address': address, 'node_address': node_address, 'public_key': public_key, 'nonce': nonce}

    @classmethod
    def unpack_chain (cls, chain):
        unpacked = [cls.unpack_genesis_block(chain[0])]
        for i in range(1, len(chain)):
            unpacked.append(cls.unpack_block(chain[i]))
        return unpacked

    @staticmethod
    def block_index (block):
        height_length = math.ceil(math.log(block['block_height'] + 2) / math.log(2) / 8) # number of bytes needed for block_height
        height = block['block_height'].to_bytes(height_length, byteorder='big') # convert to bytes
        height_length = height_length.to_bytes(1, byteorder='big') # convert to bytes
        return height_length + height + block['hash']

    @staticmethod
    def block_index_hex (block):
        return bytes(str(block['block_height']), 'utf-8') + b':' + hexlify(block['hash'])

    @staticmethod
    def pack_block (block):
        return SimpleSerializer.block_index(block) + block['signature'] + block['address'] + block['previous_block'] + block['nonce'] + block['body']

    @staticmethod
    def pack_genesis_block (block):
        return b'\x01\x00' + block['hash'] + block['signature'] + block['address'] + block['node_address'] + block['nonce'] + block['public_key']

    @staticmethod
    def print_block (block):
        print('{')
        print('\tblock_height: ', block['block_height'])
        print('\thash: ', hexlify(block['hash']))
        print('\tsignature: ', hexlify(block['signature']))
        print('\taddress: ', hexlify(block['address']))
        print('\tnonce: ', hexlify(block['nonce']))

        if block['block_height'] == 0:
            print('\tpublic_key: ', hexlify(block['public_key']))
            print('\tnode_address: ', hexlify(block['node_address']))
        else:
            print('\tprevious_block: ', hexlify(block['previous_block']))
            print('\tbody: ', block['body'])

        print('}')
