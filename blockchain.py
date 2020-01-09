from nacl.encoding import RawEncoder
from nacl.hash import sha256
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PublicKey, PrivateKey, Box, SealedBox
import nacl
from operator import itemgetter

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

class BasicBlockChain(list):
    def __init__ (self):
        self.difficulty = 1
        self.difficulty_mode = 0
        self.address = b''
        self.public_key = b''

    def sort (self, key=None, reverse=False):
        if key == None:
            super().sort(key=itemgetter('block_height'), reverse=reverse)
        else:
            super().sort(key=key, reverse=reverse)

    # assuming we have the node's seed but not the genesis key
    @classmethod
    def from_seed (cls, seed, difficulty=1, difficulty_mode=0):
        blockchain = cls()
        blockchain.difficulty = difficulty
        blockchain.difficulty_mode = difficulty_mode
        blockchain.seed = seed
        blockchain.signing_key = SigningKey(seed)
        blockchain.verify_key = blockchain.signing_key.verify_key
        blockchain.address = blockchain.verify_key._key
        blockchain.private_key = blockchain.signing_key.to_curve25519_private_key()
        blockchain.public_key = blockchain.verify_key.to_curve25519_public_key()

        return blockchain

    @classmethod
    def from_chain (cls, chain, difficulty=1, difficulty_mode=0):
        blockchain = cls()
        blockchain.difficulty = difficulty
        blockchain.difficulty_mode = difficulty_mode
        for i in range(0, len(chain)):
            blockchain.append(chain[i])

        blockchain.sort()
        blockchain.address = blockchain[0]['node_address']
        blockchain.public_key = PublicKey(blockchain[0]['public_key'])

        return blockchain

    # assuming we have the genesis_key and are making a fresh node
    @classmethod
    def from_genesis_key (cls, genesis_key, difficulty=1, difficulty_mode=0):
        blockchain = cls.from_seed(PrivateKey.generate()._private_key)
        blockchain.difficulty = difficulty
        blockchain.difficulty_mode = difficulty_mode
        blockchain.append(cls.create_genesis_block(genesis_key, blockchain.address, blockchain.public_key, difficulty, difficulty_mode))
        blockchain.genesis_address = blockchain[0]['address']
        return blockchain

    # assuming we have the genesis block (dict) for a node and nothing else; e.g. for verification purposes
    @classmethod
    def from_genesis_block (cls, genesis_block, difficulty=1, difficulty_mode=0):
        blockchain = cls()
        blockchain.difficulty = difficulty
        blockchain.difficulty_mode = difficulty_mode
        blockchain.append(genesis_block)
        blockchain.public_key = genesis_block['public_key']
        blockchain.address = genesis_block['node_address']
        return blockchain

    def add_block (self, data):
        new_block = self.create_block(self.signing_key, self[-1], data, self.difficulty, self.difficulty_mode)
        self.append(new_block)

    @staticmethod
    def meets_difficulty (signature, difficulty=1, mode=0):
        hash = sha256(signature, encoder=RawEncoder)

        if mode == 0:
            # determines if the block hash has enough preceding null bytes
            for i in range(0, difficulty):
                if hash[i] > 0:
                    return False
        if mode == 1:
            # determins if the block has enough repeating digits at end
            for i in range(1, difficulty+1):
                if hash[-i] != hash[-1-i]:
                    return False

        return True

    '''
        Block hash: 32 bytes
        Block signature: 64 bytes
        Signer's address/verification key: 32 bytes
        Previous block hash: 32 bytes
        Nonce: 16 bytes
        Body: variable length

        Parameters: signing_key SigningKey, previous_block dict, body bytes(*), difficulty int
    '''
    @staticmethod
    def create_block (signing_key, previous_block, body, difficulty=1, difficulty_mode=0):
        signing_key = SigningKey(signing_key) if type(signing_key) == type('s') or type(signing_key) == type(b's') else signing_key
        nonce = nacl.utils.random(16)
        signature = signing_key.sign(previous_block['hash'] + nonce + body)

        # mild PoW
        while not BasicBlockChain.meets_difficulty(signature.signature, difficulty, difficulty_mode):
            nonce = nacl.utils.random(16)
            signature = signing_key.sign(previous_block['hash'] + nonce + body)

        hash = sha256(signature.signature, encoder=RawEncoder)

        # return the block
        return {
            'block_height': previous_block['block_height'] + 1,
            'hash': hash,
            'signature': signature.signature,
            'address': signing_key.verify_key._key,
            'previous_block': previous_block['hash'],
            'nonce': nonce,
            'body': body
        }

    '''
        Block hash: 32 bytes
        Block signature: 64 bytes
        Genesis address: 32 bytes
        Address/verification key of node: 32 bytes
        Nonce: 16 bytes
        Public key of node for ECDHE: 32 bytes

        Parameters: genesis_key SigningKey, node_address bytes(64), public_key bytes(32), difficulty int(0<x<5)
    '''
    @staticmethod
    def create_genesis_block (genesis_key, node_address, public_key, difficulty=1, difficulty_mode=0):
        nonce = nacl.utils.random(16)
        public_key = public_key._public_key if isinstance(public_key, nacl.public.PublicKey) else public_key
        signature = genesis_key.sign(node_address + nonce + public_key)
        difficulty = difficulty if difficulty < 5 and difficulty > 0 else 1

        # mild PoW
        while not BasicBlockChain.meets_difficulty(signature.signature, difficulty, difficulty_mode):
            nonce = nacl.utils.random(16)
            signature = genesis_key.sign(node_address + nonce + public_key)

        hash = sha256(signature.signature, encoder=RawEncoder)

        # return the genesis block
        return {
            'block_height': 0,
            'hash': hash,
            'signature': signature.signature,
            'address': genesis_key.verify_key._key,
            'node_address': node_address,
            'nonce': nonce,
            'public_key': public_key
        }

    # returns True or False
    @classmethod
    def verify_block (cls, block, difficulty=1, difficulty_mode=0):
        try:
            # reject if it does not meet the required difficulty
            if not cls.meets_difficulty(block['signature'], difficulty, difficulty_mode):
                return False
            # then verify the signature
            verify_key = VerifyKey(block['address']) if type(block['address']) == type('s') or type(block['address']) == type(b's') else block['address']
            verify_key.verify(block['previous_block'] + block['nonce'] + block['body'], block['signature'])
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except KeyError:
            return False

    # returns True or False
    @classmethod
    def verify_genesis_block (cls, block, genesis_address, difficulty=1, difficulty_mode=0):
        try:
            # reject if it is not signed by the genesis address
            if block['address'] != genesis_address:
                return False
            # reject if it does not meet the required difficulty
            if not cls.meets_difficulty(block['signature'], difficulty, difficulty_mode):
                return False
            # then verify the signature
            verify_key = VerifyKey(block['address']) if type(block['address']) == type('s') or type(block['address']) == type(b's') else block['address']
            verify_key.verify(block['node_address'] + block['nonce'] + block['public_key'], block['signature'])
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except KeyError:
            return False

    # returns True or False
    @classmethod
    def verify_chain (cls, blockchain, genesis_address, difficulty=1, difficulty_mode=0):
        # verify other blocks
        for i in range(0, len(blockchain)):
            # throw it out if its genesis block is invalid
            if i == 0 and not cls.verify_genesis_block(blockchain[0], genesis_address, difficulty_mode):
                return False

            # throw it out if any non-genesis block has a corrupt or fraudulent signature
            if i > 0 and not cls.verify_block(blockchain[i], difficulty, difficulty_mode):
                return False

            # throw it out if the current block does not reference previous block
            if i > 0 and blockchain[i]['previous_block'] != blockchain[i-1]['hash']:
                return False

            # throw it out if the previous, non-genesis block's address is not the same as the current one
            if i > 1 and blockchain[i]['address'] != blockchain[i-1]['address']:
                return False

        return True

    def encrypt (self, public_key, plaintext):
        box = Box(self.private_key, public_key)
        return box.encrypt(plaintext)

    def decrypt (self, public_key, ciphertext):
        box = Box(self.private_key, public_key)
        return box.decrypt(ciphertext)

    def encrypt_sealed (self, public_key, plaintext):
        box = SealedBox(public_key)
        return box.encrypt(plaintext)

    def decrypt_sealed (self, ciphertext):
        box = SealedBox(self.private_key)
        return box.decrypt(ciphertext)
