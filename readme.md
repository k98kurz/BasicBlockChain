# About

This is a basic, simple crypto system in which all nodes share a genesis
address but each node has its own block chain. Thus, there is no consensus
mechanism/protocol -- that must be handled by the application/network.

This system uses elliptic curves and sha256 to guarantee only three things:
- Every block within a chain was created by the address authorized in the genesis block.
- Every block will meet a customizable PoW difficulty threshold to avoid spam.
- Each genesis block will include that node's public key for ECDHE (encrypted communications).

As long as your protocol allows it, there can be any number of subnetworks using
different genesis addresses. Trust within a network largely depends upon the
secrecy of the genesis key and the trustworthiness of its owner. For embedded
devices, you can accomplish this by including the genesis seed in a file that
is deleted after generating the genesis block on the first run or by having the
device make an API request during the first run (which must be on a secure network)
supplying its node address and receiving a genesis block.

Block chains are saved/loaded with a rudimentary file IO system as this was
originally designed for use in small devices. I recommend writing custom
serializer/deserializer and save/load functions for prod applications.

There is no version control in the block headers. If necessary, add it to the
body and implement version checking in the application. Or just fork the library.

Likewise, there are no timestamps in the block headers. This is because each node
has its own block chain, and the system was envisioned for use with embedded
devices. If necessary, add timestamps to the body or fork the library.


# Primitives

This uses the PyNaCL library for Ed25519 signatures and sha256 hashes. Eventually,
I will add some functions for ECDHE using Curve25519 for messaging between nodes,
hence the inclusion of Curve25519 public keys in genesis blocks.

There are two reasons for using sha256 hashes instead of the sha512 signatures:
1. When a block references another block on another block chain, it will be a total
of 64 bytes: 32 for the address and 32 for the block hash. This saves some bandwidth
in low-bandwidth networks for embedded devices, e.g. LoRa.
2. It is easier on human eyes to use 256 bit hashes, and this scheme allows a
theoretical maximum of 2^(256-difficulty) possible hashes per block chain/node,
which is sufficient for any task.


# Setup / Usage

1. Install the `python3-nacl` library.
2. Put `blockchain.py` somewhere in the project files.
3. `from [path/to/blockchain] import BasicBlockChain`

See `sample.py` for some sample code.


# Methods

## BasicBlockChain

Inherits from list and has these definitions:

- Constructors
    1. `__init__`
    2. from_seed
    3. from_chain
    4. from_genesis_key
    5. from_genesis_block

- Non-constructor class methods
    1. verify_block
    2. verify_genesis_block
    3. verify_chain

- Instance methods
    1. add_block
    2. encrypt
    3. decrypt
    4. encrypt_sealed
    5. decrypt_sealed
    6. sort (override)

- Static methods
    1. meets_difficulty
    2. create_block
    3. create_genesis_block

### `__init__` ()

Returns BasicBlockChain with following instance attributes:
- `difficulty`: 1
- `address`: empty byte string
- `public_key`: empty byte string

### @classmethod from_seed (seed)

Parameter:
- `seed`: 32 bytes to seed the CSPRNG

Returns a BasicBlockChain with the following instance attributes:

- `seed`: bytes
- `signing_key`: `nacl.signing.SigningKey`
- `verify_key`: `nacl.signing.VerifyKey`
- `address`: byte string of verify_key
- `private_key`: `nacl.public.PrivateKey`
- `public_key`: `nacl.public.PublicKey`

The SigningKey is derived from the seed, and all other values are derived from it.

### @classmethod from_chain (chain)

Parameter:
- `chain`: list

Returns a BasicBlockChain with the contents of `chain` and the following instance attributes:

- `address`: byte string
- `public_key`: `nacl.public.PublicKey`

### @classmethod from_genesis_key (genesis_key)

Parameter:
- `genesis_key`: `nacl.signing.SigningKey`

Generates a seed and returns result of BasicBlockChain.from_seed with a genesis block and `genesis_address` attribute.

### @classmethod from_genesis_block (genesis_block)

Parameter:
- `genesis_block`: dict of form:
    - `block_height`: int
    - `hash`: 32 byte string
    - `signature`: 64 byte string
    - `address`: 32 byte string genesis address
    - `node_address`: 32 byte string
    - `nonce`: 16 bytes
    - `public_key`: `nacl.public.PublicKey`

Returns a BasicBlockChain with the genesis_block appended and the following instance attributes:
- `public_key`: nacl.public.PublicKey
- `address`: byte string of node address

### add_block (data)

Parameter:
- `data`: bytes

Calls `create_block` and appends the result to `self`. Returns `None`.

### @staticmethod meets_difficulty (signature, difficulty=1)

Parameters:
- `signature`: byte string of result from `nacl.signing.SigningKey.sign()`
- `difficulty=1`: int, minimum number of preceding zeroes in block hash

Returns boolean:
- `True` if the sha256 of the signature has difficulty number of preceding zeroes
- `False` otherwise

(For brevity, I will omit explanation of difficulty=1 hereinafter.)

### @staticmethod create_block (signing_key, previous_block, body, difficulty=1)

Parameters:
- signing_key: `nacl.signing.SigningKey`
- previous_block: byte string or dict
- body: byte string

Returns dict of this form:
```
{
    block_height: int,
    hash: 32 bytes,
    signature: 64 bytes,
    address: 32 bytes,
    previous_block: 32 bytes,
    nonce: 16 bytes,
    body: variable length byte string
}
```

### @staticmethod create_genesis_block (genesis_key, node_address, public_key, difficulty=1)

Parameters:
- `genesis_key`: `nacl.signing.SigningKey`
- `node_address`: `_key` element from `nacl.signing.VerifyKey`, e.g. `node.verify_key._key`
- `public_key`: `_public_key` element from `nacl.public.PublicKey`, e.g. `node.public_key._public_key`

Returns a dict of this form:
```
{
    block_height: 0,
    hash: 32 bytes,
    signature: 64 bytes,
    address: 32 bytes (genesis_address),
    node_address: 32 bytes,
    nonce: 16 bytes,
    public_key: 32 bytes
}
```

### @classmethod verify_block (block, difficulty=1)

Parameters:
- `block`: dict (see `create_block` above)

Returns a boolean:
- `False` if block hash does not meet difficulty level
- `False` if block signature fails verification
- `False` if the block is malformed/missing data
- `True` if all checks are passed

### @classmethod verify_genesis_block (block, genesis_address, difficulty=1)

Parameters:
- `block`: dict
- `genesis_address`: byte string

Returns a boolean:
- `False` if block address is not the genesis_address
- `False` if block hash does not meet difficulty level
- `False` if block signature fails verification
- `False` if the block is malformed/missing data
- `True` if all checks are passed

### @classmethod verify_chain (blocks, genesis_address, difficulty=1)

Parameters:
- `blocks`: list of dicts
- `genesis_address`: byte string of genesis address

Returns a boolean:
- `False` if `verify_genesis_block` fails on first block
- `False` if `verify_block` fails on any other block
- `False` if any non-genesis block does not reference previous block
- `True` if all checks are passed

### encrypt (public_key, plaintext)

Parameters:
- `public_key`: `nacl.public.PublicKey`
- `plaintext`: bytes

Does ECDHE and returns the ciphertext.

### decrypt (public_key, ciphertext)

Parameters:
- `public_key`: `nacl.public.PublicKey`
- `ciphertext`: bytes

Does ECDHE and returns the plaintext.

### encrypt_sealed (public_key, plaintext)

Parameters:
- `public_key`: `nacl.public.PublicKey`
- `plaintext`: bytes

Does ephemeral ECDHE and returns the ciphertext.

### decrypt_sealed (ciphertext)

Parameter:
- `ciphertext`: bytes

Does ephemeral ECDHA and returns the plaintext.



## SimpleSerializer

Meant to be used from static context. Has these definitions:

- Non-constructor class methods:
    1. save_block_chain
    2. find_block_hash
    3. load_block
    4. load_genesis_block
    5. load_block_chain
    6. unpack_block
    7. unpack_chain

- Static methods:
    1. unpack_genesis_block
    2. block_index
    3. block_index_hex
    4. pack_block
    5. pack_genesis_block
    6. print_block
    7. print_block_chain


### @classmethod save_block_chain (path, name, chain)

Parameters:
- `path`: string (should be namespaced with genesis_address if allowing subnetworks)
- `name`: string (should be hex or b64 of node address)
- `chain`: list of packed (bytes) or unpacked (dict) blocks

Saves blocks to flat files. Creates path/name directory if necessary. No return value.

### @classmethod find_block_hash (path, name, height)

Parameters:
- `path`: string
- `name`: string
- `height`: int

Parses the (human-readable) `index` file for the block chain and returns the hex hash of the requested block height.

### @classmethod load_block (path, name, hash)

Parameters:
- `path`: string
- `name`: string
- `hash`: string

Reads the block file and returns `cls.unpack_block(block)`.

### @classmethod load_genesis_block (path, name)

Parameters:
- `path`: string
- `name`: string

Reads the genesis file and returns `cls.unpack_genesis_block(block)`.

### @classmethod load_block_chain (path, name)

Parameters:
- `path`: string (should be namespaced with genesis_address if allowing subnetworks)
- `name`: string (should be hex or b64 of node address)

Loads a block chain from `path/name`. Returns a `BasicBlockChain` of unpacked blocks.

### @classmethod unpack_block (block_bytes)

Parameter:
- `block_bytes`: byte string (at least 178 bytes long)

Returns dict of same form as `create_block`.

Raises `ValueError` if len(block_bytes) < 178.

### @staticmethod unpack_genesis_block (block_bytes)

Parameter:
- block_bytes: byte string (208 bytes exactly)

Returns dict of same form as `create_genesis_block`.

Raises `ValueError` if len(block_bytes) != 210.

### @classmethod unpack_chain (chain)

Parameter:
- `chain`: `list` of packed blocks (bytes)

Returns a `list` of unpacked blocks (dicts of forms outlined above).

### @staticmethod block_index (block)

Parameter:
- `block`: `dict`

Encodes the block height in bytes.

### @staticmethod block_index_hex (block)

Parameter:
- `block`: `dict`

Returns human-readable `bytes` for the index file. Of form `numeral_height:hex_hash`.

### @classmethod pack_block (block)

Parameter:
- `block`: `dict` of form displayed above

Returns a byte string: index + hash + signature + address + previous_block + nonce + body

### @staticmethod pack_genesis_block (block)

Parameter:
- `block`: `dict` of form displayed above

Returns a byte string: \x01\x00 + hash + signature + genesis_address + node_address + nonce + public_key

### @staticmethod print_block (block)

Parameter:
- `block`: `dict`

Prints the block in clean, human-readable format.

### @classmethod print_block_chain (blockchain)

Parameter:
- `blockchain`: `BasicBlockChain`

Prints the chain in clean, human-readable format. Does not print instance attributes.



# To Do

- Write new serializer that uses SQLite.

# Copyright / ISC License

Copyright (c) 2019 Jonathan Voss

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 THIS SOFTWARE.
