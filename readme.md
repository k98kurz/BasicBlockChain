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
I will add some functions for ECDHE using Cruve25519 for messaging between nodes.


# Setup / Usage

1. Install the `python3-nacl` library.
2. Put `blockchain.py` somewhere in the project files.
3. `import [path/to/blockchain] as bc`
4. `from nacl.public import PrivateKey`
5. `from nacl.signing import SigningKey, VerifyKey`

See `sample.py` for some sample code.


# Methods

### setup_node (seed)

Parameter:
- seed: byte string to seed the CSPRNG

Returns a dict of this form:

```
{
    signing_key: nacl.signing.SigningKey,
    verify_key: nacl.signing.VerifyKey,
    address: byte string of verify_key,
    private_key: nacl.public.PrivateKey,
    public_key: nacl.public.PublicKey
}
```

Th SigningKey is derived from the seed, and all other values are derived from it.

### meets_difficulty (signature, difficulty=1)

Parameters:
- signature: byte string of result from `nacl.signing.SigningKey.sign()`
- difficulty=1: int, minimum number of preceding zeroes in block hash

Returns boolean:
- True if the sha256 of the signature has difficulty number of preceding zeroes
- False otherwise

(For brevity, I will omit explanation of difficulty=1 hereinafter.)

### create_genesis_block (genesis_key, node_address, public_key, difficulty=1)

Parameters:
- genesis_key: `nacl.signing.SigningKey`
- node_address: `_key` element from `nacl.signing.VerifyKey`, e.g. `node['verify_key']._key`
- public_key: `_public_key` element from `nacl.public.PublicKey`, e.g. `node['public_key']._public_key`

Returns a packed block (i.e. byte string).

### create_block (signing_key, previous_block, body, difficulty=1)

Parameters:
- signing_key: `nacl.signing.SigningKey`
- previous_block: byte string or dict
- body: byte string

Returns a packed block (i.e. byte string).

### verify_chain (blocks, genesis_address, difficulty=1)

Parameters:
- blocks: list of blocks (dicts or byte strings)
- genesis_address: byte string of genesis address

Returns a boolean:
- False if verify_genesis_block fails on first block
- False if verify_block fails on any other block
- False if any non-genesis block does not reference previous block
- True if all checks are passed

### verify_genesis_block (block, genesis_address, difficulty=1)

Parameters:
- block: dict or byte string
- genesis_address: byte string

Returns a boolean:
- False if block address is not the genesis_address
- False if block hash does not meet difficulty level
- False if block signature fails verification
- False if unpacking a byte string block into a dict encounters a ValueError
- True if all checks are passed

### verify_block (block, difficulty=1)

Parameters:
- block: dict or byte string

Returns a boolean:
- False if block hash does not meet difficulty level
- False if block signature fails verification
- False if unpacking a byte string block into a dict encounters a ValueError
- True if all checks are passed

### unpack_block (block_bytes)

Parameter:
- block_bytes: byte string (at least 176 bytes long)

Returns dict of this form:
```
{
    hash: 32 bytes,
    signature: 64 bytes,
    address: 32 bytes,
    previous_block: 32 bytes,
    nonce: 16 bytes,
    body: variable length byte string
}
```

Raises ValueError if len(block_bytes) < 176.

### pack_block (block)

Parameter:
- block: dict of form displayed above

Returns a byte string: hash + signature + address + previous_block + nonce + body

### unpack_genesis_block (block_bytes)

Parameter:
- block_bytes: byte string (208 bytes exactly)

Returns a dict of this form:
```
{
    hash: 32 bytes,
    signature: 64 bytes,
    address: 32 bytes (genesis_address),
    node_address: 32 bytes,
    nonce: 16 bytes,
    public_key: 32 bytes
}
```

Raises ValueError if len(block_bytes) != 208.

### pack_genesis_block (block)

Parameter:
- block: dict of form displayed above

Returns a byte string: hash + signature + genesis_address + node_address + nonce + public_key

### unpack_chain (chain)

Parameter:
- chain: list of packed blocks (bytes)

Returns a list of unpacked blocks (dicts of forms outlined above).

### save_block_chain (path, name, chain)

Parameters:
- path: string (should be namespaced with genesis_address if allowing subnetworks)
- name: string (should be hex or b64 of node address)
- chain: list of packed (bytes) or unpacked (dict) blocks

Saves blocks to flat files. Creates path/name directory if necessary. No return value.

### load_block_chain (path, name)

Parameters:
- path: string (should be namespaced with genesis_address if allowing subnetworks)
- name: string (should be hex or b64 of node address)

Loads a block chain from path/name. Returns a list of unpacked blocks (dicts).


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
