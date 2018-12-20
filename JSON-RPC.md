# JSON-RPC

The JSON-RPC interface is served on port :8332 for mainnet and :18332 for testnet unless you specified otherwise. So if you are using testnet, you will need to change the port in the sample curl requests shown below.

### Network

The Parity Zcash `network` interface.

#### addnode

Add the node.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "add"], "id":1 }' localhost:8332

Remove the node.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "remove"], "id":1 }' localhost:8332

Connect to the node.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "onetry"], "id":1 }' localhost:8332

#### getaddednodeinfo

Query info for all added nodes.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getaddednodeinfo", "params": [true] }' localhost:8332

Query info for the specified node.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getaddednodeinfo", "params": [true, "192.168.0.201"] }' localhost:8332

#### getconnectioncount

Get the peer count.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getconnectioncount", "params": [] }' localhost:8332

### Blockchain

The Parity-bitcoin `blockchain` data interface.

#### getbestblockhash

Get hash of best block.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getbestblockhash", "params": [], "id":1 }' localhost:8332

#### getblockcount

Get height of best block.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id":1 }' localhost:8332

#### getblockhash

Get hash of block at given height.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getblockhash", "params": [0], "id":1 }' localhost:8332

#### getdifficulty

Get proof-of-work difficulty as a multiple of the minimum difficulty

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getdifficulty", "params": [], "id":1 }' localhost:8332

#### getblock

Get information on given block.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getblock", "params": ["000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"], "id":1 }' localhost:8332

#### gettxout

Get details about an unspent transaction output.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "gettxout", "params": ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", 0], "id":1 }' localhost:8332

#### gettxoutsetinfo

Get statistics about the unspent transaction output set.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "gettxoutsetinfo", "params": [], "id":1 }' localhost:8332

### Miner

The Parity-bitcoin `miner` data interface.

#### getblocktemplate

Get block template for mining.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getblocktemplate", "params": [{"capabilities": ["coinbasetxn", "workid", "coinbase/append"]}], "id":1 }' localhost:8332

### Raw

The Parity-bitcoin `raw` data interface.


#### getrawtransaction

Return the raw transaction data.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "getrawtransaction", "params": ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"], "id":1 }' localhost:8332

#### decoderawtransaction

Return an object representing the serialized, hex-encoded transaction.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "decoderawtransaction", "params": ["01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"], "id":1 }' localhost:8332

#### createrawtransaction

Create a transaction spending the given inputs and creating new outputs.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "createrawtransaction", "params": [[{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","vout":0}],{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa":0.01}], "id":1 }' localhost:8332

#### sendrawtransaction

Adds transaction to the memory pool && relays it to the peers.

    curl -H 'content-type: application/json' --data-binary '{"jsonrpc": "2.0", "method": "sendrawtransaction", "params": ["01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"], "id":1 }' localhost:8332