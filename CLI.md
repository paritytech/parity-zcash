# Command-line options

```
pzec 0.1.0
Parity Technologies <info@parity.io>
Parity Zcash client

USAGE:
    pzec [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help            Prints help information
        --no-jsonrpc      Disable the JSON-RPC API server.
    -q, --quiet           Do not show any synchronization information in the console.
        --regtest         Use a private network for regression tests.
        --testnet         Use the test network (Testnet3).
    -V, --version         Prints version information

OPTIONS:
        --blocknotify <COMMAND>            Execute COMMAND when the best block changes (%s in COMMAND is replaced by the block hash).
    -c, --connect <IP>                     Connect only to the specified node.
    -d, --data-dir <PATH>                  Specify the database and configuration directory PATH.
        --db-cache <SIZE>                  Sets the database cache size.
        --jsonrpc-apis <APIS>              Specify the APIs available through the JSONRPC interface. APIS is a comma-delimited list of API names.
        --jsonrpc-cors <URL>               Specify CORS header for JSON-RPC API responses.
        --jsonrpc-hosts <HOSTS>            List of allowed Host header values.
        --jsonrpc-interface <INTERFACE>    The hostname portion of the JSONRPC API server.
        --jsonrpc-port <PORT>              Specify the PORT for the JSONRPC API server.
        --only-net <NET>                   Only connect to nodes in network version <NET> (ipv4 or ipv6).
        --port <PORT>                      Listen for connections on PORT.
    -s, --seednode <IP>                    Connect to a seed-node to retrieve peer addresses, and disconnect.
        --verification-edge <BLOCK>        Non-default verification-level is applied until a block with given hash is met.
        --verification-level <LEVEL>       Sets the Blocks verification level to full (default), header (scripts are not verified), or none (no verification at all).

SUBCOMMANDS:
    help        Prints this message or the help of the given subcommand(s)
    import      Import blocks from a zcashd database.
    rollback    Rollback the database to given canonical-chain block.
```
