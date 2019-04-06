# The Parity Zcash client.

[![Build Status][travis-image]][travis-url] [![Snap Status](https://build.snapcraft.io/badge/paritytech/parity-bitcoin.svg)](https://build.snapcraft.io/user/paritytech/parity-bitcoin)

Gitter [![Gitter https://gitter.im/paritytech/parity-zcash](https://badges.gitter.im/paritytech/parity-zcash.svg)](https://gitter.im/paritytech/parity-zcash)

## Blog: [Parity teams up with Zcash Foundation for Parity Zcash client](https://www.parity.io/parity-teams-up-with-zcash-foundation-for-parity-zcash-client/)

- [Installing from source](#installing-from-source)

- [Installing the snap](#installing-the-snap)

- [Running tests](#running-tests)

- [Going online](#going-online)

- [Importing bitcoind database](#importing-zcashd-database)

- [Command line interface](#command-line-interface)

- [JSON-RPC](JSON-RPC.md)

- [Logging](#logging)

- [Internal Documentation](#internal-documentation)

[travis-image]: https://api.travis-ci.org/paritytech/parity-zcash.svg?branch=master
[travis-url]: https://travis-ci.org/paritytech/parity-zcash
[doc-url]: https://paritytech.github.io/parity-zcash/pzec/index.html

## Installing from source

Installing `pzec` from source requires `rustc` and `cargo`.

Minimal supported version is `rustc 1.23.0 (766bd11c8 2018-01-01)`

#### Install rustc and cargo

Both `rustc` and `cargo` are a part of rust tool-chain.

An easy way to install the stable binaries for Linux and Mac is to run this in your shell:

```
curl https://sh.rustup.rs -sSf | sh
```

Windows binaries can be downloaded from [rust-lang website](https://forge.rust-lang.org/other-installation-methods.html#standalone).

#### Install C and C++ compilers

You will need the cc and gcc compilers to build some of the dependencies.

On macOS <br />

`build-essential` is a Debian package. On macOS you will need to make sure you have Xcode installed. If you already have Homebrew installed, you probably also already have the Xcode tools installed as well. If not, you can run the command below:
```
xcode-select --install
```

On Linux
```
sudo apt-get update
sudo apt-get install build-essential
```

#### Clone and build pzec

Now let's clone `pzec` and enter it's directory:

```
git clone https://github.com/paritytech/parity-zcash
cd parity-zcash

# builds pzec in release mode
cargo build -p pzec --release
```

`pzec` is now available at `./target/release/pzec`.

## Installing the snap

In any of the [supported Linux distros](https://snapcraft.io/docs/core/install):

```
sudo snap install parity-zcash --edge
```

## Running tests

`pzec` has internal unit tests and it conforms to external integration tests.

#### Running unit tests

Assuming that repository is already cloned, we can run unit tests with this command:

```
cargo test --all
```

## Going online

By default parity connects to Zcash seednodes. Full list is [here](./pzec/seednodes.rs).

To start syncing the main network, just start the client without any arguments:

```
./target/release/pzec
```

To start syncing the testnet:

```
./target/release/pzec --testnet
```

To not print any syncing progress add `--quiet` flag:

```
./target/release/pzec --quiet
```

## Importing zcashd database

It it is possible to import existing `zcashd` database:

```
# where $ZCASH_DB is path to your zcashd database. By default:
# on macOS: "/Users/user/Library/Application Support/Zcash"
# on Linux: "~/.zcash"
./target/release/pzec import "$ZCASH_DB/blocks"
```

By default, import verifies the imported blocks. You can disable this, by adding the `--verification-level=none` option.

```
./target/release/pzec --verification-level=none import "$ZCASH_DB/blocks"
```

## Command line interface

Full list of CLI options, which is available under `pzec --help`: see [here](CLI.md)

## Logging

This is a section only for developers and power users.

You can enable detailed client logging by setting the environment variable `RUST_LOG`, e.g.,

```
RUST_LOG=verification=info ./target/release/pzec
```

`pzec` started with this environment variable will print all logs coming from `verification` module with verbosity `info` or higher. Available log levels are:

- `error`
- `warn`
- `info`
- `debug`
- `trace`

It's also possible to start logging from multiple modules in the same time:

```
RUST_LOG=sync=trace,p2p=trace,verification=trace,db=trace ./target/release/pzec
```

## Internal documentation

Once released, `pzec` documentation will be available [here][doc-url]. Meanwhile it's only possible to build it locally:

```
cd parity-zcash
./tools/doc.sh
open target/doc/pzec/index.html
```
