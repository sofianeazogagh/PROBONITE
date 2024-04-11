# PROBONITE (Private One Branch Only Non-Interactive Decision Tree Evaluation)

This repository allows to execute a proof of concept of [PROBONITE](https://dl.acm.org/doi/pdf/10.1145/3560827.3563377) using the shortint module from the tfhe-rs library.

Disclaimer: This proof of concept has not been applied to any dataset yet. You can simply choose the depth of the tree and the precision bits you want (up to 4 bits).

## Dependencies 

You need to install Rust and Cargo to use tfhe-rs.

First, install the needed Rust toolchain:
```bash
rustup toolchain install nightly
```

Then, you can either:

1. Manually specify the toolchain to use in each of the cargo commands:
For example:
```bash
cargo +nightly build
cargo +nightly run
```
2. Or override the toolchain to use for the current project:
```bash
rustup override set nightly
```

Cargo will use the `nightly` toolchain.
```
cargo build
```

## Usage

The main file contain the following parameters

- ``depth`` corresponding to the depth of the tree
- ``bit_precision`` corresponding to the bit precision you want

Then, a call to the function ``probonite`` is made with those parameters. A random tree will be generated according to the chosen parameters, and the evaluation of the tree will be performed.


To run the project, don't forget to use the ``--release`` flag :
```
cargo run --release
```
