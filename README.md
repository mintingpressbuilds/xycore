# xycore

[![xycore](https://img.shields.io/badge/xycore-v1.0.1-green)](https://pypi.org/project/xycore/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/xycore/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

The zero-dependency cryptographic protocol for proving state transitions.

X is state before. Y is state after. XY is proof the transition 
happened. Chain them. Anyone can verify.

Not a blockchain. Not a database. Not a logging framework.
A standalone protocol — the cryptographic core, extracted,
with nothing else attached.

## Install

pip install xycore

## Usage

from xycore import XYChain

chain = XYChain(name="my-chain")
chain.append("deploy",
    x_state={"version": "1.0"},
    y_state={"version": "1.1"}
)
chain.append("configure",
    x_state={"version": "1.1"},
    y_state={"version": "1.1", "configured": True}
)

valid, break_index = chain.verify()
assert valid

## Properties

- Zero dependencies. Standard library only.
- Works offline. Works without an account. Works forever.
- Anyone can implement against this spec in any language.
- Anyone can verify a chain independently — no trust required.

## Signatures (optional)

pip install xycore[signatures]

## pruv

pruv is the verification layer built on xycore.
https://pruv.dev
