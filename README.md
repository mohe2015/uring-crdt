<!--
SPDX-FileCopyrightText: 2022 Moritz Hedtke <Moritz.Hedtke@t-online.de>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# uring-crdt

## Setup


```bash
openssl genpkey -algorithm ed25519 -outform der -out server-key.der
openssl req -addext basicConstraints=critical,CA:FALSE -addext "subjectAltName = DNS:example.org" -nodes -x509 -keyform der -key server-key.der -outform der -out server-cert.der -sha256 -batch -days 3650 -subj "/CN=example.org"
openssl genpkey -algorithm ed25519 -outform der -out client-key.der
openssl req -addext basicConstraints=critical,CA:FALSE -addext "subjectAltName = DNS:example.org" -nodes -x509 -keyform der -key client-key.der -outform der -out client-cert.der -sha256 -batch -days 3650 -subj "/CN=example.org"

openssl x509 -in client-cert.der -inform der -text
```

## Documentation (also of dependencies because git dependencies)

```bash
cargo doc --open
```

## crdt design

We need to use an Operation-based CRDT and not a State-based CRDT because we want to know who changed what and also add a permission system.

We need to authenticate each operation by the author of the operation using cryptography.

We should probably cache the current value of the CRDTs underlying value for efficiency.

But for now we first need to persist the CRDT itself.

As CRDT nodes need to reference (multiple) previous nodes (similar to git) this is a Directed acyclic graph.

It could be a kind of append only log as the dependency order creates a natural order of the elements. There is no unique order though.

Then there would be one file per element. Maybe later we could create an abstraction that does this in the database itself so we rely less on the file system.

## Update license headers

```bash
reuse addheader --copyright "Moritz Hedtke <Moritz.Hedtke@t-online.de>" --license "AGPL-3.0-or-later" --recursive --skip-unrecognised .
reuse lint
```
