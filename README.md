# CPUS: Code-based PQ-secure User-Server authentication

Reference implementation and formal models accompanying the paper
*"CPUS: Code-based PQ-secure User-Server Authentication"*.

CPUS is a lightweight user-server authentication and key-agreement protocol
built on RQC.KEM: the client performs one RQC encryption, the server performs
the rank-metric decoding.

> **Research prototype.** Not constant-time, not side-channel audited, and not
> cross-checked against the official RQC reference code. Do not use in production.

## Contents

| Path | Description |
|---|---|
| `cpus.c` | C implementation: protocol, RQC-I from scratch, tests, benchmark |
| `proverif/cpus_main.pv` | ProVerif model of the protocol as specified |
| `proverif/cpus_fs.pv` | Same, with the server RQC secret key leaked after the sessions |
| `proverif/cpus_eph.pv` | Optional extension with an ephemeral server KEM key |
| `proverif/run_all.sh` | Runs the three ProVerif models |
| `Makefile` | `make`, `make test`, `make bench`, `make proverif` |

## C implementation

Requirements: `gcc`, OpenSSL development headers (`sudo apt install libssl-dev`).

```
make            # gcc -O2 -march=native cpus.c -o cpus -lcrypto -lm
make test       # prints the RQC parameters, then runs all tests
make bench      # timing over 30 runs
```

`-march=native` enables PCLMULQDQ. Without it a portable multiplier is used
and everything is roughly 30x slower.

### RQC-I parameters

`q=2, m=127, n=113, k=3, w=w1=7, w2=6, delta=55`, `F_{2^127}=F_2[x]/(x^127+x+1)`,
`P = X^113 + X^9 + 1`. Packed `|PK| = |SK| = |CT| = 3588` bytes (this code
stores ciphertexts unpacked, 3616 bytes). Hashes: SHA-256 with domain-separation
bytes; seed expansion: SHAKE-256.

### Tests (`./cpus`)

| Test | Checks |
|---|---|
| 0 | field identities, `Dec(Enc(m)) = m`, error rank = delta, FO check, wrong key |
| 1-2 | mutual authentication, `sk_U = sk_S`, pseudonym rotation |
| 3 | loss of message 4 and recovery via `IDS_old` |
| 4 | modified ciphertext rejected |
| 5 | unknown pseudonym rejected without decoding |
| 6 | replay rejected |
| 7 | server with a wrong secret key |
| 8 | impostor server passing only the Step-1 check |

Expected last line: `RESULT: Mutual Authentication Successful, all tests passed`.

### Benchmark (`./cpus bench 30`)

Reference run (`gcc -O2 -march=native`, PCLMULQDQ, mean of 30 runs, ms):

| Operation | Mean |
|---|---|
| Client encapsulation | 0.181 |
| Client total per run | 0.243 |
| Server decapsulation (decode + re-encrypt) | 4.614 |
| Server total per run | 4.335 |

Absolute times depend on the machine; the client/server ratio (about 18x) is the
portable result. The decoder is an O(n^3) reference solver, so server times are
an upper bound.

## ProVerif models

Tested with ProVerif 2.00 (https://bblanche.gitlabpages.inria.fr/proverif/).

```
cd proverif
proverif cpus_main.pv
proverif cpus_fs.pv
proverif cpus_eph.pv
# or:  PV=proverif sh run_all.sh   (from the proverif directory), or: make proverif
```

Expected for each model: both `not attacker(secret...)` lines `is true`, both
`inj-event(...)` lines `is true`, and both `not event(...)` lines `is false`
(accepting events are reachable).

Assumption: `ID_U` is a high-entropy value known only to the user and the server.
The models are symbolic, use one registered user, and do not model pseudonym
rotation (covered by the C tests).



