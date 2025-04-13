[//]: # (SPDX-License-Identifier: CC-BY-4.0)

# mldsa-native

![CI](https://github.com/pq-code-package/mldsa-native/actions/workflows/ci.yml/badge.svg)
![Benchmarks](https://github.com/pq-code-package/mldsa-native/actions/workflows/bench.yml/badge.svg)
[![Apache](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://www.apache.org/licenses/LICENSE-2.0)

mldsa-native is a work-in-progress implementation of the [ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) post-quantum signature standard. It is a fork of the ML-DSA [reference implementation](https://github.com/pq-crystals/dilithium).

The goal of mldsa-native is to be a secure, fast and portable C90 implementation of ML-DSA, paralleling [mlkem-native](https://github.com/pq-code-package/mlkem-native) for ML-KEM.

## Status

mldsa-native is work in progress. **WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A
PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** Once we have the first stable version,
this notice will be removed.

## Quickstart for Ubuntu

```bash
# Install base packages
sudo apt-get update
sudo apt-get install make gcc python3 git

# Clone mldsa-native
git clone https://github.com/pq-code-package/mldsa-native.git
cd mldsa-native

# Build and run tests
make build
make test

# The same using `tests`, a convenience wrapper around `make`
./scripts/tests all
# Show all options
./scripts/tests --help
```

## Contributing

If you want to help us build mldsa-native, please reach out. You can contact the mldsa-native team
through the [PQCA Discord](https://discord.com/invite/xyVnwzfg5R).
