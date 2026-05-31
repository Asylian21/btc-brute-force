# Contributing

Thanks for considering a contribution to `btc-brute-force`, the Bitcoin address-collision research toolkit.

This project is intentionally focused on education, reproducible benchmarks, and cryptographic reality checks. Contributions should help readers understand Bitcoin P2PKH address generation, secp256k1, Hash160, Go performance engineering, or why broad Bitcoin brute force remains infeasible.

## Good Contributions

- Benchmark results from additional CPUs, operating systems, and Go versions.
- Performance improvements with before/after measurements and reproducible commands.
- Tests that protect the secp256k1 walk, GLV variant mapping, Hash160 pipeline, checkpointing, or address parsing.
- Documentation that makes Bitcoin security, P2PKH, SHA-256, RIPEMD-160, Hash160, Base58, or probability easier to understand.
- Build, release, and CI improvements that make the toolkit easier to verify.

## Not Accepted

- Wallet-cracking claims, theft workflows, or instructions for unauthorized access.
- Misleading success-probability claims.
- Changes that hide the mathematical infeasibility of broad Bitcoin address search.
- Large address databases, match output, checkpoints, private keys, seed phrases, credentials, or secrets.

## Before Opening a Pull Request

Run the core checks:

```bash
make vet
make test
make build
```

For performance work, include benchmark context:

```bash
make bench
```

Please include hardware, OS, Go version, command used, and whether the machine was thermally stable. For security-sensitive reports, follow [`SECURITY.md`](SECURITY.md) instead of opening a public issue.
