# GitHub SEO Checklist

Use this checklist after pushing the repository so GitHub search, social cards, and external search engines describe the project accurately.

## Repository Description

```text
Offline Bitcoin address-collision research toolkit and Go benchmark for P2PKH, Hash160, secp256k1, SHA-256, RIPEMD-160, and brute-force infeasibility demos.
```

## Repository Topics

Add these topics in GitHub repository settings:

```text
bitcoin
bitcoin-security
cryptography
secp256k1
hash160
p2pkh
brute-force
address-collision
go
golang
benchmark
performance-engineering
offline-tool
security-education
```

## Website Field

Use the related article as the website until a dedicated project page exists:

```text
https://medium.com/@asylian21/brute-force-vs-reality-what-my-bitcoin-brute-force-really-shows-67872323d6bf
```

## Social Preview

Generate the preview image and upload it in GitHub:

```bash
python3 docs/create-social-preview.py
```

Then open repository **Settings -> General -> Social preview** and upload:

```text
docs/social-preview.png
```

Recommended visible text:

```text
Bitcoin Address-Collision Lab
Go Hash160 + secp256k1 Benchmark
```

## Search Intent Covered

- Bitcoin brute force research
- Bitcoin address collision benchmark
- Bitcoin P2PKH address generator internals
- Hash160 lookup and RIPEMD-160/SHA-256 benchmarking
- secp256k1 Go benchmark
- Offline Bitcoin security education
- Why Bitcoin brute force is impossible

## Release Notes Keywords

When publishing releases, include natural phrases such as:

- `offline Bitcoin address-collision research toolkit`
- `Go secp256k1 and Hash160 benchmark`
- `P2PKH brute-force infeasibility demonstration`
- `multi-buffer SHA-256 and RIPEMD-160 performance`
- `systematic checkpointed key-space scan`

Keep the wording educational and precise. Do not claim practical wallet cracking, guaranteed discovery, recovery capability, or access to funds.
