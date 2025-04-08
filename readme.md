# Locky

A Rust implementation of multi-party ML-KEM-768 (formerly CRYSTALS-Kyber) using threshold cryptography.

## Overview

Locky adapts FIPS 203's ML-KEM-768 (Module Learning With Errors Key Encapsulation Mechanism) for the multi-party setting using Shamir's Secret Sharing. This allows distributing the private key among multiple parties, where decryption requires a threshold number of these parties to collaborate without any single party having access to the entire private key.

### Features

- **Threshold Cryptography**: Distribute private keys among N parties with a customizable threshold (t-of-N)
- **Post-Quantum Security**: Based on the ML-KEM-768 algorithm, resistant to quantum attacks
- **FIPS 203 Compatibility**: Uses the standardized implementation of ML-KEM-768
- **Shamir's Secret Sharing**: Secure secret splitting with polynomial interpolation

## Technical Background

Locky implements a threshold version of the ML-KEM-768 cryptosystem with the following characteristics:

- Module dimension: n = 256
- Modulus: q = 3329
- Security parameter: k = 3 (768-bit security level)
- Error parameter: η = 2

The implementation handles:

1. Secret key generation and sharing
2. Distributed public key generation
3. Encryption against the combined public key
4. Partial decryption by individual keyholders
5. Combining partial decryptions to recover the plaintext

## Installation

Add Locky to your `Cargo.toml`:

```toml
[dependencies]
locky = "0.0.1"
```

## Usage Examples

### Secret Generation and Key Sharing

```rust
use locky::mlwe::{generate_secret_and_shares, SecretAndShares};

// Generate a secret key and share it among 5 parties with a threshold of 3
const PARTIES: usize = 5;
let threshold = 3;
let SecretAndShares { secret, shares } = generate_secret_and_shares::<PARTIES>(threshold);

// Distribute shares[i] to party i
```

### Distributed Public Key Generation

```rust
use locky::mlwe::{generate_keypair, add_public_keys, ASeed, Keypair, Pk};
use rand::Rng;

// Each party generates their own keypair using their share
let mut rng = rand::thread_rng();
let a_seed: ASeed = rng.gen();

// Party 1 generates their keypair
let Keypair { sk: sk1, pk: pk1 } = generate_keypair::<PARTIES>(party1_shares, &a_seed);

// Party 2 generates their keypair
let Keypair { sk: sk2, pk: pk2 } = generate_keypair::<PARTIES>(party2_shares, &a_seed);

// ... Party N generates their keypair

// Combine public keys
let combined_pk = add_public_keys(pk1, pk2);
// Continue combining all public keys
```

### Encryption

```rust
use locky::mlwe::{encrypt, Plaintext, CiphertextU, CiphertextV};

// The plaintext (32 bytes for ML-KEM-768)
let plaintext: Plaintext = [/* your 32-byte data */; 32];

// Encrypt using the combined public key
let (v, u) = encrypt(&combined_pk, &a_seed, &plaintext);
```

### Partial Decryption and Combining Results

```rust
use locky::mlwe::{partial_decrypt, assemble_decryptions};

// Each party performs partial decryption
let participating_indexes = [1, 2, 3]; // Indexes of participating parties (assuming threshold = 3)

// Party 1 performs partial decryption
let h1 = partial_decrypt((sk1.0, &sk1.1), u.clone(), &participating_indexes);

// Party 2 performs partial decryption
let h2 = partial_decrypt((sk2.0, &sk2.1), u.clone(), &participating_indexes);

// Party 3 performs partial decryption
let h3 = partial_decrypt((sk3.0, &sk3.1), u.clone(), &participating_indexes);

// Combine partial decryptions to get the original plaintext
let decrypted = assemble_decryptions(v, [h1, h2, h3].into_iter());
assert_eq!(plaintext, decrypted);
```

## Implementation Details

### Module Structure

- `mlwe.rs`: Core implementation of multi-party ML-KEM
- `shamirs.rs`: Implementation of Shamir's Secret Sharing
- `helpers.rs`: Utility functions for hashing, sampling, and standard ML-KEM operations

### Mathematical Foundation

The implementation leverages:

- **Module Learning With Errors**: A post-quantum secure cryptographic primitive
- **Polynomial Rings**: Operations over Zq[x]/(x^n + 1)
- **Number Theoretic Transform**: Efficient polynomial multiplication
- **Lagrange Interpolation**: For reconstructing secrets from shares

## Dependencies

- `feanor-math`: Mathematical operations for polynomial rings
- `fips203`: FIPS 203 ML-KEM implementation
- `rand`: Random number generation
- `bitvec`: Bit manipulation
- `sha3`: Cryptographic hashing
- `aes-gcm`: AES-GCM authenticated encryption
- `aes-kw`: AES Key Wrap

## License

This project is available under [LICENSE].

## Contributing

Contributions are welcome. Please feel free to submit a Pull Request.