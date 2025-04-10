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
use locky::mlwe::{
    add_public_keys, assemble_decryptions, encrypt, generate_keypair, generate_secret_and_shares,
    partial_decrypt, ASeed, Keypair, Pk, Plaintext, SecretAndShares,
};
use rand::Rng;

const PARTIES: usize = 2;
// t + 1 = 2 parties required to decrypt
let threshold = 1;

// The parties collaborate to generate a public random seed
let mut rng = rand::rng();
let a_seed: ASeed = rng.random();

// Each party generates a secret with shares for each other party
// Party 1
let SecretAndShares { secret: secret_1, shares: shares_1 } = generate_secret_and_shares::<PARTIES>(threshold);
// Party 2
let SecretAndShares { secret: secret_2 , shares: shares_2 } = generate_secret_and_shares::<PARTIES>(threshold);

// Each party sends shares to every other party, and generates a keypair from them
// Party 1
let keypair_1 = generate_keypair::<PARTIES>([shares_1[0], shares_2[0]], &a_seed);
// Party 2
let keypair_2 = generate_keypair::<PARTIES>([shares_2[1], shares_1[1]], &a_seed);

// Each party publishes their public key
// public keys are combined into one root public key
let public_key = add_public_keys(keypair_1.pk, keypair_2.pk);

// Anyone with the root public key and a_seed can encrypt data for the parties to decrypt
let plaintext: Plaintext = rand::rng().random();
let ciphertext = encrypt(&public_key, &a_seed, &plaintext);

// The ciphertext is sent to each party for a partial decryption
// Party 1
let partial_decryption_1 = partial_decrypt(&keypair_1.sk, ciphertext.1, &[1, 2]);
// Party 2
let partial_decryption_2 = partial_decrypt(&keypair_2.sk, ciphertext.1, &[1, 2]);

// Partial decryptions are assembled to reconstitute the plaintext
let decrypted = assemble_decryptions(ciphertext.0, [partial_decryption_1, partial_decryption_2].into_iter());
assert_eq!(decrypted, plaintext);
```

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