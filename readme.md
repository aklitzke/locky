# Locky

An _experimental_ adaptation of FIPS203 / ML-KEM-768 to the multi-party setting using threshold cryptography. This allows for post-quantum
distributed key generation with similar security guarantees as ML-KEM

Disclaimer: This project has not been built with production in mind and has known timing vulnerabilities. Do not
use it to encrypt anything of value!

## Technical Background

The implementation handles cryptographic primitives for:

1. Secret key generation and sharing
2. Distributed public key generation
3. Encryption against the combined public key
4. Partial decryption by individual keyholders
5. Combining partial decryptions to recover the plaintext

Locky implements a threshold version of the ML-KEM-768 cryptosystem with the following characteristics:

- Module dimension: n = 256
- Modulus: q = 3329
- Security parameter: k = 3 (768-bit security level)
- Error parameter: η = 2

## Usage Examples

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
let party_1 = generate_secret_and_shares::<PARTIES>(threshold);
// Party 2
let party_2 = generate_secret_and_shares::<PARTIES>(threshold);

// Each party sends shares to every other party, and generates a keypair from them
// Party 1
let keypair_1 = generate_keypair::<PARTIES>([party_1.shares[0], party_2.shares[0]], &a_seed);
// Party 2
let keypair_2 = generate_keypair::<PARTIES>([party_2.shares[1], party_1.shares[1]], &a_seed);

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
let decrypted = assemble_decryptions(
    ciphertext.0,
    [partial_decryption_1, partial_decryption_2].into_iter(),
);
assert_eq!(decrypted, plaintext);
```

## Installation

Check out the repo and add Locky's repo root to your `Cargo.toml`:

```toml
[dependencies]
locky = { path = "../locky" }
```

## Contributing

Contributions are welcome. Please feel free to submit a Pull Request.