//! This file does simple SHA-3 based commitments
use crate::mlwe::{N, Q as mlweQ};
use aes_kw::KekAes256;
use ml_kem_rs::ml_kem_768::{CipherText, EncapsKey};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Sha3_256, Shake128};

const Q: u32 = mlweQ as u32;

pub fn hash<D>(data: &D) -> [u8; 32]
where
    D: AsRef<[u8]>,
{
    use sha3::Digest;
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Function XOF on page 16 (4.2).
#[must_use]
pub(crate) fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    use sha3::digest::Update;
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    hasher.finalize_xof()
}

/// Algorithm 6 `SampleNTT(B)` on page 20.
/// If the input is a stream of uniformly random bytes, the output is a uniformly random element of `T_q`.
#[must_use]
pub fn sample_ntt(mut byte_stream_b: impl XofReader) -> [u16; N] {
    // Input: byte stream B ∈ B^{∗}
    // Output: array a_hat ∈ Z^{256}_q              ▷ the coeffcients of the NTT of a polynomial
    let mut array_a_hat = [0; N];
    let mut bbb = [0u8; 3]; // Space for 3 random (byte) draws

    // 1: i ← 0 (not needed as three bytes are repeatedly drawn from the rng bytestream via bbb)

    // 2: j ← 0
    let mut j = 0;

    // 3: while j < 256 do
    while j < N {
        //
        byte_stream_b.read(&mut bbb); // Draw 3 bytes

        // 4: d1 ← B[i] + 256 · (B[i + 1] mod 16)
        let d1 = u32::from(bbb[0]) + 256 * (u32::from(bbb[1]) % 16);

        // 5: d2 ← ⌊B[i + 1]/16⌋ + 16 · B[i + 2]
        let d2 = u32::from(bbb[1]) / 16 + 16 * u32::from(bbb[2]);

        // 6: if d1 < q then
        if d1 < Q {
            //
            // 7: a_hat[j] ← d1         ▷ a_hat ∈ Z256
            array_a_hat[j] = (d1 % Q).try_into().unwrap();

            // 8: j ← j+1
            j += 1;
            //
        } // 9: end if

        // 10: if d2 < q and j < 256 then
        if (d2 < Q) & (j < N) {
            //
            // 11: a_hat[j] ← d2
            array_a_hat[j] = (d2 % Q).try_into().unwrap();

            // 12: j ← j+1
            j += 1;
            //
        } // 13: end if

        // 14: i ← i+3  (not needed as we draw 3 more bytes next time
    } // 15: end while

    array_a_hat // 16: return a_hat
}

/// Encrypt a user key with their provided ephermeral key
pub fn encrypt_key(to_enc: [u8; 32], ek: &EncapsKey) -> (CipherText, [u8; 40]) {
    let (ssk, ct) = ek.encaps();
    let kek = KekAes256::from(ssk.to_bytes());
    let mut res = [0u8; 40];
    kek.wrap(&to_enc, &mut res).unwrap();
    (ct, res)
}

// currently only used in testing
// will probably get used in an SDK
#[cfg(test)]
use ml_kem_rs::ml_kem_768::DecapsKey;
#[cfg(test)]
pub fn decrypt_key(dk: &DecapsKey, ct: &CipherText, to_dec: [u8; 40]) -> [u8; 32] {
    let ssk = dk.decaps(&ct);
    let kek = KekAes256::from(ssk.to_bytes());
    let mut result = [0u8; 32];
    kek.unwrap(&to_dec, &mut result).unwrap();
    result
}

#[test]
fn test_encrypt_and_decrypt() {
    use ml_kem_rs::ml_kem_768;
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut to_enc = [0u8; 32];
    rng.fill(&mut to_enc);
    let (ek, dk) = ml_kem_768::key_gen();
    let (ct, key_ct) = encrypt_key(to_enc, &ek);
    let decrypted = decrypt_key(&dk, &ct, key_ct);
    assert_eq!(to_enc, decrypted);
}
