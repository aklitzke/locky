use crate::helpers::{sample_ntt, xof};
#[cfg(test)]
use crate::shamirs::{assemble_share_ref, interpolate_shares_ref};
use crate::shamirs::{generate_shares, mul_by_lagrange};
use bitvec::prelude as bv;
use feanor_math::divisibility::{DivisibilityRing, DivisibilityRingStore};
use feanor_math::homomorphism::Homomorphism;
use feanor_math::ring::{El, RingExtensionStore, RingStore};
use feanor_math::rings::finite::FiniteRingStore;
use feanor_math::rings::poly::dense_poly::DensePolyRing;
use feanor_math::rings::poly::PolyRingStore;
use feanor_math::rings::zn::zn_static::Fp;
use rand::Rng;

// ml-kem 768
pub const Q: u64 = 3329;
// pub const Q: u64 = 11;
// const Q: u64 = 29;
// const Q: u64 = 7681;
pub const N: usize = 256;
// pub const N: usize = 2;
pub const K: usize = 3;
// pub const K: usize = 1;
pub const ETA: usize = 2;
// const ETA: usize = 1;

pub type Sk = [[u16; N]; K];
pub struct SecretAndShares<const PARTIES: usize> {
    pub secret: (u32, Sk),
    pub shares: [(u32, Sk); PARTIES],
}
pub fn generate_secret_and_shares<const PARTIES: usize>(
    threshold: u32,
) -> SecretAndShares<PARTIES> {
    let ring = ring();
    // generate the secret
    let (secret, shares) = ring.new_secret_and_shares(threshold as i32, PARTIES as i32);
    // convert base ring type into sized and compressed arrays
    debug_assert_eq!(shares.len(), PARTIES);
    SecretAndShares {
        secret: (0, ring.compress_vec(secret)),
        shares: shares
            .into_iter()
            .map(|i| {
                debug_assert_eq!(ring.0.degree(&i.index).unwrap(), 0);
                (
                    *ring.0.coefficient_at(&i.index, 0) as u32,
                    ring.compress_vec(i.shares),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    }
}

pub type Pk = [[u16; N]; K];
pub type ASeed = [u8; 32];
pub struct Keypair {
    pub sk: (u32, Sk),
    pub pk: Pk,
}
pub fn generate_keypair<const PARTIES: usize>(
    shares: [(u32, Sk); PARTIES],
    a_seed: &ASeed,
) -> Keypair {
    let ring = ring();
    let shares = shares
        .into_iter()
        .map(|(index, share)| VecShare::<Ring> {
            index: ring.0.int_hom().map(index as i32),
            shares: ring.decompress_vec(share),
        })
        .collect();
    let secret = ring.make_secret_from_shares(shares);
    // print!("{} final secret: ", ring.0.format(&secret.index));
    // print_vec(&secret.shares, &ring.0);
    let pk = ring.make_public_key::<PARTIES>(&secret, a_seed);
    // print!("{} final pk: ", ring.0.format(&secret.index));
    // print_vec(&pk, &ring.0);
    Keypair {
        sk: (
            ring.ring_to_index(&secret.index),
            ring.compress_vec(secret.shares),
        ),
        pk: ring.compress_vec(pk),
    }
}
pub fn add_public_keys(pk1: Pk, pk2: Pk) -> Pk {
    let ring = ring();
    ring.compress_vec(mat_add_vec(
        ring.decompress_vec(pk1),
        ring.decompress_vec(pk2),
        &ring.0,
    ))
}

pub type Plaintext = [u8; N / 8];
pub type CiphertextV = [u16; N];
pub type CiphertextU = [[u16; N]; K];
pub fn encrypt(pk: &Pk, a_seed: &ASeed, plaintext: &Plaintext) -> (CiphertextV, CiphertextU) {
    let ring = ring();
    let pk_ring = ring.decompress_vec(pk.clone());
    let a = ring.a_from_seed(a_seed);
    let pt: Vec<u8> = bv::BitVec::<_, bv::Msb0>::from_slice(plaintext.as_slice())
        .iter()
        .by_vals()
        .map(|bit| bit as u8)
        .collect();
    let (v, u) = ring.encrypt(pk_ring, a, pt);
    (ring.compress(v), ring.compress_vec(u))
}

pub fn partial_decrypt(sk: (u32, &Sk), u: CiphertextU, indexes: &[u32]) -> CiphertextV {
    let ring = ring();
    let secret = VecShare {
        shares: ring.decompress_vec(sk.1.clone()),
        index: ring.0.int_hom().map(sk.0 as i32),
    };
    let ring_u = ring.decompress_vec(u);
    let ring_indexes: Vec<_> = indexes
        .iter()
        .map(|i| ring.0.int_hom().map(*i as i32))
        .collect();
    ring.compress(ring.partial_decrypt(secret, &ring_indexes, ring_u))
}

pub fn assemble_decryptions<I>(v: CiphertextV, hs: I) -> Plaintext
where
    I: Iterator<Item = CiphertextV>,
{
    let ring = ring();
    let ring_v = ring.decompress(v);
    let ring_hs = hs.map(|h| ring.decompress(h));
    let bits: bv::BitVec<_, bv::Msb0> = ring
        .assemble_decryptions(ring_v, ring_hs)
        .into_iter()
        .map(|i| {
            // println!("is: {}", i);
            debug_assert!(i <= 1);
            i == 1
        })
        .collect();
    bits.into_vec().try_into().unwrap()
}

struct VecShare<P: RingStore> {
    pub shares: Vec<El<P>>,
    pub index: El<P>,
}

type Ring = feanor_math::ring::RingValue<
    feanor_math::rings::poly::dense_poly::DensePolyRingBase<
        feanor_math::ring::RingValue<feanor_math::rings::zn::zn_static::ZnBase<Q, true>>,
    >,
>;

struct RingHelper(Ring);

fn ring() -> RingHelper {
    let base_ring = Fp::<Q>::RING;
    RingHelper(DensePolyRing::new(base_ring, "x"))
}

impl RingHelper {
    pub fn binomial_random_poly(&self) -> El<Ring> {
        let mut rng = rand::rng();
        let bits_needed = N * ETA * 2;
        let bytes: Vec<u8> = (0..(bits_needed.div_ceil(64)))
            .map(|_| rng.random::<u64>().to_be_bytes())
            .flatten()
            .collect();
        let bits = bv::BitVec::<_, bv::Msb0>::from_vec(bytes);
        let coeffs: Vec<u64> = (0..N)
            .map(|i| {
                let x = (0..ETA).fold(0, |x, j| x + (bits[(ETA * i * 2) + j] as i32));
                let y = (0..ETA).fold(0, |y, j| y + (bits[(ETA * i * 2) + ETA + j] as i32));
                self.0.base_ring().int_hom().map(x - y)
                // self.0.base_ring().int_hom().map(0)
            })
            .collect();
        self.make_ring(&coeffs)
    }
    fn binomial_random_poly_vec(&self) -> Vec<El<Ring>> {
        (0..K).map(|_| self.binomial_random_poly()).collect()
    }
    fn uniform_random_poly(&self) -> El<Ring> {
        let mut rng = rand::rng();
        self.make_ring(
            &(0..N)
                .map(|_| self.0.base_ring().random_element(|| rng.random::<u64>()))
                .collect::<Vec<_>>(),
        )
    }
    // not used anymore since A is generated from a seed
    // fn uniform_random_poly_vec(&self) -> Vec<El<Ring>> {
    //     (0..K).map(|_| self.uniform_random_poly()).collect()
    // }
    pub fn make_ring<B>(&self, terms: &[B]) -> El<Ring>
    where
        B: Into<u64> + Copy,
    {
        self.0.from_terms(
            terms
                .iter()
                .enumerate()
                .map(|(i, term)| ((*term).into(), i)),
        )
    }
    pub fn ring_to_index(&self, el: &El<Ring>) -> u32 {
        self.0
            .terms(el)
            .fold(None, |acc, (term, pow)| {
                if pow == 0 {
                    debug_assert_eq!(acc, None);
                    Some(*term as u32)
                } else {
                    debug_assert!(*term == 0);
                    None
                }
            })
            .unwrap()
    }
    pub fn compress(&self, el: El<Ring>) -> [u16; N] {
        // println!("compressing {}", self.0.format(&el));
        let mut compressed = [0 as u16; N];
        self.0.terms(&el).for_each(|(term, pow)| {
            compressed[pow] = (*term).try_into().unwrap();
        });
        compressed
    }
    pub fn compress_vec(&self, el: Vec<El<Ring>>) -> [[u16; N]; K] {
        debug_assert_eq!(el.len(), K);
        el.into_iter()
            .map(|inner_el| self.compress(inner_el))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    pub fn decompress(&self, el: [u16; N]) -> El<Ring> {
        self.0
            .from_terms(el.iter().enumerate().map(|(i, term)| ((*term) as u64, i)))
    }
    pub fn decompress_vec(&self, el_vec: [[u16; N]; K]) -> Vec<El<Ring>> {
        el_vec.into_iter().map(|el| self.decompress(el)).collect()
    }
    pub fn new_secret_and_shares(
        &self,
        threshold: i32,
        parties: i32,
    ) -> (Vec<El<Ring>>, Vec<VecShare<Ring>>) {
        let secret = self.binomial_random_poly_vec();
        let indexes = (0..parties).map(|i| self.0.int_hom().map(i + 1));
        let mut random_el = || self.uniform_random_poly();
        let shares = generate_shares_vec(threshold, &indexes, &secret, &mut random_el, &self.0);
        (secret, shares)
    }
    pub fn a_from_seed(&self, a_seed: &[u8; 32]) -> Vec<Vec<El<Ring>>> {
        (0..K as u8)
            .map(|i| {
                (0..K as u8)
                    .map(|j| self.make_ring(&sample_ntt(xof(&a_seed, i, j))))
                    .collect()
            })
            .collect()
    }
    pub fn make_secret_from_shares(&self, shares: Vec<VecShare<Ring>>) -> VecShare<Ring> {
        sum_shares_vec(shares, &self.0)
    }
    // assumes linear party organization: parties of 3 means indexes are 1,2, and 3
    pub fn make_public_key<const PARTIES: usize>(
        &self,
        secret: &VecShare<Ring>,
        a_seed: &[u8; 32],
    ) -> Vec<El<Ring>> {
        let indexes = (0..PARTIES)
            .map(|i| self.0.int_hom().map((i + 1) as i32))
            .collect::<Vec<_>>();
        let secret_copy = VecShare {
            shares: clone_vec(&secret.shares, &self.0).collect(),
            index: self.0.clone_el(&secret.index),
        };
        let t_secret = mul_by_lagrange_vec(secret_copy, &indexes, &self.0);
        let a = self.a_from_seed(&a_seed);
        mat_add_vec(
            reduce_vec(mat_mul_vector(a, t_secret, &self.0), &self.0),
            self.binomial_random_poly_vec(),
            &self.0,
        )
    }

    pub fn encrypt(
        &self,
        pk: Vec<El<Ring>>,
        a: Vec<Vec<El<Ring>>>,
        plaintext: Vec<u8>,
    ) -> (El<Ring>, Vec<El<Ring>>) {
        debug_assert_eq!(plaintext.len(), N);
        // convert {0,1} -> {0, Q/2} == (q/2)*m
        let q2m = self.0.mul(
            self.make_ring(&plaintext),
            self.0.int_hom().map((Q as i32) / 2),
        );
        // u <= A^-1 * r + e1
        let r = self.binomial_random_poly_vec();
        let r_cloned = clone_vec(&r, &self.0).collect();
        let a_inv = transpose(a);
        let e1 = self.binomial_random_poly_vec();
        let u = mat_add_vec(
            reduce_vec(mat_mul_vector(a_inv, r_cloned, &self.0), &self.0),
            e1,
            &self.0,
        );

        // v <= pk * r + e2 + (q/2)*m
        let e2 = self.binomial_random_poly();
        let pk_times_r = reduce_vec(mat_mul_vector(vec![pk], r, &self.0), &self.0)
            .pop()
            .unwrap();
        let v = self.0.add(self.0.add(pk_times_r, e2), q2m);
        (v, u)
    }

    pub fn partial_decrypt(
        &self,
        secret: VecShare<Ring>,
        indexes: &[El<Ring>],
        u: Vec<El<Ring>>,
    ) -> El<Ring> {
        // transform 's' via lagrange
        let t_secret = mul_by_lagrange_vec(secret, indexes, &self.0);
        // h <= s*u + e
        let e = self.binomial_random_poly();
        let s_times_u = reduce_vec(mat_mul_vector(vec![t_secret], u, &self.0), &self.0)
            .pop()
            .unwrap();
        self.0.add(s_times_u, e)
    }

    pub fn assemble_decryptions<I>(&self, v: El<Ring>, hs: I) -> El<Ring>
    where
        I: Iterator<Item = El<Ring>>,
    {
        // v - ((s1 * u + e1) + (s2 * u + e2) + ...)
        let q2m = self
            .0
            .sub(v, hs.fold(self.0.zero(), |acc, h| self.0.add(acc, h)));
        // {<Q/4 || >=3Q/4 , >=Q/4 && <3Q/4} => {0,1}
        self.0.from_terms(
            self.0
                .terms(&q2m)
                .map(|(term, pow)| ((*term >= (Q / 4) && *term < (Q - (Q / 4))) as u64, pow)),
        )
    }
}

fn generate_shares_vec<P, I, G>(
    threshold: i32,
    indexes: &I,
    secret: &Vec<El<P>>,
    random_el: &mut G,
    ring: &P,
) -> Vec<VecShare<P>>
where
    P: RingStore,
    I: Iterator<Item = El<P>> + Clone,
    G: FnMut() -> El<P>,
{
    let n = secret.len();
    let shares: Vec<Vec<_>> = (0..n)
        .map(|i| generate_shares(threshold, indexes.clone(), &secret[i], random_el, &ring))
        .collect();
    transpose(shares)
        .into_iter()
        .enumerate()
        .map(|(_i, v)| {
            let index = ring.clone_el(&v[0].index);
            VecShare {
                shares: v
                    .into_iter()
                    .map(|el| {
                        #[cfg(debug_assertions)]
                        feanor_math::assert_el_eq!(
                            &ring,
                            &el.index,
                            &ring.int_hom().map((_i + 1) as i32)
                        );
                        el.share
                    })
                    .collect(),
                index,
            }
        })
        .collect()
}

#[cfg(test)]
fn interpolate_shares_vec<P>(shares: &[VecShare<P>], ring: &P) -> Vec<El<P>>
where
    P: DivisibilityRingStore,
    P::Type: DivisibilityRing,
{
    transpose(
        // after this iterator, it will be [[1 1 1][2 2 2]...shares]
        shares
            .iter()
            .map(|share| {
                share
                    .shares
                    .iter()
                    .map(|el| assemble_share_ref(el, &share.index, &ring))
                    .collect()
            })
            .collect(),
    )
    // after transposition, will be [[1 2 3 4][1 2 3 4]...]
    .into_iter()
    .map(|el| interpolate_shares_ref(&el, &ring))
    .collect()
}

fn sum_shares_vec<P>(mut shares: Vec<VecShare<P>>, ring: &P) -> VecShare<P>
where
    P: RingStore,
{
    let VecShare {
        shares: first_shares,
        index: first_index,
    } = shares.pop().unwrap();
    debug_assert!(shares.iter().all(|el| ring.eq_el(&el.index, &first_index)));
    VecShare {
        index: first_index,
        shares: shares
            .into_iter()
            .fold(first_shares, |acc, el| mat_add_vec(acc, el.shares, &ring)),
    }
}

fn mul_by_lagrange_vec<P>(shares: VecShare<P>, indexes: &[El<P>], ring: &P) -> Vec<El<P>>
where
    P: DivisibilityRingStore,
    P::Type: DivisibilityRing,
{
    let VecShare { shares, index } = shares;
    shares
        .into_iter()
        .map(|share| crate::shamirs::Share {
            share,
            index: ring.clone_el(&index),
        })
        .map(|s| mul_by_lagrange(s, indexes, ring))
        .collect()
}

fn mat_mul_vector<P>(lhs: Vec<Vec<El<P>>>, rhs: Vec<El<P>>, ring: &P) -> Vec<El<P>>
where
    P: RingStore,
{
    lhs.into_iter()
        .map(|row| {
            row.into_iter()
                .zip(rhs.iter())
                .fold(ring.zero(), |acc, (l, r)| {
                    ring.add(acc, ring.mul_ref_snd(l, r))
                })
        })
        .collect()
}

fn reduce_vec(item: Vec<El<Ring>>, ring: &Ring) -> Vec<El<Ring>> {
    let irr_poly: El<Ring> = ring.from_terms([(1, 0), (1, N)].into_iter());
    // println!("irrpoly: {}", ring.format(&irr_poly));
    item.into_iter()
        .map(|poly| ring.div_rem_monic(poly, &irr_poly).1)
        .collect()
}

fn mat_add_vec<P>(lhs: Vec<El<P>>, rhs: Vec<El<P>>, ring: &P) -> Vec<El<P>>
where
    P: RingStore,
{
    lhs.into_iter()
        .zip(rhs.into_iter())
        .map(|(l, r)| ring.add(l, r))
        .collect()
}

fn transpose<P>(v: Vec<Vec<P>>) -> Vec<Vec<P>> {
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<P>>()
        })
        .collect()
}

fn clone_vec<'a, P>(v: &'a [El<P>], ring: &'a P) -> impl Iterator<Item = El<P>> + 'a
where
    P: RingStore,
{
    v.iter().map(|i| ring.clone_el(&i))
}

#[cfg(test)]
fn print_vec<P>(v: &Vec<El<P>>, ring: &P)
where
    P: RingStore,
{
    print!("[");
    for e in &v[..v.len() - 1] {
        print!("{} , ", ring.format(&e))
    }
    println!("{}]", ring.format(&v[v.len() - 1]));
}

#[test]
fn test_transpose() {
    let a = vec![vec![1, 2, 3], vec![4, 5, 6]];
    let b = transpose(a);
    assert_eq!(b, vec![vec![1, 4], vec![2, 5], vec![3, 6]])
}

#[test]
fn test_compressed_ss_mlwe() {
    for _ in 0..15 {
        test_compressed_ss_mlwe_once()
    }
}

#[test]
fn test_compressed_ss_mlwe_once() {
    const PARTIES: usize = 10;
    let mut secrets = vec![];
    let mut sorted_shares: Vec<_> = (0..PARTIES).map(|_| vec![]).collect();
    for _ in 0..PARTIES {
        let SecretAndShares { secret, shares } = generate_secret_and_shares::<PARTIES>(1);
        secrets.push(secret);
        for (dest, share) in shares {
            sorted_shares[dest as usize - 1].push((dest, share));
        }
    }
    let a_seed: [u8; 32] = rand::rng().random();
    let mut sks = vec![];
    let mut pks = vec![];
    for shares in sorted_shares {
        let Keypair { sk, pk } = generate_keypair::<PARTIES>(shares.try_into().unwrap(), &a_seed);
        sks.push(sk);
        pks.push(pk);
    }

    let pk = pks
        .into_iter()
        .fold([[0; N]; K], |acc, pk| add_public_keys(acc, pk));

    let pt: Plaintext = rand::rng().random();
    let (v, u) = encrypt(&pk, &a_seed, &pt);

    let indexes: Vec<_> = (1..PARTIES as u32 + 1).collect();
    let hs = sks
        .into_iter()
        .map(|sk| partial_decrypt((sk.0, &sk.1), u.clone(), &indexes));

    let plaintext = assemble_decryptions(v, hs);
    assert_eq!(plaintext, pt);
}

#[test]
fn test_plain_ss_mlwe() {
    for _ in 0..15 {
        test_plain_ss_mlwe_once()
    }
}
#[test]
fn test_a_seed() {
    let ring_h = ring();
    let a_seed_1: [u8; 32] = rand::rng().random();
    assert_eq!(
        ring_h.a_from_seed(&a_seed_1.clone()),
        ring_h.a_from_seed(&a_seed_1.clone())
    );
    let a_seed_2: [u8; 32] = rand::rng().random();
    assert_ne!(ring_h.a_from_seed(&a_seed_1), ring_h.a_from_seed(&a_seed_2))
}

#[test]
fn test_plain_ss_mlwe_once() {
    use feanor_math::assert_el_eq;
    const DEBUGPRINT: bool = false;
    let ring_h = ring();
    let ring = ring_h.0.clone();

    let (sk1, shares_1) = ring_h.new_secret_and_shares(1, 3);
    let (sk2, shares_2) = ring_h.new_secret_and_shares(1, 3);
    let (sk3, shares_3) = ring_h.new_secret_and_shares(1, 3);
    if DEBUGPRINT {
        print_vec(&sk1, &ring);
        print_vec(&sk2, &ring);
        print_vec(&sk3, &ring);
    }
    // compute a test, shared sk <= sk1 + sk2 + sk3
    let sk: Vec<Vec<u64>> = [&sk1, &sk2, &sk3]
        .into_iter()
        .map(|e| clone_vec(e, &ring).collect())
        .fold(vec![ring.zero(); K], |acc, i| mat_add_vec(acc, i, &ring));
    if DEBUGPRINT {
        print_vec(&sk, &ring);
    }

    if DEBUGPRINT {
        println!("shares after 1st parties polynomial generation");
        for share in &shares_1 {
            println!("index: {}", ring.format(&share.index));
            for s in &share.shares {
                println!("s: {}", ring.format(s));
            }
        }
    }
    // [[1,2,3], [1,2,3]] -> [[1,1], [2,2], [3,3]]
    // transform array so that it is:
    // all_shares[for_player][by_player][0..K]
    let all_shares = transpose(vec![shares_1, shares_2, shares_3]);

    if DEBUGPRINT {
        println!("shares after transformation");
        for (i, index) in all_shares.iter().enumerate() {
            println!("i: {}", i);
            for j in index {
                println!("index: {}", ring.format(&j.index));
                for s in &j.shares {
                    println!("s: {}", ring.format(s));
                }
            }
        }
    }

    // unwrap the share objects and
    // sum all shares
    let mut sks: Vec<_> = all_shares
        .into_iter()
        // shares for each player
        .map(|shares| ring_h.make_secret_from_shares(shares))
        .collect();

    if DEBUGPRINT {
        println!("sk1, sk2, sk3");
        sks.iter().for_each(|ski| print_vec(&ski.shares, &ring));
    }

    // compute a test, shared sk
    let test_sk = interpolate_shares_vec(&sks, &ring);
    let sk3 = sks.pop().unwrap();
    let sk2 = sks.pop().unwrap();
    let sk1 = sks.pop().unwrap();

    // assert that the sum of the sks equals the lagrange interpolation of the sum of the polynomials
    for i in 0..K {
        assert_el_eq!(&ring, &test_sk[i], &sk[i]);
    }
    if DEBUGPRINT {
        println!("sk:");
        print_vec(&sk, &ring);
    }

    // generate just a single, shared 'A', clone for later use
    let a_seed: [u8; 32] = rand::rng().random();
    let a = ring_h.a_from_seed(&a_seed);
    if DEBUGPRINT {
        println!("A:");
        for i in &a {
            print_vec(&i, &ring);
        }
    }
    let a_ct: Vec<Vec<_>> = a.iter().map(|i| clone_vec(&i, &ring).collect()).collect();

    // each player generates a public key
    let pk1 = ring_h.make_public_key::<3>(&sk1, &a_seed);
    let pk2 = ring_h.make_public_key::<3>(&sk2, &a_seed);
    let pk3 = ring_h.make_public_key::<3>(&sk3, &a_seed);

    if DEBUGPRINT {
        println!("pk1, pk2, pk3");
        [&pk1, &pk2, &pk3]
            .into_iter()
            .for_each(|pki| print_vec(&pki, &ring));
    }

    // final pk is sum of pki's
    let pk = [pk1, pk2, pk3]
        .iter()
        .map(|pki| clone_vec(pki, &ring).collect())
        .fold(vec![ring.zero(); K], |acc, el| mat_add_vec(acc, el, &ring));

    if DEBUGPRINT {
        print!("pk: ");
        print_vec(&pk, &ring);
    }

    // encrypt something!
    let plaintext_vec: Vec<u64> = vec![1; N.div_ceil(2)]
        .into_iter()
        .chain(vec![0; N / 2].into_iter())
        .collect();
    let plaintext = ring_h.make_ring(&plaintext_vec);
    if DEBUGPRINT {
        println!("plaintext: {}", ring.format(&plaintext));
    }

    // generate ciphertext randomness
    let r = ring_h.binomial_random_poly_vec();
    let e1 = ring_h.binomial_random_poly_vec();
    let e2 = ring_h.binomial_random_poly();

    // transpose a
    let a_transpose = transpose(a_ct);

    // calculating A^-1*r+e1 => u
    let u = reduce_vec(
        mat_add_vec(
            mat_mul_vector(a_transpose, clone_vec(&r, &ring).collect(), &ring),
            e1,
            &ring,
        ),
        &ring,
    );

    // m -> (q/2)*m
    let half_q = ring.int_hom().map((Q as i32) / 2);
    let adj_plaintext = ring.mul_ref_snd(half_q, &plaintext);

    // calculating pk*r + e2 + (q/2)*m => v
    let pk_times_r = reduce_vec(mat_mul_vector(vec![pk], r, &ring), &ring)
        .pop()
        .unwrap();
    let v = ring.add(ring.add(pk_times_r, e2), adj_plaintext);

    // decrypt! v - s*u => pt
    let downcast_terms = |r| {
        ring.from_terms(
            ring.terms(&r)
                .map(|(term, pow)| ((*term >= (Q / 4) && *term < (Q - (Q / 4))) as u64, pow)),
        )
    };
    // first, just for testing, try decrypting with just 'sk' from earlier
    let s_times_u = reduce_vec(
        mat_mul_vector(vec![sk], clone_vec(&u, &ring).collect(), &ring),
        &ring,
    )
    .pop()
    .unwrap();
    let pt_test = downcast_terms(ring.sub_ref_fst(&v, s_times_u));
    if DEBUGPRINT {
        ring.println(&pt_test);
    }
    assert_el_eq!(&ring, &pt_test, &plaintext);

    // now try decrypting with actual share sk's
    // v - ((s1*u+e1) + (s2*u+e2) + ...)
    let indexes = (0..3)
        .map(|i| ring.int_hom().map((i + 1) as i32))
        .collect::<Vec<_>>();
    let pt_final = downcast_terms(
        ring.sub(
            v,
            vec![sk1, sk2, sk3]
                .into_iter()
                .map(|ski| ring_h.partial_decrypt(ski, &indexes, clone_vec(&u, &ring).collect()))
                .fold(ring.zero(), |acc, sue| ring.add(acc, sue)),
        ),
    );
    if DEBUGPRINT {
        ring.println(&pt_final);
    }
    assert_el_eq!(&ring, &pt_final, &plaintext);
}

#[test]
fn test_mlwe_once() {
    use feanor_math::default_memory_provider;
    use feanor_math::rings::extension::extension_impl::FreeAlgebraImpl;
    use feanor_math::rings::extension::FreeAlgebraStore;
    use feanor_math::vector::vec_fn::VectorFn;
    let base_ring = Fp::<Q>::RING;
    let x_pow_rank = vec![base_ring.neg_one(); N];
    let ring = FreeAlgebraImpl::new(base_ring, x_pow_rank, default_memory_provider!());

    const DEBUGPRINT: bool = false;
    let mut rng = rand::rng();
    let mut rng2 = rng.clone();
    let mut uniform_random_poly =
        || ring.from_canonical_basis((0..N).map(|_| base_ring.random_element(|| rng.random::<u64>())));
    let mut binomial_random_poly = || {
        let bits_needed = N * ETA * 2;
        let bytes: Vec<u8> = (0..(bits_needed.div_ceil(64)))
            .map(|_| rng2.random::<u64>().to_be_bytes())
            .flatten()
            .collect();
        let bits = bv::BitVec::<_, bv::Msb0>::from_vec(bytes);
        let coeffs = (0..N).map(|i| {
            let x = (0..ETA).fold(0, |x, j| x + (bits[(ETA * i * 2) + j] as i32));
            let y = (0..ETA).fold(0, |y, j| y + (bits[(ETA * i * 2) + ETA + j] as i32));
            base_ring.int_hom().map(x - y)
            // simulate weird cases, remove
            // base_ring.int_hom().map((ETA as i32))
            // base_ring.int_hom().map(0)
            // base_ring.int_hom().map(x - y) * 2
        });
        ring.from_canonical_basis(coeffs)
    };

    println!("generating A");
    let a: Vec<Vec<_>> = (0..K)
        .map(|_| (0..K).map(|_| uniform_random_poly()).collect())
        .collect();
    if DEBUGPRINT {
        for i in &a {
            print_vec(&i, &ring);
        }
    }

    println!("generating s");
    // let s: Vec<_> = (0..K).map(|_| binomial_random_poly()).collect();
    let s: Vec<_> = (0..K)
        .map(|_| ring.mul(ring.int_hom().map(3), binomial_random_poly()))
        .collect();
    // let s: Vec<_> = (0..K).map(|_| uniform_random_poly()).collect();
    // let s: Vec<_> = (0..K)
    //     .map(|_| ring.from_canonical_basis(vec![Q - 1; N].into_iter()))
    //     .collect();
    if DEBUGPRINT {
        print_vec(&s, &ring);
    }

    println!("generating e");
    // let e: Vec<_> = (0..K).map(|_| binomial_random_poly()).collect();
    let e: Vec<_> = (0..K)
        .map(|_| ring.mul(ring.int_hom().map(3), binomial_random_poly()))
        .collect();
    // let e: Vec<_> = (0..K)
    //     .map(|_| ring.from_canonical_basis(vec![Q - 1; N].into_iter()))
    //     .collect();
    if DEBUGPRINT {
        print_vec(&e, &ring);
    }

    println!("calculating A*s+e => pk");
    let clone_a: Vec<Vec<_>> = a.iter().map(|i| clone_vec(&i, &ring).collect()).collect();
    let mut pk = mat_mul_vector(clone_a, clone_vec(&s, &ring).collect(), &ring);
    if DEBUGPRINT {
        print_vec(&pk, &ring);
    }
    pk = mat_add_vec(pk, e, &ring);
    if DEBUGPRINT {
        print_vec(&pk, &ring);
    }

    println!("encrypting!");
    let plaintext_vec: Vec<u8> = vec![1; N.div_ceil(2)]
        .into_iter()
        .chain(vec![0; N / 2].into_iter())
        .collect();
    let plaintext = ring.from_canonical_basis(plaintext_vec.iter().map(|c| *c as u64));

    println!("generating r, e1, e2");
    let r: Vec<_> = (0..K).map(|_| binomial_random_poly()).collect();
    // let r: Vec<_> = (0..K)
    //     .map(|_| ring.from_canonical_basis(vec![Q - 1; N].into_iter()))
    //     .collect();
    let e1: Vec<_> = (0..K).map(|_| binomial_random_poly()).collect();
    // let e1: Vec<_> = (0..K)
    //     .map(|_| ring.from_canonical_basis(vec![1; N].into_iter()))
    //     .collect();
    // let e2 = binomial_random_poly();
    let e2 = ring.mul(ring.int_hom().map(3), binomial_random_poly());
    // let e2 = ring.from_canonical_basis(vec![Q - 1; N].into_iter());
    if DEBUGPRINT {
        print_vec(&r, &ring);
        print_vec(&e1, &ring);
        ring.println(&e2);
    }

    println!("transposing a");
    let clone_a: Vec<Vec<_>> = a.iter().map(|i| clone_vec(&i, &ring).collect()).collect();
    let transpose_a = transpose(clone_a);
    if DEBUGPRINT {
        for i in &transpose_a {
            print_vec(&i, &ring);
        }
    }

    println!("calculating A*r+e1 => u");
    let u = mat_mul_vector(transpose_a, clone_vec(&r, &ring).collect(), &ring);
    if DEBUGPRINT {
        print_vec(&u, &ring);
    }
    let u = mat_add_vec(u, e1, &ring);
    if DEBUGPRINT {
        print_vec(&u, &ring);
    }

    println!("calculating pk*r + e2 + (q/2)*m => v");
    let half_q = ring.int_hom().map((Q as i32) / 2);
    let adj_plaintext = ring.mul(half_q, plaintext);
    let mut v = mat_mul_vector(vec![pk], r, &ring);
    assert_eq!(v.len(), 1);
    let v = v.pop().unwrap();
    let v = ring.add(v, e2);
    let v = ring.add(v, adj_plaintext);
    if DEBUGPRINT {
        ring.println(&v);
    }

    println!("Decrypting! v - s*u => pt");
    let mut pt = mat_mul_vector(vec![s], u, &ring);
    assert_eq!(pt.len(), 1);
    let pt = pt.pop().unwrap();
    let pt = ring.sub(v, pt);
    let pt: Vec<_> = ring.wrt_canonical_basis(&pt).to_vec();
    println!("pt: {:?}", pt);
    let plaintext: Vec<_> = pt
        .iter()
        .map(|coeff| (*coeff > (Q / 4) && *coeff < (Q - Q / 4)) as u8)
        .collect();
    println!("pt: {:?}", plaintext);
    assert_eq!(plaintext, plaintext_vec);
    // return pt;
}
