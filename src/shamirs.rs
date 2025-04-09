use feanor_math::divisibility::{DivisibilityRing, DivisibilityRingStore};
use feanor_math::ring::{El, RingStore};
#[cfg(test)]
use feanor_math::rings::extension::FreeAlgebraStore;

pub struct Share<P: RingStore> {
    pub share: El<P>,
    pub index: El<P>,
}

// |threshold| cannot reconsitute
// |threshold+1| CAN reconstitute
pub fn generate_shares<P, I, G: FnMut() -> El<P>>(
    threshold: i32,
    indexes: I,
    secret: &El<P>,
    random_el: &mut G,
    ring: &P,
) -> Vec<Share<P>>
where
    P: RingStore,
    I: Iterator<Item = El<P>>,
{
    let coeffs: Vec<_> = (0..threshold).map(|_| random_el()).collect();

    // println!("Generating Player Keys...");
    indexes
        .map(|index| {
            debug_assert!(!ring.eq_el(&index, &ring.zero()));
            let mut share = ring.clone_el(secret);
            for power in 1..(threshold + 1) as usize {
                let coeff = ring.clone_el(&coeffs[power - 1]);
                // todo: performance enhancement to feanor-math to allow it to more quickly multiply constants
                share = ring.add(
                    share,
                    ring.mul(coeff, ring.pow(ring.clone_el(&index), power)),
                );
            }
            // println!("key {}: {}", player, ring.format(&share));
            Share { share, index }
        })
        .collect()
}

pub fn mul_by_lagrange<P>(share: Share<P>, indexes: &[El<P>], ring: &P) -> El<P>
where
    P: DivisibilityRingStore,
    P::Type: DivisibilityRing,
{
    let Share { index, share } = share;
    indexes
        .iter()
        .filter(|i| !ring.eq_el(*i, &index))
        .map(|i| ring.mul_ref_fst(i, ring.invert(&ring.sub_ref(i, &index)).unwrap()))
        .fold(share, |acc, lag| ring.mul(acc, lag))
}

#[cfg(test)]
pub fn interpolate_shares_ref<P>(shares: &[Share<P>], ring: &P) -> El<P>
where
    P: DivisibilityRingStore,
    P::Type: DivisibilityRing,
{
    let indexes: Vec<_> = shares
        .iter()
        .map(|share| ring.clone_el(&share.index))
        .collect();
    ring.sum(shares.iter().map(|share| {
        mul_by_lagrange(
            assemble_share_ref(&share.share, &share.index, &ring),
            &indexes,
            &ring,
        )
    }))
}

#[cfg(test)]
pub fn assemble_share_ref<P>(share: &El<P>, index: &El<P>, ring: &P) -> Share<P>
where
    P: RingStore,
{
    Share {
        share: ring.clone_el(share),
        index: ring.clone_el(index),
    }
}

#[test]
fn test_generate_shares() {
    use feanor_math::assert_el_eq;
    use feanor_math::homomorphism::Homomorphism;
    use feanor_math::ring::RingStore;
    use feanor_math::rings::finite::FiniteRingStore;
    use feanor_math::rings::poly::PolyRingStore;
    use feanor_math::rings::zn::zn_static::Fp;
    const ELEMENTS: usize = 256;
    let base_ring = Fp::<3329>::RING;
    // let x_pow_rank = vec![base_ring.neg_one(); ELEMENTS];
    // let ring = feanor_math::rings::extension::extension_impl::FreeAlgebraImpl::new(base_ring, x_pow_rank, default_memory_provider!());
    let ring = feanor_math::rings::poly::dense_poly::DensePolyRing::new(base_ring, "x");
    let mut random_secret = || {
        let can_secret: Vec<_> = (0..ELEMENTS)
            .map(|_| base_ring.random_element(rand::random::<u64>))
            .collect();
        // ring.from_canonical_basis(can_secret.into_iter())
        ring.from_terms(can_secret.into_iter().enumerate().map(|(i, x)| (x, i)))
    };
    let secret = random_secret();
    let indexes = (1..6).map(|i| ring.int_hom().map(i));
    // println!("secret: {}", ring.format(&secret));
    let shares = generate_shares(2, indexes, &secret, &mut random_secret, &ring);
    // for s in &shares {
    //     println!("share: {}", ring.format(&s.share));
    // }

    let new_secret = interpolate_shares_ref(&shares[2..5], &ring);
    assert_el_eq!(&ring, &secret, &new_secret);
}

#[test]
fn test_z256x32() {
    use feanor_math::assert_el_eq;
    use feanor_math::homomorphism::Homomorphism;
    use feanor_math::ring::RingStore;
    use feanor_math::rings::extension::FreeAlgebraStore;
    use feanor_math::rings::finite::FiniteRingStore;
    use feanor_math::rings::zn::zn_static::Zn;
    const ELEMENTS: usize = 16;
    let base_ring = Zn::<256>::RING;
    let x_pow_rank = vec![base_ring.neg_one(); ELEMENTS];
    let ring = feanor_math::rings::extension::extension_impl::FreeAlgebraImpl::new(
        base_ring,
        ELEMENTS,
        x_pow_rank
    );
    // let ring = feanor_math::rings::poly::dense_poly::DensePolyRing::new(base_ring, "x");
    let mut random_secret = || {
        let can_secret: Vec<_> = (0..ELEMENTS)
            .map(|_| base_ring.random_element(rand::random::<u64>))
            .collect();
        ring.from_canonical_basis(can_secret.into_iter())
        // ring.from_terms(can_secret.into_iter().enumerate().map(|(i,x)| (x,i)))
    };
    let secret = random_secret();
    let indexes = (1..6).map(|i| {
        ring.from_canonical_basis({
            let mut el = vec![0; ELEMENTS];
            el[i] = 1;
            el.into_iter().map(|i| base_ring.int_hom().map(i))
        })
    });
    println!("secret: {}", ring.format(&secret));
    let shares = generate_shares(2, indexes, &secret, &mut random_secret, &ring);
    for s in &shares {
        println!(
            "share ({}):\n ({})",
            ring.format(&s.index),
            ring.format(&s.share)
        );
    }
    println!("Combining!");
    let new_secret = interpolate_shares_ref(&shares[2..5], &ring);
    println!("new secret: {}", ring.format(&new_secret));
    assert_el_eq!(&ring, &secret, &new_secret);
}

#[test]
fn test_mpc() {
    use feanor_math::assert_el_eq;
    use feanor_math::homomorphism::Homomorphism;
    use feanor_math::ring::RingStore;
    use feanor_math::rings::finite::FiniteRingStore;
    use feanor_math::rings::poly::PolyRingStore;
    use feanor_math::rings::zn::zn_static::Fp;
    const ELEMENTS: usize = 3;
    let base_ring = Fp::<3329>::RING;
    let ring = feanor_math::rings::poly::dense_poly::DensePolyRing::new(base_ring, "x");
    let random_secret = || {
        let can_secret: Vec<_> = (0..ELEMENTS)
            .map(|_| base_ring.random_element(rand::random::<u64>))
            .collect();
        ring.from_terms(can_secret.into_iter().enumerate().map(|(i, x)| (x, i)))
    };
    let indexes = || (1..6).map(|i| ring.int_hom().map(i));
    let shares: Vec<_> = (0..5)
        .map(|_| random_secret())
        .map(|secret| {
            ring.println(&secret);
            secret
        })
        .map(|secret| generate_shares(2, indexes(), &secret, &mut random_secret.clone(), &ring))
        .collect();

    fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
        assert!(!v.is_empty());
        let len = v[0].len();
        let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
        (0..len)
            .map(|_| {
                iters
                    .iter_mut()
                    .map(|n| n.next().unwrap())
                    .collect::<Vec<T>>()
            })
            .collect()
    }

    let sent_shares = transpose(shares);

    let individual_shares: Vec<_> = sent_shares
        .into_iter()
        .map(|shares| {
            let index = ring.clone_el(&shares[0].index);
            assert!(shares.iter().all(|share| ring.eq_el(&index, &share.index)));
            println!("Player {}:", ring.format(&index));
            for share in shares.iter() {
                println!("  {}", ring.format(&share.share));
            }
            let share = ring.sum(shares.iter().map(|share| ring.clone_el(&share.share)));
            println!(" share: {}", ring.format(&share));
            Share { share, index }
        })
        .collect();

    println!("Combining!");
    let perm1 = interpolate_shares_ref(&individual_shares[0..3], &ring);
    let perm2 = interpolate_shares_ref(&individual_shares[1..4], &ring);
    let perm3 = interpolate_shares_ref(&individual_shares[2..5], &ring);
    assert_el_eq!(&ring, &perm1, &perm2);
    assert_el_eq!(&ring, &perm1, &perm3);
    println!("secret: {}", ring.format(&perm1));
}

#[test]
fn test_aes() {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes128;
    use feanor_math::homomorphism::Homomorphism;
    use feanor_math::rings::zn::zn_static::Zn;
    use feanor_math::seq::VectorFn;
    use rand::Rng;

    const ELEMENTS: usize = 16;
    let base_ring = Zn::<256>::RING;

    let mut rng = rand::rng();
    let mut rand_bytes = |num_bytes| {
        assert_eq!(num_bytes % 8, 0);
        let mut bytes = vec![];
        for _ in 0..num_bytes / 8 {
            bytes.extend_from_slice(&rng.random::<u64>().to_ne_bytes())
        }
        bytes
    };

    let x_pow_rank = vec![base_ring.neg_one(); ELEMENTS];
    let ring = feanor_math::rings::extension::extension_impl::FreeAlgebraImpl::new(
        base_ring,
        ELEMENTS,
        x_pow_rank,
    );

    // let random_secret = || {
    //     let can_secret: Vec<_> = (0..ELEMENTS)
    //         .map(|_| base_ring.random_element(rand::random::<u64>))
    //         .collect();
    //     ring.from_terms(can_secret.into_iter().enumerate().map(|(i, x)| (x, i)))
    // };
    let main_key: [u8; ELEMENTS] = rand_bytes(ELEMENTS).try_into().unwrap();
    println!("main_key: {:?}", main_key);
    let cipher = Aes128::new((&main_key).into());
    let main_key_poly = ring.from_canonical_basis(main_key.iter().map(|i| *i as u64));
    println!("main_key_poly: {}", ring.format(&main_key_poly));

    let indexes = (1..6).map(|i| {
        ring.from_canonical_basis({
            let mut el = vec![0; ELEMENTS];
            el[i] = 1;
            el.into_iter().map(|i| base_ring.int_hom().map(i))
        })
    });

    let mut random_poly =
        || ring.from_canonical_basis(rand_bytes(ELEMENTS).iter().map(|i| *i as u64));
    let shares = generate_shares(2, indexes, &main_key_poly, &mut random_poly, &ring);
    for s in &shares {
        println!(
            "share {}:\n  {}",
            ring.format(&s.index),
            ring.format(&s.share)
        )
    }

    let orig_data = rand_bytes(ELEMENTS);
    println!("plaintext: {:?}", orig_data);
    let mut block = GenericArray::clone_from_slice(&orig_data);
    cipher.encrypt_block(&mut block);

    let partial_decryptions: Vec<_> = shares
        .into_iter()
        .map(|mut share| {
            // convert y-coordinate of share to a key to be used in AES
            let share_vec: Vec<u8> = ring
                .wrt_canonical_basis(&share.share)
                .iter()
                .collect::<Vec<u64>>()
                .into_iter()
                .map(|i| i.try_into().unwrap())
                .collect();
            assert_eq!(share_vec.len(), ELEMENTS);
            let share_cipher = Aes128::new(&GenericArray::clone_from_slice(&share_vec));
            let mut share_block = block.clone();

            // partially decrypt ciphertext with key
            share_cipher.decrypt_block(&mut share_block);

            // convert partially decrypted ciphertext into new polynomial
            let y_coord = ring.from_canonical_basis(
                share_block
                    .into_iter()
                    .map(|i| i as u64)
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            // Share {
            //     share: ring.clone_el(&y_coord),
            //     index: ring.clone_el(&share.index),
            // }
            share.share = y_coord;
            share
        })
        .collect();

    let combined_data = interpolate_shares_ref(&partial_decryptions[0..3], &ring);
    println!("combined: {}", ring.format(&combined_data));

    cipher.decrypt_block(&mut block);
    println!("decrypted data: {:?}", block);

    // this will never pass, because AES results are not homomorphic like that
    //assert_eq!(block.to_vec(), orig_data);
}
