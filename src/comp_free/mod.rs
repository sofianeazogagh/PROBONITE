pub mod clear;
pub mod ctree;
pub mod dataset;
pub mod forest;
pub mod serial;
pub mod tree;

use std::time::Instant;

const DEBUG: bool = false;
const OBLIVIOUS: bool = false;

use revolut::key;
use revolut::radix::NyblByteLUT;
// use revolut::{key, Context, PublicKey};
// REVOLUT
pub use revolut::{radix::ByteLWE, Context, PrivateKey, PublicKey, LUT, LWE};

// TFHE
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;

// type LWE = LweCiphertext<Vec<u64>>;
type RLWE = GlweCiphertext<Vec<u64>>;

trait Majority {
    fn blind_count_extra(&self, lwes: &[LWE], ctx: &Context, n_classes: u64) -> Vec<ByteLWE>;
    fn blind_majority_extra(&self, lwes: &[LWE], ctx: &Context, n_classes: u64) -> LWE;
    fn blind_majority_extra_index(
        &self,
        lwes: &[LWE],
        ctx: &Context,
        n_classes: u64,
        i: u64,
    ) -> LWE;
}

impl Majority for PublicKey {
    /// Count the number of occurences of more than p LWEs
    /// Cost : n * (5 br + 2 ks)
    fn blind_count_extra(&self, lwes: &[LWE], ctx: &Context, n_classes: u64) -> Vec<ByteLWE> {
        let mut count = NyblByteLUT::from_bytes_trivially(&[0u8; 16], ctx);
        for lwe in lwes {
            // 5 br + 2 ks
            count.blind_array_inc(&lwe, ctx, self);
        }
        count.to_many_blwes(self, ctx)[..n_classes as usize].to_vec()
    }

    /// Blind Majority of more than p LWEs
    fn blind_majority_extra(&self, lwes: &[LWE], ctx: &Context, n_classes: u64) -> LWE {
        let start = Instant::now();
        let count = self.blind_count_extra(lwes, ctx, n_classes);
        let duration = start.elapsed();
        println!("[TIME] Blind count: {:?}", duration);

        let start = Instant::now();
        let maj = self.blind_argmax_blwe_lwe(&count, ctx);
        let duration = start.elapsed();
        println!("[TIME] Blind argmax: {:?}", duration);
        maj
    }

    /// Blind Majority of more than p LWEs
    /// n * (5 br + 2 ks) + (n-1) * (11 br + 8KS + 3pKS)
    fn blind_majority_extra_index(
        &self,
        lwes: &[LWE],
        ctx: &Context,
        n_classes: u64,
        i: u64,
    ) -> LWE {
        // n * (5 br + 2 ks)
        let count = self.blind_count_extra(lwes, ctx, n_classes);
        // (n-1)*(11 br + 8KS + 3pKS)
        let maj = self.blind_argmax_blwe_lwe(&count, ctx);
        maj
    }
}

mod tests {
    use std::time::Instant;

    use revolut::key;

    use super::*;

    #[test]
    fn test_blind_majority_extra() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters());
        let public_key = &private_key.public_key;
        let p = ctx.full_message_modulus() as usize;
        let mut vec = (0..64)
            .map(|_| rand::random::<usize>() % p)
            .collect::<Vec<_>>();

        println!("vec: {:?}", vec);

        let expected = {
            // Clear count
            let mut counts = std::collections::HashMap::new();
            for &value in &vec {
                *counts.entry(value).or_insert(0) += 1;
            }

            // Clear Argmax
            counts
                .into_iter()
                .max_by_key(|&(_, count)| count)
                .map(|(value, _)| value)
                .unwrap()
        };

        // Encrypt
        let lwes = vec
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x as u64, &mut ctx))
            .collect::<Vec<_>>();

        // Blind majority
        let start = Instant::now();
        let maj = public_key.blind_majority_extra_index(&lwes, &ctx, p as u64, 0);
        let end = Instant::now();
        println!(
            "time taken for blind majority: {:?}",
            end.duration_since(start)
        );

        // Decrypt
        let actual = private_key.decrypt_lwe(&maj, &ctx);
        println!("maj: {}", actual);
        assert_eq!(actual, expected as u64);
    }
}
