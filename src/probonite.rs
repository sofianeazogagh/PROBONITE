use std::time::Instant;

// TFHE
use tfhe::core_crypto::prelude::*;

// REVOLUT
use revolut::*;

// PARALLELIZATION
use rayon::prelude::*;

type LWE = LweCiphertext<Vec<u64>>;

use crate::model::*;

const DEBUG: bool = false;
const THREADS: usize = 6; // Nombre de threads pour la parallélisation

pub struct Query {
    features: LUT,
}

impl Query {
    pub fn make_query(
        feature_vector: &Vec<u64>,
        private_key: &PrivateKey,
        ctx: &mut Context,
    ) -> Self {
        let feature_lut = LUT::from_vec(feature_vector, private_key, ctx);
        Self {
            features: feature_lut,
        }
    }
}

pub fn next_accumulators(
    accumulators: &Vec<LWE>,
    selector_bit: &LWE,
    public_key: &PublicKey,
    ctx: &Context,
    pool: &rayon::ThreadPool,
) -> Vec<LWE> {
    let not_selector_bit = public_key.not_lwe(selector_bit, ctx);
    let nexts_accumulators: Vec<LWE> = pool.install(|| {
        accumulators
            .par_iter()
            .flat_map(|lwe| {
                let accumulator_left = public_key.lwe_mul_encrypted_bit(lwe, &not_selector_bit, ctx);
                let accumulator_right = public_key.lwe_mul_encrypted_bit(lwe, selector_bit, ctx);
                vec![accumulator_left, accumulator_right]
            })
            .collect()
    });

    nexts_accumulators
}

pub fn blind_node_selection(
    nodes: &Vec<InternalNode>,
    accumulators: &Vec<LWE>,
    public_key: &PublicKey,
    ctx: &Context,
    pool: &rayon::ThreadPool,
) -> (LWE, LWE) {
    let (thresholds, feature_indices): (Vec<u64>, Vec<u64>) = pool.install(|| {
        nodes
            .par_iter()
            .map(|node| (node.threshold, node.feature_index))
            .unzip()
    });
    
    let selected_threshold = public_key.private_selection(&thresholds, accumulators, ctx);
    let selected_feature_index = public_key.private_selection(&feature_indices, accumulators, ctx);

    (selected_threshold, selected_feature_index)
}

pub fn blind_leaf_selection(
    leaves: &Vec<Leaf>,
    accumulators: &Vec<LWE>,
    public_key: &PublicKey,
    ctx: &Context,
    pool: &rayon::ThreadPool,
) -> LWE {
    let leaves_labels: Vec<u64> = pool.install(|| {
        leaves.par_iter().map(|leaf| leaf.label).collect()
    });
    let selected_leaf = public_key.private_selection(&leaves_labels, accumulators, ctx);
    selected_leaf
}

pub fn probonite(tree: &Tree, query: &Query, public_key: &PublicKey, ctx: &Context) -> LWE{
    // Configurer le pool de threads rayon avec THREADS
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .unwrap();
    
    // First stage

    
    let index = tree.root.feature_index;
    let threshold = tree.root.threshold;
    let start = Instant::now();
    let feature = public_key.lut_extract(&query.features, index as usize, ctx);
    let b = public_key.leq_scalar(&feature, threshold, ctx);
    let not_b = public_key.not_lwe(&b, ctx);
    let end = Instant::now();
    println!("First stage: {:?}", end.duration_since(start));
    let mut accumulators = vec![b, not_b];
    
    // Internal Stages
    for i in 0..tree.nodes.len() {
        let start = Instant::now();
        let (threshold, feature_index) =
            blind_node_selection(&tree.nodes[i], &accumulators, public_key, ctx, &pool);

        if DEBUG {
            let private_key = key(ctx.parameters());
            let t_selected = private_key.decrypt_lwe(&threshold, ctx);
            let f_selected = private_key.decrypt_lwe(&feature_index, ctx);
            println!("selected:({t_selected}, {f_selected})");
        }

        let feature = public_key.blind_array_access(&feature_index, &query.features, ctx);
        let b = public_key.blind_lt_bma_mv(&threshold, &feature, ctx);
        accumulators = next_accumulators(&accumulators, &b, public_key, ctx, &pool);
        let end = Instant::now();
        println!("Internal stage {}: {:?}", i, end.duration_since(start));
    }

    // Last stage : increment the leaves and get the majority class through argmax
    let start = Instant::now();
    let selected_leaf = blind_leaf_selection(&tree.leaves, &accumulators, public_key, ctx, &pool);
    let end = Instant::now();
    println!("Last stage: {:?}", end.duration_since(start));
    selected_leaf
}
