use std::time::Instant;

mod probonite;
use probonite::*;

mod model;
use model::*;

use revolut::{key, Context};
use tfhe::shortint::parameters::*;

const GENERATE_TREE: bool = true;

fn main() {
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = key(ctx.parameters());
    let public_key = &private_key.public_key;
    let p = ctx.full_message_modulus() as u64;

    let mut tree: Tree;
    // let tree_depth = 3;
    let n_classes = 2;

    for tree_depth in [3,7,5,10,13,16].iter() {
        println!("Tree depth: {}", *tree_depth);
        println!("--------------------------------");
        if GENERATE_TREE {
            tree = Tree::generate_random_tree(*tree_depth, n_classes, &ctx);
            tree.save_to_file(
                &format!("random_trees/exp/random_tree_{}_{}.json", *tree_depth, n_classes),
            );
        } else {
            tree = Tree::load_from_file(
                &format!("random_trees/exp/random_tree_{}_{}.json", *tree_depth, n_classes),
            )
            .unwrap();
        }

        let feature_vector: Vec<u64> = (0..p)
            .map(|_| rand::random::<u64>() % p)
            .collect();

        let query = Query::make_query(&feature_vector, &private_key, &mut ctx);

        let start = Instant::now();
        let predicted_class = probonite(&mut tree, &query, &public_key, &ctx);
        let end = Instant::now();
        println!("[TIME]: {:?}", end.duration_since(start));
        let predicted_class = private_key.decrypt_lwe(&predicted_class, &ctx);
        println!("Predicted class: {}", predicted_class);
        tree.print_tree();
    }
}
