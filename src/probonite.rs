// use rand::seq::index;
use rand::{thread_rng, Rng};
use rayon::prelude::*;

use tfhe::shortint::parameters::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::Accumulator;

#[allow(dead_code)]
use std::time::Instant;

pub fn probonite_one_stage(
    sks: ServerKey,
    ct_node: (Ciphertext, Ciphertext),
    lut: &Accumulator,
    ct_parent_acc: Vec<Ciphertext>,
    next_stage: Vec<(u8, u8)>,
    cks: ClientKey,
) -> ((Ciphertext, Ciphertext), Vec<Ciphertext>) {
    let stage = (next_stage.len() as f64).log2();
    println!(
        "---------- STAGE {} to {} ----------",
        stage as usize - 1,
        stage
    );

    let mut ct_one = sks.create_trivial(1);

    let ct_index_feature = ct_node.0;
    let mut ct_theta = ct_node.1;

    // BAAcc
    let mut ct_feat = sks.keyswitch_programmable_bootstrap(&ct_index_feature, lut);

    // CMP
    let start_cmp = Instant::now();
    let mut ct_cp = sks.smart_greater_or_equal(&mut ct_feat, &mut ct_theta);
    let duration_cmp = start_cmp.elapsed();
    println!("TIME CMP : {:?}", duration_cmp);
    let not_ct_cp = sks.smart_sub(&mut ct_one, &mut ct_cp);

    //AccAgg
    let mut ct_childs_acc: Vec<_> = ct_parent_acc
        .par_iter()
        .flat_map(|ct_acc| {
            let ct_child_left = sks.smart_mul_lsb(&mut ct_acc.clone(), &mut ct_cp.clone());
            let ct_child_right = sks.smart_mul_lsb(&mut ct_acc.clone(), &mut not_ct_cp.clone());

            vec![ct_child_left, ct_child_right]
        })
        .collect();

    ///////// BNS

    //Absorb the nodes

    let mut ct_thetas: Vec<_> = ct_childs_acc
        .par_iter_mut()
        .enumerate()
        .map(|(i, ct_acc)| sks.smart_scalar_mul(ct_acc, next_stage[i].1))
        .collect();

    let mut ct_indexs: Vec<_> = ct_childs_acc
        .par_iter_mut()
        .enumerate()
        .map(|(i, ct_acc)| sks.smart_scalar_mul(ct_acc, next_stage[i].0))
        .collect();

    let mut ct_next_theta = ct_thetas[0].clone();
    for i in 1..ct_thetas.len() {
        ct_next_theta = sks.smart_add(&mut ct_next_theta, &mut ct_thetas[i]);
    }

    let mut ct_next_index = ct_indexs[0].clone();
    for i in 1..ct_thetas.len() {
        ct_next_index = sks.smart_add(&mut ct_next_index, &mut ct_indexs[i]);
    }

    let output_theta = cks.decrypt(&ct_next_theta);
    let output_index = cks.decrypt(&ct_next_index);

    println!("Index {} ; Theta {}", output_index, output_theta);
    let ct_res = (ct_next_index, ct_next_theta);
    return (ct_res, ct_childs_acc);
}

fn features(x: u64) -> u64 {
    let vector: Vec<u64> = (0..32).collect();
    let result = vector.get(x as usize);

    return match result {
        Some(result) => *result,
        None => 0,
    };
}

#[allow(dead_code)]
fn random_numbers_up_to_n(n: u64, num_elements: u64) -> Vec<u64> {
    let mut rng = thread_rng();
    (0..num_elements).map(|_| rng.gen_range(0..=n)).collect()
}

#[allow(dead_code)]
fn cast_to_u8(v: Vec<u64>) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}

pub fn probonite_first_stage(
    sks: ServerKey,
    node: (u8, u8),
    lut: &Accumulator,
    next_stage: Vec<(u8, u8)>,
    cks: ClientKey,
) -> ((Ciphertext, Ciphertext), Vec<Ciphertext>) {
    let stage = (next_stage.len() as f64).log2();
    println!(
        "---------- STAGE {} to {} ----------",
        stage as usize - 1,
        stage
    );

    let index_feat = node.0;
    let theta = node.1;

    //BAAcc
    let trivial_index = sks.create_trivial(index_feat as u64);
    let mut ct_feat = sks.keyswitch_programmable_bootstrap(&trivial_index, lut);

    //CMP
    let mut ct_theta = sks.create_trivial(theta as u64);
    let mut ct_cp = sks.smart_greater(&mut ct_feat, &mut ct_theta);

    //ACCAgg
    let mut ct_one = sks.create_trivial(1);
    let not_ct_cp = sks.smart_sub(&mut ct_one, &mut ct_cp);

    let mut ct_childs_acc = vec![ct_cp, not_ct_cp];

    // BNS
    //Absorption in parallel
    let ct_thetas: Vec<_> = ct_childs_acc
        .par_iter_mut()
        .enumerate()
        .map(|(i, ct_acc)| sks.smart_scalar_mul(ct_acc, next_stage[i].1))
        .collect();

    let ct_index: Vec<_> = ct_childs_acc
        .par_iter_mut()
        .enumerate()
        .map(|(i, ct_acc)| sks.smart_scalar_mul(ct_acc, next_stage[i].0))
        .collect();

    //Sum not in place
    let mut ct_theta_0 = ct_thetas[0].clone();
    let mut ct_index_0 = ct_index[0].clone();
    let mut ct_theta_1 = ct_thetas[1].clone();
    let mut ct_index_1 = ct_index[1].clone();
    let ct_theta = sks.smart_add(&mut ct_theta_0, &mut ct_theta_1);
    let ct_index = sks.smart_add(&mut ct_index_0, &mut ct_index_1);

    let output_index = cks.decrypt(&ct_index);
    let output_theta = cks.decrypt(&ct_theta);
    println!("Index {} ; Theta {}", output_index, output_theta);

    let ct_res = (ct_theta, ct_index);

    return (ct_res, ct_childs_acc);
}

fn build_decision_tree(depth: usize, p: u8) -> Vec<Vec<(u8, u8)>> {
    let mut rng = rand::thread_rng();
    let mut tree = vec![vec![(rng.gen_range(0..=p), rng.gen_range(0..=p))]];

    for _ in 1..depth {
        let mut new_level = Vec::new();
        let last_level_nodes = tree.last().unwrap();

        for _ in 0..(last_level_nodes.len() * 2) {
            new_level.push((rng.gen_range(0..=p), rng.gen_range(0..=p)));
        }

        tree.push(new_level);
    }

    tree
}

#[allow(dead_code)]
fn print_decision_tree(tree: &[Vec<(u8, u8)>]) {
    for (level, nodes) in tree.iter().enumerate() {
        println!("Level {}: ", level + 1);
        for (index, &(left, right)) in nodes.iter().enumerate() {
            println!("Node {}: Left: {}, Right: {}", index + 1, left, right);
        }
    }
}

fn choose_parameter(p: u8) -> Parameters {
    match p {
        2 => PARAM_MESSAGE_2_CARRY_2,
        3 => PARAM_MESSAGE_3_CARRY_3,
        4 => PARAM_MESSAGE_4_CARRY_4,
        _ => panic!("Invalid parameter"),
    }
}

pub fn probonite(d: usize, p: u8) {
    // We choose the parameters for the scheme:
    let parameters = choose_parameter(p);
    let (cks, sks) = gen_keys(parameters);
    let lut = sks.generate_accumulator(|x| features(x));

    println!("Generated accumulator");
    let tree = build_decision_tree(d + 1, cks.parameters.message_modulus.0 as u8 - 1);

    // print_decision_tree(&tree);

    let mut ct_res: (Ciphertext, Ciphertext);
    let mut ct_acc: Vec<Ciphertext>;

    let start_probonite = Instant::now();

    (ct_res, ct_acc) =
        probonite_first_stage(sks.clone(), tree[0][0], &lut, tree[1].clone(), cks.clone());

    println!("FRST STAGE DONE !");

    for i in 2..d + 1 {
        //tree.len() à la place de depth
        (ct_res, ct_acc) = probonite_one_stage(
            sks.clone(),
            ct_res,
            &lut,
            ct_acc,
            tree[i].clone(),
            cks.clone(),
        );
    }

    let duration_probonite = start_probonite.elapsed();
    println!("TIME PROBONITE : {:?}", duration_probonite);

    let ct_index = ct_res.0;
    let ct_theta = ct_res.1;

    let output_index = cks.decrypt(&ct_index);
    let output_theta = cks.decrypt(&ct_theta);

    println!(
        "Prediction : Index {} ; Theta {}",
        output_index, output_theta
    );
}
