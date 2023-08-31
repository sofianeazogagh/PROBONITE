// use rand::seq::index;
use rayon::prelude::*;
use rand::{thread_rng, Rng};

use tfhe::shortint::parameters::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::Accumulator;

// #[allow(dead_code)]
// use std::time::Duration;
#[allow(dead_code)]
use std::time::{Instant};



pub fn probonite_one_stage(sks : ServerKey,
    ct_node : (Ciphertext,Ciphertext),
    lut : &Accumulator,
    ct_parent_acc : Vec<Ciphertext>,
    next_stage : Vec<(u8,u8)>,
    cks : ClientKey
)
-> ((Ciphertext,Ciphertext),Vec<Ciphertext>)
{

    let stage = (next_stage.len() as f64).log2();
    println!("---------- STAGE {} to {} ----------", stage as usize - 1,stage);

    let ct_one = sks.create_trivial(1);

    let start_stage = Instant::now();


    let start_baacc = Instant::now();
    let ct_index_feature = ct_node.0;
    let mut ct_theta = ct_node.1;

    // BAAcc
    let mut ct_feat = sks.keyswitch_programmable_bootstrap(&ct_index_feature, lut);
    let duration_baacc = start_baacc.elapsed();
    println!("Temps d'execution BAACC: {:?}",duration_baacc);

    // let mut output = cks.decrypt(&ct_feat);
    // println!("ct_feat {}", output);

    // CMP
    let start_cmp = Instant::now();
    let ct_cp = sks.unchecked_greater_or_equal( &mut ct_feat, &mut ct_theta );
    let duration_cmp = start_cmp.elapsed();
    println!("Temps d'exécution CP: {:?}", duration_cmp);
    // output = cks.decrypt(&ct_cp);
    // println!("ct_cp {}", output);

    let not_ct_cp = sks.unchecked_sub(&ct_one, &ct_cp);
    // output = cks.decrypt(&not_ct_cp);
    // println!("not_ct_cp {}", output);


    //AccAgg
    let start_acc_agg = Instant::now();

    let mut ct_childs_acc: Vec<_> = ct_parent_acc
    .par_iter()
    .flat_map(|ct_acc| {
        let ct_child_left = sks.unchecked_mul_lsb(&mut ct_acc.clone(), &mut ct_cp.clone());
        let ct_child_right = sks.unchecked_mul_lsb(&mut ct_acc.clone(), &mut not_ct_cp.clone());
        // let output1 = cks.decrypt(&(ct_child_left.clone()));
        // let output2 = cks.decrypt(&(ct_child_right.clone()));
        // println!("ct_child_left = {} \nct_child_right = {}",output1,output2);
        vec![ct_child_left, ct_child_right]
    })
    .collect();



    let duration_acc_agg = start_acc_agg.elapsed();
    println!("Temps d'exécution AccAgg : {:?}", duration_acc_agg);

    ///////// BNS

    //Absorb the nodes

    let start_bns = Instant::now();

    let start_abs = Instant::now();

    

    let mut ct_thetas: Vec<_> = ct_childs_acc
    .par_iter_mut()
    .enumerate()
    .map(|(i, ct_acc)| sks.unchecked_scalar_mul(ct_acc, next_stage[i].1))
    .collect();

    let mut ct_indexs: Vec<_> = ct_childs_acc
    .par_iter_mut()
    .enumerate()
    .map(|(i, ct_acc)| sks.unchecked_scalar_mul(ct_acc, next_stage[i].0))
    .collect();


    let duration_abs = start_abs.elapsed();
    println!("Temps d'exécution ABS thresholds : {:?}", duration_abs);

    // // Sum the absorbed nodes
    let start_sum_in_place = Instant::now();

    let mut ct_next_theta = ct_thetas[0].clone();
    for i in 1..ct_thetas.len()
    {
        ct_next_theta = sks.unchecked_add(&mut ct_next_theta, &mut ct_thetas[i]);
    }

    let mut ct_next_index = ct_indexs[0].clone();
    for i in 1..ct_thetas.len()
    {
        ct_next_index = sks.unchecked_add(&mut ct_next_index, &mut ct_indexs[i]);
    }

    let duration_sum_in_place = start_sum_in_place.elapsed();
    println!("Temps d'éxecution Sum in Place : {:?}",duration_sum_in_place);

    let duration_bns = start_bns.elapsed();
    println!("Temps d'exécution BNS: {:?}", duration_bns);

    let duration_third_stage = start_stage.elapsed();
    println!("Temps d'exécution stage: {:?}", duration_third_stage);

    let output_theta = cks.decrypt(&ct_next_theta);
    let output_index = cks.decrypt(&ct_next_index);

    println!("Index {} ; Theta {}", output_index, output_theta);
    let ct_res = (ct_next_index,ct_next_theta);
    return (ct_res, ct_childs_acc);


}


fn features(x:u64)->u64{

    let vector:Vec<u64> = (0..32).collect();
    let result = vector.get(x as usize);

    return match result {
        Some(result) => *result,
        None => 0,
    }

}

#[allow(dead_code)]
fn random_numbers_up_to_n(n: u64, num_elements: u64) -> Vec<u64> {
    let mut rng = thread_rng();
    (0..num_elements)
        .map(|_| rng.gen_range(0..=n))
        .collect()
}


#[allow(dead_code)]
fn cast_to_u8(v: Vec<u64>) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}



pub fn probonite_first_stage(sks: ServerKey,
    node : (u8,u8),
    lut : &Accumulator,
    next_stage : Vec<(u8,u8)>,
    cks : ClientKey)
-> ((Ciphertext,Ciphertext), Vec<Ciphertext>)
{


    let stage = (next_stage.len() as f64).log2();
    println!("---------- STAGE {} to {} ----------", stage as usize - 1,stage);


    let index_feat = node.0;
    let theta = node.1;

    //BAAcc
    let trivial_index = sks.create_trivial(index_feat as u64);
    let ct_feat = sks.keyswitch_programmable_bootstrap(&trivial_index, lut);

    //CMP entre feature[index_feature] et theta chiffré
    let ct_theta = sks.create_trivial(theta as u64);
    let ct_cp = sks.unchecked_greater(&ct_feat, &ct_theta);
    

    //ACCAgg
    let ct_one = sks.create_trivial(1);
    let not_ct_cp = sks.unchecked_sub(&ct_one, &ct_cp);

    let mut ct_childs_acc = vec![ct_cp,not_ct_cp];


    // BNS
    //Absorption in parallel
    let ct_thetas: Vec<_> = ct_childs_acc
    .par_iter_mut()
    .enumerate()
    .map(|(i, ct_acc)| sks.unchecked_scalar_mul(&ct_acc, next_stage[i].1))
    .collect();

    let ct_index: Vec<_> = ct_childs_acc
    .par_iter_mut()
    .enumerate()
    .map(|(i, ct_acc)| sks.unchecked_scalar_mul(&ct_acc, next_stage[i].0))
    .collect();

    //Sum not in place
    let ct_theta = sks.unchecked_add(&ct_thetas[0], &ct_thetas[1]);
    let ct_index = sks.unchecked_add(&ct_index[0], &ct_index[1]);

    let output_index = cks.decrypt(&ct_index);
    let output_theta = cks.decrypt(&ct_theta);
    println!("Index {} ; Theta {}", output_index, output_theta);

    let ct_res = (ct_theta,ct_index);

    return (ct_res, ct_childs_acc);

}   



// fn build_decision_tree(depth: usize) -> Vec<Vec<(u8, u8)>> {
//     if depth == 0 {
//         return vec![];
//     }

//     let mut tree = vec![vec![(0, 2)]];

//     for _ in 1..depth {
//         let mut new_level = Vec::new();
//         let branches = tree.last().unwrap();
        
//         for &(a, b) in branches {
//             new_level.push((a, b));
//             new_level.push((a, b));
//         }
        
//         tree.push(new_level);
//     }

//     print!("tree = {:?}",tree);

//     tree
// }



fn build_decision_tree(depth: usize) -> Vec<Vec<(u8, u8)>> {
    let mut rng = rand::thread_rng();
    let mut tree = vec![vec![(rng.gen_range(0..=3), rng.gen_range(0..=3))]];

    for _ in 1..depth {
        let mut new_level = Vec::new();
        let last_level_nodes = tree.last().unwrap();

        for _ in 0..(last_level_nodes.len() * 2) {
            new_level.push((rng.gen_range(0..=3), rng.gen_range(0..=3)));
        }

        tree.push(new_level);
    }


    tree
}


pub fn probonite(d : usize)
{

    // We generate a set of client/server keys, using the default parameters:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    let lut = sks.generate_accumulator(|x| features(x));
    println!("Generated accumulator");

 
    // Tree
    // let tree : Vec<Vec<(u8,u8)>> = vec![
    //                         vec![(1,1)],
    //                     vec![(2,1)  ,(2,2)],
    //              vec![(2,3),   (2,2),   (2,1),   (2,2)],
    //     vec![(2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0)],
    //     vec![(2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0)],
    //     vec![(2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0)],
    //     vec![(2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0)],
    //     vec![(2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0), (2,3),(1,2), (3,2),(2,1), (1,3),(0,3), (3,1),(3,0)]

    // ];

    let tree = build_decision_tree(d+1);

    let mut ct_res : (Ciphertext,Ciphertext);
    let mut ct_acc : Vec<Ciphertext>;


    let start_probonite = Instant::now();

    (ct_res, ct_acc) = probonite_first_stage(sks.clone(), 
        tree[0][0],
        &lut,
        tree[1].clone(), cks.clone());
    
    println!("FRST STAGE DONE !");

    for i in 2..d+1 { //tree.len() à la place de depth
        (ct_res, ct_acc) = probonite_one_stage(sks.clone(), 
            ct_res,
            &lut,
            ct_acc,
            tree[i].clone(), cks.clone());
    }

    // ct_res = bench_probonite(&cks, &sks, tree, &lut, d);
    
    let duration_probonite = start_probonite.elapsed();
    println!("TIME PROBONITE : {:?}",duration_probonite);

    let ct_index = ct_res.0;
    let ct_theta = ct_res.1;

    let output_index = cks.decrypt(&ct_index);
    let output_theta = cks.decrypt(&ct_theta);


    println!("Prediction : Index {} ; Theta {}", output_index, output_theta);



}