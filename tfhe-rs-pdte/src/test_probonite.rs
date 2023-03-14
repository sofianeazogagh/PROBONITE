use rayon::prelude::*;
use rand::{thread_rng, Rng};

use tfhe::shortint::parameters::*;
use tfhe::shortint::prelude::*;

#[allow(dead_code)]


use std::time::{Instant};

pub fn test_probonite_one_stage(current_stage : u64, next_stage : u64){

    // We generate a set of client/server keys, using the default parameters:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let lut = sks.generate_accumulator(f);
    println!("Generated accumulator");


    println!("---------- STAGE {} to {} ----------", current_stage,next_stage);


    // let base: u64 = 2;
    // let msg_modulus = cks.parameters.message_modulus.0;
    // let mut parent_acc : Vec<u64> = vec![0;base.pow(current_stage as u32) as usize];
    // parent_acc[0] = 1;
    // let thetas:Vec<u64> = random_numbers_up_to_n((msg_modulus - 1) as u64, base.pow(next_stage as u32));
    // let thetas = cast_to_u8(thetas);


    // let parent_acc : Vec<u64> = vec![1,0];
    // let thetas:Vec<u8> = vec![3,2,1,2];

    let parent_acc : Vec<u64> = vec![1,0,0,0];
    let thetas:Vec<u8> = vec![3, 0, 0, 1, 0, 2, 2, 0];



    println!("parent_acc {:?}", parent_acc);
    println!("thetas {:?}", thetas);





    let index_feature:u64 = 1;
    let theta:u64 = 2;

    let ct_index_feature = cks.encrypt(index_feature);
    let mut ct_theta = cks.encrypt(theta);


    let mut ct_parent_acc: Vec<Ciphertext> = vec![];

    for acc in parent_acc {
        let ct_acc = cks.encrypt(acc);
        ct_parent_acc.push(ct_acc);
    }

    let ct_one = cks.encrypt(1);
    println!("Encryption node for testing");


    let start_third_stage = Instant::now();


    let start_baacc = Instant::now();
    let mut ct_feat = sks.keyswitch_programmable_bootstrap(&ct_index_feature, &lut);
    let duration_baacc = start_baacc.elapsed();
    println!("Temps d'execution BAACC: {:?}",duration_baacc);

    let mut output = cks.decrypt(&ct_feat);
    println!("ct_feat {}", output);

    // CMP
    let start_cmp = Instant::now();
    let ct_cp = sks.smart_greater_or_equal( &mut ct_feat, &mut ct_theta );
    let duration_cmp = start_cmp.elapsed();
    println!("Temps d'exécution CP: {:?}", duration_cmp);
    output = cks.decrypt(&ct_cp);
    println!("ct_cp {}", output);

    let not_ct_cp = sks.unchecked_sub(&ct_one, &ct_cp);
    output = cks.decrypt(&not_ct_cp);
    println!("not_ct_cp {}", output);


    //AccAgg
    let start_acc_agg = Instant::now();


    let mut ct_childs_acc: Vec<_> = ct_parent_acc
    .par_iter()
    .flat_map(|ct_acc| {
        let ct_child_left = sks.unchecked_mul_lsb(&ct_acc, &ct_cp);
        let ct_child_right = sks.unchecked_mul_lsb(&ct_acc, &not_ct_cp);
        let output1 = cks.decrypt(&(ct_child_left.clone()));
        let output2 = cks.decrypt(&(ct_child_right.clone()));
        println!("ct_child_left = {} \nct_child_right = {}",output1,output2);
        vec![ct_child_left, ct_child_right]
    })
    .collect();







    let duration_acc_agg = start_acc_agg.elapsed();
    println!("Temps d'exécution AccAgg : {:?}", duration_acc_agg);

    ///////// BNS


    //Absorb the nodes

    let start_bns = Instant::now();

    let start_abs = Instant::now();

    

    let ct_thetas: Vec<_> = ct_childs_acc
    .par_iter_mut()
    .enumerate()
    .map(|(i, ct_acc)| sks.unchecked_scalar_mul(&ct_acc, thetas[i]))
    .collect();


    let duration_abs = start_abs.elapsed();
    println!("Temps d'exécution ABS thresholds : {:?}", duration_abs);

    // // Sum the absorbed nodes
    let start_sum_in_place = Instant::now();

    let mut ct_res = ct_thetas[0].clone();

    if current_stage>1 {
        for i in 1..ct_thetas.len()
        {
            ct_res = sks.unchecked_add(&ct_res, &ct_thetas[i]);
        }
    }
    else {
        ct_res = sks.unchecked_add(&ct_res, &ct_thetas[1]);
    } 

    let duration_sum_in_place = start_sum_in_place.elapsed();
    println!("Temps d'éxecution Sum in Place : {:?}",duration_sum_in_place);

    let duration_bns = start_bns.elapsed();
    println!("Temps d'exécution BNS: {:?}", duration_bns);

    let duration_third_stage = start_third_stage.elapsed();
    println!("Temps d'exécution stage: {:?}", duration_third_stage);


    // We use the client key to decrypt the output of the circuit:
    output = cks.decrypt(&ct_res);
    println!("Got theta {}", output);

}


fn f(x:u64)->u64{

    let vector:Vec<u64> = (0..32).collect();
    let result = vector.get(x as usize);

    return match result {
        Some(result) => *result,
        None => 0,
    }

}


fn random_numbers_up_to_n(n: u64, num_elements: u64) -> Vec<u64> {
    let mut rng = thread_rng();
    (0..num_elements)
        .map(|_| rng.gen_range(0..=n))
        .collect()
}



fn cast_to_u8(v: Vec<u64>) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}



pub fn test_probonite_multi_stage()
{

    // root
    let index_root:u64 = 1;
    let theta_root:u64 = 2;


    let tree : Vec<Vec<(u8,u8)>> = vec![
                                        vec![(2,1)],
                                    vec![(2,1) , (2,2)],
                                vec![(2,3) , (2,2) , (2,1) ,( 2,2)],
                        vec![(2,3) , (2,0) , (2,0) , (2,1) , (2,0) , (2,1) , (2,0)],

        vec![(2,3),(2,0), (2,0),(2,1), (2,0),(2,1), (2,0),(2,3), (2,0),(2,0), (2,1),(2,0), (2,1),(2,0)]
    ];



    




    test_probonite_one_stage(2,3);

}