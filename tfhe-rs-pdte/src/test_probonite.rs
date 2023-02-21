use tfhe::shortint::parameters::*;
use tfhe::shortint::prelude::*;


use std::time::{Instant};

pub fn test_probonite_one_stage(){

    // We generate a set of client/server keys, using the default parameters:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_3_CARRY_2);

    let acc = sks.generate_accumulator(f);
    println!("Generated accumulator");

    let parent_acc_1 = 1;
    let parent_acc_2 = 0;
    let parent_acc_3 = 0;
    let parent_acc_4 = 0;
    let theta_1:u8 = 3;
    let theta_2:u8 = 3;
    let theta_3:u8 = 1;
    let theta_4:u8 = 2;
    let theta_5:u8 = 0;
    let theta_6:u8 = 1;
    let theta_7:u8 = 2;
    let theta_8:u8 = 3;


    let index_feature:u64 = 2;
    let theta:u64 = 1;

    let ct_index_feature = cks.encrypt(index_feature);
    let mut ct_theta = cks.encrypt(theta);
    let ct_parent_acc_1 = cks.encrypt(parent_acc_1);
    let ct_parent_acc_2 = cks.encrypt(parent_acc_2);
    let ct_parent_acc_3 = cks.encrypt(parent_acc_3);
    let ct_parent_acc_4 = cks.encrypt(parent_acc_4);
    let ct_one = cks.encrypt(1);
    println!("Encryption node for testing");


    let start_third_stage = Instant::now();






    let start_baacc = Instant::now();
    let mut ct_feat = sks.keyswitch_programmable_bootstrap(&ct_index_feature, &acc);
    let duration_baacc = start_baacc.elapsed();
    println!("Temps d'execution BAACC: {:?}",duration_baacc);
    println!("Blind array access");
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
    let ct_child_1_acc = sks.unchecked_mul_lsb(&ct_parent_acc_1, &ct_cp);
    output = cks.decrypt(&ct_child_1_acc);
    println!("ct_child_1_acc {}", output);

    let ct_child_2_acc = sks.unchecked_mul_lsb(&ct_parent_acc_1, &not_ct_cp);
    output = cks.decrypt(&ct_child_2_acc);
    println!("ct_child_2_acc {}", output);

    let ct_child_3_acc = sks.unchecked_mul_lsb(&ct_parent_acc_2, &ct_cp);
    output = cks.decrypt(&ct_child_3_acc);
    println!("ct_child_3_acc {}", output);

    let ct_child_4_acc = sks.unchecked_mul_lsb(&ct_parent_acc_2, &not_ct_cp);
    output = cks.decrypt(&ct_child_4_acc);
    println!("ct_child_4_acc {}", output);

    let ct_child_5_acc = sks.unchecked_mul_lsb(&ct_parent_acc_3, &ct_cp);
    output = cks.decrypt(&ct_child_5_acc);
    println!("ct_child_5_acc {}", output);

    let ct_child_6_acc = sks.unchecked_mul_lsb(&ct_parent_acc_3, &not_ct_cp);
    output = cks.decrypt(&ct_child_6_acc);
    println!("ct_child_6_acc {}", output);

    let ct_child_7_acc = sks.unchecked_mul_lsb(&ct_parent_acc_4, &ct_cp);
    output = cks.decrypt(&ct_child_7_acc);
    println!("ct_child_7_acc {}", output);

    let ct_child_8_acc = sks.unchecked_mul_lsb(&ct_parent_acc_4, &not_ct_cp);
    output = cks.decrypt(&ct_child_8_acc);
    println!("ct_child_8_acc {}", output);

    let duration_acc_agg = start_acc_agg.elapsed();
    println!("Temps d'exécution AccAgg : {:?}", duration_acc_agg);

    ///////// BNS


    //Absorb the nodes

    let start_bns = Instant::now();

    let start_abs = Instant::now();
    let ct_theta_1 = sks.unchecked_scalar_mul(&ct_child_1_acc, theta_1);
    output = cks.decrypt(&ct_theta_1);
    println!("ct_theta_1 {}", output);

    let ct_theta_2 = sks.unchecked_scalar_mul(&ct_child_2_acc, theta_2);
    output = cks.decrypt(&ct_theta_2);
    println!("ct_theta_2 {}", output);

    let ct_theta_3 = sks.unchecked_scalar_mul(&ct_child_3_acc, theta_3);
    output = cks.decrypt(&ct_theta_3);
    println!("ct_theta_3 {}", output);

    let ct_theta_4 = sks.unchecked_scalar_mul(&ct_child_4_acc, theta_4);
    output = cks.decrypt(&ct_theta_4);
    println!("ct_theta_4 {}", output);


    let ct_theta_5 = sks.unchecked_scalar_mul(&ct_child_5_acc, theta_5);
    output = cks.decrypt(&ct_theta_5);
    println!("ct_theta_5 {}", output);

    let ct_theta_6 = sks.unchecked_scalar_mul(&ct_child_6_acc, theta_6);
    output = cks.decrypt(&ct_theta_6);
    println!("ct_theta_6 {}", output);


    let ct_theta_7 = sks.unchecked_scalar_mul(&ct_child_7_acc, theta_7);
    output = cks.decrypt(&ct_theta_7);
    println!("ct_theta_7 {}", output);

    let ct_theta_8 = sks.unchecked_scalar_mul(&ct_child_8_acc, theta_8);
    output = cks.decrypt(&ct_theta_8);
    println!("ct_theta_8 {}", output);

    let duration_abs = start_abs.elapsed();
    println!("Temps d'exécution ABS thresholds : {:?}", duration_abs);

    // // Sum the absorbed nodes
    let mut ct_res = sks.unchecked_add(&ct_theta_1, &ct_theta_2);
    let start_sum_in_place = Instant::now();
    ct_res = sks.unchecked_add(&ct_res, &ct_theta_3);
    ct_res = sks.unchecked_add(&ct_res,&ct_theta_4);
    ct_res = sks.unchecked_add(&ct_res,&ct_theta_5);
    ct_res = sks.unchecked_add(&ct_res,&ct_theta_6);
    ct_res = sks.unchecked_add(&ct_res,&ct_theta_7);
    ct_res = sks.unchecked_add(&ct_res,&ct_theta_8);
    let duration_sum_in_place = start_sum_in_place.elapsed();
    println!("Temps d'éxecution Sum in Place : {:?}",duration_sum_in_place);

    let duration_bns = start_bns.elapsed();
    println!("Temps d'exécution BNS: {:?}", duration_bns);

    let duration_third_stage = start_third_stage.elapsed();
    println!("Temps d'exécution 3rd stage: {:?}", duration_third_stage);


    // We use the client key to decrypt the output of the circuit:
    output = cks.decrypt(&ct_res);
    println!("Got theta {} , expected theta {}", output, theta_2);

}


fn f(x:u64)->u64{

    let vector:Vec<u64> = (0..31).collect();
    let result = vector.get(x as usize);

    return match result {
        Some(result) => *result,
        None => 0,
    }

}