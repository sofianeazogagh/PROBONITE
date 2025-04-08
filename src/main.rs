#![allow(warnings)]

use std::io::Write;
use std::time::Instant;

mod probonite;
use probonite::*;

use bincode::{config::AllowTrailing, de};

mod model;
use model::*;

mod xt_probolut;
use xt_probolut::*;

mod dataset;
use dataset::*;

mod clear_model;
use clear_model::*;

mod xt_probonite;
use xt_probonite::*;

mod helpers;
use helpers::*;

mod clear_training;
use clear_training::*;

use clap::Parser;
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use revolut::*;

use tfhe::shortint::parameters::*;

use std::env;

#[allow(dead_code)]
const GENERATE_TREE: bool = true;
#[allow(dead_code)]
const EXPORT_FOREST: bool = true;
const NUM_THREADS: usize = 10;
const VERBOSE: bool = true;

mod xt_probolut_radix;
use xt_probolut_radix::*;


fn main() {
    ThreadPoolBuilder::new()
        .num_threads(NUM_THREADS)
        .build_global()
        .unwrap();

    let args = Args::parse();

    xt_probolut_radix::benchmark(args);

}
