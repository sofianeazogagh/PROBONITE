use csv;
use rand::rngs::StdRng;
use rand::seq::{index::sample, SliceRandom};
use rand::Rng;
use rand::SeedableRng;
use revolut::{Context, PrivateKey, LUT};
use std::vec;
use tfhe::{
    core_crypto::prelude::{GlweCiphertext, LweCiphertext},
    shortint::parameters::*,
};

use super::*;

#[derive(Clone)]
pub struct ClearSample {
    pub features: Vec<u64>,
    pub class: u64,
}

impl ClearSample {
    pub fn print(&self) {
        print!("\n([");
        for feature in &self.features {
            print!("{},", feature);
        }
        print!("],{})", self.class);
    }
}

#[derive(Clone)]
pub struct ClearDataset {
    pub records: Vec<ClearSample>,
    pub max_features: u64,
    pub n_classes: u64,
    pub f: u64,
    pub n: u64,
}

impl ClearDataset {
    pub fn from_file(filepath: String) -> Self {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(filepath)
            .unwrap();
        let mut records = Vec::new();
        let mut n = 0;

        let mut max = std::u64::MIN;
        let mut classes = Vec::new();

        for result in rdr.records() {
            let record = result.unwrap();
            let mut record_vec = Vec::new();
            let mut class: u64 = 0;

            for (i, field) in record.iter().enumerate() {
                let value = field.parse::<u64>().unwrap();

                if i == record.len() - 1 {
                    class = value as u64;
                    if !classes.contains(&class) {
                        classes.push(class);
                    }
                } else {
                    record_vec.push(value);
                }

                if value > max {
                    max = value;
                }
            }
            records.push(ClearSample {
                features: record_vec,
                class,
            });
        }

        let f = records[0].features.len() as u64;

        Self {
            records,
            max_features: max,
            n_classes: classes.len() as u64,
            f,
            n,
        }
    }

    pub fn split(&self, train: f64) -> (ClearDataset, ClearDataset) {
        let seed = rand::random::<u64>();
        println!("Seed used for splitting: {}", seed);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let n = self.records.len();
        let n_train = (train * n as f64) as u64;
        let mut train_indices = Vec::new();
        let mut test_indices = Vec::new();

        while train_indices.len() < n_train as usize {
            let idx = rng.gen_range(0..n);
            if !train_indices.contains(&idx) {
                train_indices.push(idx);
            }
        }

        for i in 0..n {
            if !train_indices.contains(&i) {
                test_indices.push(i);
            }
        }

        let mut train_records = Vec::new();
        let mut test_records = Vec::new();
        for idx in train_indices {
            train_records.push(self.records[idx].clone());
        }
        for idx in test_indices {
            test_records.push(self.records[idx].clone());
        }

        let train_dataset = ClearDataset {
            records: train_records,
            max_features: self.max_features,
            n_classes: self.n_classes,
            f: self.f,
            n: n_train,
        };

        let test_dataset = ClearDataset {
            records: test_records,
            max_features: self.max_features,
            n_classes: self.n_classes,
            f: self.f,
            n: n as u64 - n_train,
        };

        (train_dataset, test_dataset)
    }

    pub fn extract_batches(&self, batch_size: usize) -> Vec<ClearDataset> {
        let mut batches = Vec::new();
        let num_batches = self.records.len() / batch_size;
        for i in 0..num_batches {
            let batch = self.records[i * batch_size..(i + 1) * batch_size].to_vec();
            let clear_dataset = Self {
                records: batch,
                max_features: self.max_features,
                n_classes: self.n_classes,
                f: self.f,
                n: batch_size as u64,
            };
            batches.push(clear_dataset);
        }
        batches
    }

    pub fn join(&self, other: &ClearDataset) -> ClearDataset {
        let mut new_records = self.records.clone();
        new_records.extend_from_slice(&other.records);

        ClearDataset {
            records: new_records,
            max_features: self.max_features.max(other.max_features),
            n_classes: self.n_classes.max(other.n_classes),
            f: self.f.max(other.f),
            n: (self.n + other.n),
        }
    }
}

pub struct EncryptedSample {
    pub class: Vec<LWE>, // one hot encoded class
    pub features: Vec<RLWE>,
}

impl EncryptedSample {
    fn one_hot_encode(class: &u64, n_classes: u64) -> Vec<u64> {
        let mut one_hot = vec![0; n_classes as usize];
        one_hot[*class as usize] = 1;
        one_hot
    }
    pub fn make_encrypted_sample(
        feature_vector: &Vec<u64>,
        class: &u64,
        n_classes: u64,
        private_key: &PrivateKey,
        ctx: &mut Context,
    ) -> Self {
        let mut feature_rlwes = Vec::new();

        for feature in feature_vector {
            let mut vec = Vec::new();
            for i in 0..ctx.polynomial_size().0 as u64 {
                if (i < *feature) {
                    vec.push(0);
                } else {
                    vec.push(1);
                }
            }
            feature_rlwes.push(private_key.allocate_and_encrypt_glwe_from_vec(&vec, ctx));
        }

        let one_hot_class = Self::one_hot_encode(class, n_classes);
        let mut vec_class = Vec::new();
        for i in 0..n_classes {
            vec_class.push(private_key.allocate_and_encrypt_lwe(one_hot_class[i as usize], ctx));
        }
        Self {
            class: vec_class,
            features: feature_rlwes,
        }
    }

    pub fn print(&self, private_key: &PrivateKey, ctx: &Context) {
        print!("([");
        let features_vec: Vec<Vec<u64>> = self
            .features
            .iter()
            .map(|x| private_key.decrypt_and_decode_glwe(x, ctx)[..16].to_vec())
            .collect();
        print!("{:?}", &features_vec[..4]);
        print!(", [");
        self.class.iter().for_each(|lwe| {
            print!(", {:?}", private_key.decrypt_lwe(lwe, ctx));
        });
        print!("])\n");
    }

    pub fn clone(&self) -> Self {
        Self {
            class: self.class.clone(),
            features: self.features.clone(),
        }
    }
}

pub struct EncryptedDataset {
    pub records: Vec<EncryptedSample>,
    pub f: u64,
    pub n_classes: u64,
    pub max_features: u64,
}

impl EncryptedDataset {
    pub fn from_file(
        filepath: String,
        private_key: &PrivateKey,
        ctx: &mut Context,
        n_classes: u64,
    ) -> Self {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(filepath)
            .unwrap();
        let mut records = Vec::new();
        let mut f = 0;
        let mut max_features = std::u64::MIN;

        for result in rdr.records() {
            let record = result.unwrap();
            let mut class: u64 = 0;
            let mut record_vec = Vec::new();
            for (i, field) in record.iter().enumerate() {
                let value = field.parse::<u64>().unwrap();

                // last field is the class
                if i == record.len() - 1 {
                    class = value;
                } else {
                    record_vec.push(value);

                    if value > max_features {
                        max_features = value;
                    }
                }
            }
            records.push(EncryptedSample::make_encrypted_sample(
                &record_vec,
                &class,
                n_classes,
                private_key,
                ctx,
            ));
            f = record_vec.len() as u64;
        }

        Self {
            records,
            f,
            n_classes,
            max_features,
        }
    }

    pub fn split(&self, train: f64) -> (EncryptedDataset, EncryptedDataset) {
        let mut rng = rand::thread_rng();
        let n = self.records.len();
        let mut indices: Vec<usize> = (0..n).collect();
        indices.shuffle(&mut rng);

        let train_size = (n as f64 * train).round() as usize;
        let train_indices = &indices[0..train_size];
        let test_indices = &indices[train_size..];

        let train_records: Vec<EncryptedSample> = train_indices
            .iter()
            .map(|&i| self.records[i].clone())
            .collect();
        let test_records: Vec<EncryptedSample> = test_indices
            .iter()
            .map(|&i| self.records[i].clone())
            .collect();

        (
            EncryptedDataset {
                records: train_records,
                f: self.f,
                n_classes: self.n_classes,
                max_features: self.max_features,
            },
            EncryptedDataset {
                records: test_records,
                f: self.f,
                n_classes: self.n_classes,
                max_features: self.max_features,
            },
        )
    }

    pub fn from_clear_dataset(
        dataset: &ClearDataset,
        private_key: &PrivateKey,
        ctx: &mut Context,
    ) -> Self {
        let records = dataset
            .records
            .iter()
            .map(|sample| {
                let features = sample.features.iter().map(|x| *x as u64).collect();
                EncryptedSample::make_encrypted_sample(
                    &features,
                    &sample.class,
                    dataset.n_classes,
                    private_key,
                    ctx,
                )
            })
            .collect();

        Self {
            records,
            f: dataset.f,
            n_classes: dataset.n_classes,
            max_features: dataset.max_features,
        }
    }

    pub fn print(&self, private_key: &PrivateKey, ctx: &Context) {
        for record in &self.records {
            record.print(private_key, ctx);
        }
    }
}
