use std::fs::File;

use crate::{comp_free::dataset::*, comp_free::DEBUG, VERBOSE};
use bincode::de;
use rand::{Rng, RngCore, SeedableRng, distributions::uniform::SampleBorrow};
use regex::Regex;
use revolut::{key, Context};
use serde_json::Value;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

const OVERFLOW: bool = true;

#[derive(Clone)]
pub struct ClearRoot {
    pub threshold: u64,
    pub feature_index: u64,
}

impl ClearRoot {
    pub fn print(&self) {
        println!("({},{})", self.feature_index, self.threshold,);
    }
}

#[derive(Clone)]
pub struct ClearInternalNode {
    pub id: u64,
    pub threshold: u64,
    pub feature_index: u64,
}

impl ClearInternalNode {
    pub fn print(&self) {
        print!("({},{})", self.feature_index, self.threshold);
    }
}

#[derive(Clone, Debug)]
pub struct ClearLeaf {
    pub counts: Vec<u64>,
    pub id: u64,
    pub label: u64,
}

impl ClearLeaf {
    pub fn print(&self, n_classes: u64) {
        print!("({:?}, {})", &self.counts[..n_classes as usize], self.label);
    }
}

#[derive(Clone)]
pub struct ClearTree {
    pub root: ClearRoot,
    pub nodes: Vec<Vec<ClearInternalNode>>,
    pub leaves: Vec<ClearLeaf>,
    pub depth: u64,
    pub n_classes: u64,
    pub final_leaves: Vec<u64>,
}

impl ClearTree {
    pub fn new() -> Self {
        Self {
            root: ClearRoot {
                threshold: 0,
                feature_index: 0,
            },
            nodes: Vec::new(),
            leaves: Vec::new(),
            depth: 0,
            n_classes: 0,
            final_leaves: Vec::new(),
        }
    }

    pub fn infer(&mut self, record: &ClearSample) -> &mut ClearLeaf {
        let mut current_node = &ClearInternalNode {
            id: 0,
            threshold: 0,
            feature_index: 0,
        };

        if self.root.threshold < record.features[self.root.feature_index as usize] {
            current_node = &self.nodes[0][0];
        } else {
            current_node = &self.nodes[0][1];
        }

        for idx in 1..self.depth - 1 {
            if current_node.threshold < record.features[current_node.feature_index as usize] {
                current_node = &self.nodes[idx as usize][2 * current_node.id as usize];
            } else {
                current_node = &self.nodes[idx as usize][2 * current_node.id as usize + 1];
            }
        }

        let mut selected_leaf: &mut ClearLeaf =
            if current_node.threshold < record.features[current_node.feature_index as usize] {
                &mut self.leaves[2 * current_node.id as usize]
            } else {
                &mut self.leaves[2 * current_node.id as usize + 1]
            };

        if DEBUG {
            println!("[CLEAR] Sample: {:?}", record.features);
            println!("[CLEAR] Selected leaf: {:?}", selected_leaf);
        }

        selected_leaf
    }

    pub fn train(&mut self, dataset: &ClearDataset, label_order: u64) {
        for sample in dataset.records.iter() {
            self.update_statistic(sample);
        }

        // majoority voting to decide the class of each leaf
        for leaf in self.leaves.iter_mut() {
            leaf.counts = leaf.counts.iter().map(|count| *count as u64).collect();

            let mut max_count = 0;
            let mut max_index = 0;
            for (i, count) in leaf.counts.iter().enumerate() {
                if count >= &max_count {
                    max_count = *count;
                    max_index = i;
                }
            }

            if label_order == 0 {
                // if the counts are all 0, set the label to the highest class number
                if leaf.counts.iter().sum::<u64>() == 0 {
                    leaf.label = dataset.n_classes;
                } else {
                    leaf.label = max_index as u64;
                }
            } else {
                leaf.label = max_index as u64;
            }
        }
    }

    pub fn train_with_overflow(&mut self, dataset: &ClearDataset, label_order: u64) {
        for sample in dataset.records.iter() {
            self.update_statistic_with_overflow(sample);
        }

        // majoority voting to decide the class of each leaf
        for leaf in self.leaves.iter_mut() {
            leaf.counts = leaf.counts.iter().map(|count| *count as u64).collect();

            let mut max_count = 0;
            let mut max_index = 0;
            for (i, count) in leaf.counts.iter().enumerate() {
                if count >= &max_count {
                    max_count = *count;
                    max_index = i;
                }
            }

            if label_order == 0 {
                // if the counts are all 0, set the label to the highest class number
                if leaf.counts.iter().sum::<u64>() == 0 {
                    leaf.label = dataset.n_classes;
                } else {
                    leaf.label = max_index as u64;
                }
            } else {
                leaf.label = max_index as u64;
            }
        }
    }

    pub fn update_statistic(&mut self, sample: &ClearSample) {
        let class_index = sample.class as usize;
        let selected_leaf = self.infer(&sample);

        selected_leaf.counts[class_index] += 1;

        if selected_leaf.counts[class_index] == 255 {
            println!("Overflow detected");
        }

        if DEBUG {
            println!("[CLEAR] Sample : {:?}", sample.features);
            self.print();
        }
    }

    pub fn update_statistic_with_overflow(&mut self, sample: &ClearSample) {
        let class_index = sample.class as usize;
        let selected_leaf = self.infer(&sample);

        selected_leaf.counts[class_index] = (selected_leaf.counts[class_index] + 1) % 256;

        if DEBUG {
            println!("[CLEAR] Sample : {:?}", sample.features);
            self.print();
        }
    }

    pub fn print(&self) {
        // println!();
        print!("---------- (f,t) ----------\n");
        self.root.print();
        for level in &self.nodes {
            for node in level {
                node.print();
            }
            println!();
        }
        // print!("\n---------([c0, c1, ..., cn], label)-----------\n");
        for class in 0..self.n_classes {
            for leaf in &self.leaves {
                // print!("[{:>2?}]", leaf.counts[class as usize]);
                print!("[{:02X}]", leaf.counts[class as usize]);
            }
            println!();
        }
        println!("\n");
    }

    pub fn generate_clear_random_tree(
        depth: u64,
        n_classes: u64,
        max_features: u64,
        f: u64,
    ) -> ClearTree {
        let mut tree = ClearTree::new();
        tree.depth = depth;
        tree.n_classes = n_classes;

        let mut rng = rand::thread_rng();

        // the feature index should be selected among the possible feature indices
        // tree.root.feature_index = rng.gen_range(0..f);
        tree.root.feature_index = rand::random::<u64>() % f as u64;
        // tree.root.threshold = rng.gen_range(features_domain.0..=features_domain.1) as f64;
        tree.root.threshold = rand::random::<u64>() % max_features as u64;

        for idx in 1..depth {
            let mut level = Vec::new();
            for j in 0..(2u64.pow(idx as u32) as usize) {
                let feature_index = rng.gen_range(0..f);
                let mut threshold = 0.0;
                let threshold = rand::random::<u64>() % max_features as u64;

                let node = ClearInternalNode {
                    id: j as u64,
                    threshold,
                    feature_index,
                };
                level.push(node);
            }
            tree.nodes.push(level);
        }

        for i in 0..(2u64.pow(depth as u32) as usize) {
            let counts = vec![0; n_classes as usize];
            let leaf = ClearLeaf {
                counts,
                id: 0,
                label: 0,
            };
            tree.leaves.push(leaf);
        }

        tree
    }


    pub fn build_ert(
        depth: u64,
        n_classes: u64,
        max_features: u64,
        f: u64,
        k: usize,
        dataset: &ClearDataset,
    ) -> ClearTree {
        let mut tree = ClearTree::new();
        tree.depth = depth;
        tree.n_classes = n_classes;

        // let mut rng = rand::thread_rng();
        let seed = rand::random::<u64>();
        println!("Seed used for building the tree: {}", seed);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let n_samples = dataset.records.len();

        // indices des samples par niveau et par nœud
        // level_indices[level][node_id] = Vec<indices>
        let mut level_indices: Vec<Vec<Vec<usize>>> = Vec::new();
        level_indices.push(vec![(0..n_samples).collect()]); // niveau 0 : racine

        // ----- Root -----
        let root_indices = &level_indices[0][0];

        if let Some((f_idx, thr)) =
            best_split_for_node(dataset, root_indices, k, f, max_features, n_classes, &mut rng)
        {
            tree.root.feature_index = f_idx;
            tree.root.threshold = thr;

            // on prépare les indices pour le niveau 1
            let mut left = Vec::new();
            let mut right = Vec::new();
            for &i in root_indices {
                let sample = &dataset.records[i];
                let value = sample.features[f_idx as usize];
                if thr < value {
                    left.push(i);
                } else {
                    right.push(i);
                }
            }
            if depth > 1 {
                level_indices.push(vec![left, right]);
            }
        } else {
            // fallback : même comportement qu’avant (split aléatoire)
            tree.root.feature_index = rand::random::<u64>() % f;
            tree.root.threshold = rand::random::<u64>() % max_features;
            if depth > 1 {
                // on met tous les samples à droite, pour éviter les panics
                level_indices.push(vec![Vec::new(), (0..n_samples).collect()]);
            }
        }

        // ----- Niveaux internes 1..depth-1 -----
        for level in 1..depth {
            // si depth == 1, cette boucle est vide -> seulement la racine + feuilles
            let current = &level_indices[level as usize];
            let mut next_level: Vec<Vec<usize>> = Vec::new();
            let mut level_nodes: Vec<ClearInternalNode> = Vec::new();

            for (node_id, idxs) in current.iter().enumerate() {
                // choisir le meilleur split parmi k
                if let Some((f_idx, thr)) = best_split_for_node(
                    dataset,
                    idxs,
                    k,
                    f,
                    max_features,
                    n_classes,
                    &mut rng,
                ) {
                    level_nodes.push(ClearInternalNode {
                        id: node_id as u64,
                        threshold: thr,
                        feature_index: f_idx,
                    });

                    // on prépare les indices pour les enfants
                    let mut left = Vec::new();
                    let mut right = Vec::new();
                    for &i in idxs {
                        let sample = &dataset.records[i];
                        let value = sample.features[f_idx as usize];
                        if thr < value {
                            left.push(i);
                        } else {
                            right.push(i);
                        }
                    }
                    // l’ordre [left, right] doit correspondre à ton routage :
                    // idx enfant gauche = 2 * id, droite = 2 * id + 1
                    next_level.push(left);
                    next_level.push(right);
                } else {
                    // aucun split possible : on met un nœud "dummy"
                    level_nodes.push(ClearInternalNode {
                        id: node_id as u64,
                        threshold: 0,
                        feature_index: 0,
                    });
                    next_level.push(Vec::new());
                    next_level.push(Vec::new());
                }
            }

            tree.nodes.push(level_nodes);

            // si ce n’est pas le dernier niveau interne, on stocke les indices pour le niveau suivant
            if level < depth - 1 {
                level_indices.push(next_level);
            }
        }

        // ----- Feuilles -----
        let n_leaves = 1usize << depth;
        tree.leaves = (0..n_leaves)
            .map(|leaf_id| ClearLeaf {
                counts: vec![0; n_classes as usize],
                id: leaf_id as u64,
                label: 0,
            })
            .collect();

        tree
    }

}

#[derive(Clone)]
pub struct ClearForest {
    pub trees: Vec<ClearTree>,
}

impl ClearForest {
    pub fn new_random_forest(
        n_trees: u64,
        depth: u64,
        n_classes: u64,
        max_features: u64,
        f: u64,
    ) -> ClearForest {
        let mut forest = ClearForest { trees: Vec::new() };
        let mut rng = rand::thread_rng();
        for _ in 0..n_trees {
            let tree = ClearTree::generate_clear_random_tree(depth, n_classes, max_features, f);
            forest.trees.push(tree);
        }
        forest
    }

    pub fn train(&mut self, dataset: &ClearDataset, label_order: u64) {
        for tree in self.trees.iter_mut() {
            tree.train(dataset, label_order);
            tree.final_leaves = tree.leaves.iter().map(|leaf| leaf.label).collect();
        }
    }

    pub fn train_with_overflow(&mut self, dataset: &ClearDataset, label_order: u64) {
        for tree in self.trees.iter_mut() {
            tree.train_with_overflow(dataset, label_order);
            tree.final_leaves = tree.leaves.iter().map(|leaf| leaf.label).collect();
        }
    }

    pub fn evaluate(&mut self, dataset: &ClearDataset) -> f64 {
        let mut correct = 0;
        let mut total = 0;
        let mut abstention = 0;

        for (i, sample) in dataset.records.iter().enumerate() {
            let mut counts = vec![0; self.trees[0].n_classes as usize + 1];
            for tree in self.trees.iter_mut() {
                let predicted_class = tree.infer(&sample);
                counts[predicted_class.label as usize] += 1;
            }

            // Argmax de counts
            let mut max_count = 0;
            let mut max_index = 0;
            for (i, count) in counts.iter().enumerate() {
                if count >= &max_count {
                    max_count = *count;
                    max_index = i;
                }
            }
            if max_index as u64 == sample.class {
                correct += 1;
            }
            if max_index as u64 == self.trees[0].n_classes {
                abstention += 1;
            }
            total += 1;
        }
        (correct as f64 + abstention as f64) / total as f64
    }

    pub fn fit_dataset(
        train_dataset: &ClearDataset,
        test_dataset: &ClearDataset,
        dataset_name: &str,
    ) -> (ClearForest, f64) {
        let num_trees = 64;
        let depth = 4;
        let max_features = train_dataset.max_features;
        let mut n_classes = 3;
        let mut f = 4;

        let num_trials = 100;
        let mut best_accuracy = 0.0;
        let mut best_model =
            ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);

        for _ in 0..num_trials {
            let mut forest =
                ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);
            forest.train(&train_dataset, 1);
            let accuracy = forest.evaluate(&test_dataset);
            if accuracy > best_accuracy {
                best_accuracy = accuracy;
                best_model = forest;
            }
        }
        println!("Best accuracy: {}", best_accuracy);

        (best_model, best_accuracy)
    }

    pub fn print(&self) {
        for tree in self.trees.iter() {
            tree.print();
        }
    }

    pub fn new_ert_forest(
        n_trees: u64,
        depth: u64,
        n_classes: u64,
        max_features: u64,
        f: u64,
        k: usize,
        dataset: &ClearDataset,
    ) -> ClearForest {
        let mut trees = Vec::new();
        for i in 0..n_trees {
            println!("Building tree {}: ", i+1);
            let tree = ClearTree::build_ert(depth, n_classes, max_features, f, k, dataset);
            trees.push(tree);
        }
        ClearForest { trees }
    }

    pub fn clean_leaves(&mut self) {
        for tree in self.trees.iter_mut() {
            tree.leaves.iter_mut().for_each(|leaf| {
                leaf.counts = vec![0; tree.n_classes as usize];
            });
        }
    }
}

fn get_accuracy_for_index(
    dataset_name: &str,
    num_trees: u64,
    depth: u64,
    index: u64,
) -> Option<String> {
    let folder_path = format!("src/comp_free/{}_from_AW/{}/", dataset_name, num_trees);

    if let Ok(entries) = std::fs::read_dir(folder_path) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                let re = Regex::new(&format!(r"best_.*?_(\d+\.\d+)_{}.json$", index)).unwrap();
                if let Some(caps) = re.captures(&file_name) {
                    if let Some(accuracy_str) = caps.get(1) {
                        return Some(accuracy_str.as_str().to_string());
                    }
                }
            }
        }
    }
    None
}

fn gini_impurity(counts: &[u64]) -> f32 {
    let n: u64 = counts.iter().sum();
    if n == 0 {
        return 0.0;
    }

    let n_f = n as f32;
    let sum_sq: f32 = counts
        .iter()
        .map(|&c| {
            let p = c as f32 / n_f;
            p * p
        })
        .sum();

    1.0 - sum_sq
}

/// Gini d’un split (feature_index, threshold) pour un sous-ensemble de samples
fn gini_for_split_indices(
    dataset: &ClearDataset,
    sample_indices: &[usize],
    feature_index: u64,
    threshold: u64,
    n_classes: u64,
) -> f32 {
    let mut left_counts = vec![0u64; n_classes as usize];
    let mut right_counts = vec![0u64; n_classes as usize];

    for &i in sample_indices {
        let sample = &dataset.records[i];
        let cls = sample.class as usize;
        let value = sample.features[feature_index as usize];

        // même convention que dans infer :
        // gauche si threshold < value, droite sinon
        if threshold < value {
            left_counts[cls] += 1;
        } else {
            right_counts[cls] += 1;
        }
    }

    let n_left: u64 = left_counts.iter().sum();
    let n_right: u64 = right_counts.iter().sum();
    let n_total = n_left + n_right;

    if n_total == 0 {
        return 0.0;
    }

    let g_left = gini_impurity(&left_counts);
    let g_right = gini_impurity(&right_counts);

    (n_left as f32 / n_total as f32) * g_left
        + (n_right as f32 / n_total as f32) * g_right
}



fn best_split_for_node(
    dataset: &ClearDataset,
    sample_indices: &[usize],
    k: usize,
    f: u64,            // nombre de features = ton `f`
    max_features: u64, // borne sup pour les thresholds (comme dans generate_clear_random_tree)
    n_classes: u64,
    rng: &mut impl Rng,
) -> Option<(u64, u64)> {
    if sample_indices.is_empty() {
        return None;
    }

    let mut best_gini = f32::INFINITY;
    let mut best_split: Option<(u64, u64)> = None;

    for _ in 0..k {
        let feature_index = rng.gen_range(0..f);
        let threshold = rng.gen_range(0..max_features);

        let g = gini_for_split_indices(
            dataset,
            sample_indices,
            feature_index,
            threshold,
            n_classes,
        );

        if g < best_gini {
            best_gini = g;
            best_split = Some((feature_index, threshold));
        }
    }

    best_split
}


fn print_hyperparameters(
    dataset_name: &str,
    num_trees: u64,
    depth: u64,
    mut n_classes: u64,
    mut f: u64,
    max_features: u64,
    k: usize,
) {
    if dataset_name == "wine" {
        n_classes = 3;
        f = 13;
    }
    if dataset_name == "cancer" {
        n_classes = 2;
        f = 30;
    }
    println!("Dataset: {}", dataset_name);
    println!("num_trees: {}", num_trees);
    println!("depth: {}", depth);
    println!("n_classes: {}", n_classes);
    println!("f (features): {}", f);
    println!("max_features: {}", max_features);
    println!("k (candidates per split): {}", k);
}

mod tests {
    use super::*;

    #[test]
    fn test_train_clear_forest() {
        let seed = 10;
        let filepath = "./src/comp_free/test_forest.json";
        let ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters());
        let public_key = &private_key.public_key;

        let dataset = ClearDataset::from_file("data/iris-uci/iris.csv".to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        let mut forest = ClearForest::load_from_file(filepath);
        forest.train(&train_dataset, 1);
        let accuracy = forest.evaluate(&test_dataset);
        println!("Accuracy: {}", accuracy);
    }

    #[test]
    fn find_best_model() {
        // let dataset_name = "iris";
        // let dataset_name = "wine";
        // let dataset_name = "adult";
        let dataset_name = "cancer";
        // let seed = 10;
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);

        let dataset = ClearDataset::from_file(dataset_path.to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        let num_trees = 64;
        let depth = 5;
        let max_features = dataset.max_features;
        let mut n_classes = 3;
        let mut f = 4;

        if dataset_name == "adult" {
            n_classes = 2;
            f = 105;
        }

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }

        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }

        let num_trials = 10;
        let mut best_accuracy = 0.0;
        let mut best_model =
            ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);

        for _ in 0..num_trials {
            let mut forest =
                ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);
            forest.train(&train_dataset, 1);
            let accuracy = forest.evaluate(&test_dataset);
            if accuracy > best_accuracy {
                best_accuracy = accuracy;
                best_model = forest;
            }
        }

        // let filepath = format!(
        //     "./src/comp_free/best_{}_{}_{}_{:.2}.json",
        //     dataset_name, num_trees, depth, best_accuracy
        // );

        // best_model.save_to_file(&filepath);
        // println!("Best model saved to: {}", filepath);

        println!("Best accuracy: {}", best_accuracy);
    }

    #[test]
    fn test_argmax_order() {
        let dataset_name = "iris";
        let num_trees = 64;
        let depth = 4;
        let ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters());
        let public_key = &private_key.public_key;

        let dataset = ClearDataset::from_file("data/iris-uci/iris.csv".to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        // find the best model
        let (mut forest, best_accuracy) =
            ClearForest::fit_dataset(&train_dataset, &test_dataset, dataset_name);

        // reset the leaves
        forest.trees.iter_mut().for_each(|tree| {
            tree.final_leaves = vec![0; tree.leaves.len()];
            tree.leaves.iter_mut().enumerate().for_each(|(i, leaf)| {
                leaf.counts = vec![0; tree.n_classes as usize];
            });
        });

        // train the model by choosing the highest label when all counts are 0
        forest.train(&train_dataset, 0);

        let accuracy = forest.evaluate(&test_dataset);
        println!("Best accuracy: {}", best_accuracy);
        println!("Accuracy with weird majority voting: {}", accuracy);
    }

    #[test]
    fn analysis_best_model() {
        // let dataset_name = "iris";
        // let dataset_name = "wine";
        let dataset_name = "cancer";
        // let dataset_name = "adult";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);

        let dataset = ClearDataset::from_file(dataset_path.to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        let num_trees = 64;
        let depth = 4;
        let max_features = dataset.max_features;
        let mut n_classes = 3;
        let mut f = 4;

        if dataset_name == "adult" {
            n_classes = 2;
            f = 105;
        }

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }

        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }

        let num_trials = 100;
        let mut best_accuracy = 0.0;
        let mut best_model =
            ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);
        let num_trees = [8, 16, 32, 64];
        for m in num_trees {
            for i in 0..num_trials {
                let mut forest =
                    ClearForest::new_random_forest(m, depth, n_classes, max_features, f);
                forest.train(&train_dataset, 1);
                let accuracy = forest.evaluate(&test_dataset);

                println!("Accuracy trial {}: {}", i, accuracy);

                if accuracy > best_accuracy {
                    best_accuracy = accuracy;
                    best_model = forest;
                }
            }
            println!("Best accuracy for {} trees: {}", m, best_accuracy);
        }
    }

    #[test]
    fn best_model_depth() {
        // let dataset_name = "iris";
        // let dataset_name = "wine";
        let dataset_name = "cancer";
        // let dataset_name = "adult";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);

        let dataset = ClearDataset::from_file(dataset_path.to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        let num_trees = 64;

        let depths = [4, 5, 6, 7, 8, 9, 10];
        for d in depths {
            let max_features = dataset.max_features;
            let mut n_classes = 3;
            let mut f = 4;

            if dataset_name == "adult" {
                n_classes = 2;
                f = 105;
            }

            if dataset_name == "wine" {
                n_classes = 3;
                f = 13;
            }

            if dataset_name == "cancer" {
                n_classes = 2;
                f = 30;
            }

            let num_trials = 100;
            let mut best_accuracy = 0.0;
            let mut best_model =
                ClearForest::new_random_forest(num_trees, d, n_classes, max_features, f);
            for i in 0..num_trials {
                let mut forest =
                    ClearForest::new_random_forest(num_trees, d, n_classes, max_features, f);
                forest.train(&train_dataset, 1);
                let accuracy = forest.evaluate(&test_dataset);

                println!("{},{},{}", d, i, accuracy);

                if accuracy > best_accuracy {
                    best_accuracy = accuracy;
                    best_model = forest;
                }
            }
        }
    }

    #[test]
    fn batched_training() {
        // let dataset_name = "iris";
        // let dataset_name = "wine";
        // let dataset_name = "cancer";
        // let dataset_name = "adult";
        let dataset_name = "credit";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);

        let dataset = ClearDataset::from_file(dataset_path.to_string());
        let (train_dataset, test_dataset) = dataset.split(0.8);

        // let num_trees = 8;
        let depth = 4;
        let max_features = dataset.max_features;
        let mut n_classes = 3;
        let mut f = 4;

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }

        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }

        if dataset_name == "adult" {
            n_classes = 2;
            f = 14;
        }

        if dataset_name == "credit" {
            n_classes = 2;
            f = 15;
        }

        let batch_size = 10;
        let num_batches = train_dataset.records.len() / batch_size;
        let batches = train_dataset.extract_batches(batch_size);

        for num_trees in [8, 16, 32, 64] {
            for i in 0..10 {
                // let best_accuracy =
                //     get_accuracy_for_index(dataset_name, num_trees, depth, i).unwrap();
                // println!("Best accuracy: {:?}", best_accuracy);
                println!("Number of trees: {}", num_trees);

                // Train the best model on the first batch
                let num_trials = 100;
                let mut best_accuracy = 0.0;
                let mut best_model =
                    ClearForest::new_random_forest(num_trees, depth, n_classes, max_features, f);
                for i in 0..num_trials {
                    let mut forest = ClearForest::new_random_forest(
                        num_trees,
                        depth,
                        n_classes,
                        max_features,
                        f,
                    );
                    forest.train(&batches[0], 1);
                    let accuracy = forest.evaluate(&test_dataset);

                    if accuracy > best_accuracy {
                        best_accuracy = accuracy;
                        best_model = forest;
                    }
                }

                // // Get the best model from the folder
                // let filepath = format!(
                //     "./src/comp_free/{}_from_AW/{}/best_{}_{}_{}_{}_{}.json",
                //     dataset_name, num_trees, dataset_name, num_trees, depth, best_accuracy, i
                // );
                // println!("Filepath: {}", filepath);
                // let mut best_model = ClearForest::load_from_file(filepath.as_str());

                // best_model.print();

                println!(
                    "Accuracy after batch of {} samples: ({:.2}, {:.2})",
                    batch_size, best_accuracy, best_accuracy
                );

                // Keep training the best model on the remaining batches
                let mut best_model_with_overflow = best_model.clone();
                for b in 1..num_batches {
                    best_model.train(&batches[b], 1);
                    best_model_with_overflow.train_with_overflow(&batches[b], 1);
                    let accuracy = best_model.evaluate(&test_dataset);
                    let accuracy_with_overflow = best_model_with_overflow.evaluate(&test_dataset);
                    println!(
                        "Accuracy after batch of {} samples: ({:.2}, {:.2})",
                        batch_size * (b + 1),
                        accuracy,
                        accuracy_with_overflow
                    );

                    // if accuracy != accuracy_with_overflow {
                    //     println!("-------------Tree Clear-------------");
                    //     // best_model.print();
                    //     println!("-------------Tree FHE-------------");
                    //     // best_model_with_overflow.print();
                    // }

                    // Save the current model
                    // let no_overflow_dir = "./src/comp_free/test_batch_models/no_overflow";
                    // if !std::path::Path::new(no_overflow_dir).exists() {
                    //     std::fs::create_dir_all(no_overflow_dir).unwrap();
                    // }
                    // let filepath = format!(
                    //     "{}/{}_batch_{}_{:.2}.json",
                    //     no_overflow_dir, dataset_name, b, accuracy
                    // );
                    // best_model.save_to_file(&filepath);

                    // let overflow_dir = "./src/comp_free/test_batch_models/overflow";
                    // if !std::path::Path::new(overflow_dir).exists() {
                    //     std::fs::create_dir_all(overflow_dir).unwrap();
                    // }
                    // let filepath_overflow = format!(
                    //     "{}/{}_batch_{}_{:.2}.json",
                    //     overflow_dir, dataset_name, b, accuracy_with_overflow
                    // );
                    // best_model_with_overflow.save_to_file(&filepath_overflow);
                }
            }
        }
    }

    #[test]
    pub fn find_best_model_ert() {
        let dataset_name = "cancer";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);

        let dataset = ClearDataset::from_file(dataset_path.to_string());
        let (d_0, d_1) = dataset.split(0.3);
        println!("Size of d_0: {}", d_0.records.len());
        println!("Size of d_1: {}", d_1.records.len());
        let (train_dataset, test_dataset) = d_0.split(0.8);
        println!("Size of train_dataset: {}", train_dataset.records.len());
        // let (train_dataset, test_dataset) = dataset.split(0.8);

        let num_trees = 64;
        let depth = 5;
        let max_features = dataset.max_features;
        let mut n_classes = 3;
        let mut f = 4;

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }
        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }

        let k = 2; // par ex : 16 splits candidats par noeuds
        let num_trials = 10;
        let mut best_accuracy = 0.0;
        let mut best_model =
            ClearForest::new_ert_forest(num_trees, depth, n_classes, max_features, f, k, &train_dataset);

        for _ in 0..num_trials {
            let mut forest =
                ClearForest::new_ert_forest(num_trees, depth, n_classes, max_features, f, k, &train_dataset);
            forest.train(&train_dataset, 1);
            let accuracy = forest.evaluate(&test_dataset);
            if accuracy > best_accuracy {
                best_accuracy = accuracy;
                best_model = forest;
            }
        }

        println!("Best accuracy (ERT + Gini): {}", best_accuracy);
    }

    #[test]
    pub fn train_with_gini_then_accumulate() {
        let dataset_name = "iris";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);
        let dataset = ClearDataset::from_file(dataset_path.to_string());
        // Hyperparameters
        let num_trees = 64;
        let depth = 2;
        let mut n_classes = 3;
        let mut f = 4;
        let max_features = dataset.max_features;

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }
        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }
        let k = 2; // nombre de candidats pour le split
        
        print_hyperparameters(dataset_name, num_trees, depth, n_classes, f, max_features, k);

        
        
        let num_trials = 10;
        for _ in 0..num_trials {
        
            let (d_0, d_1) = dataset.split(0.3);
            let (train_dataset, test_dataset) = d_0.split(0.8);
            println!("Size of d_0: {}", d_0.records.len());
            println!("Size of d_1: {}", d_1.records.len());
            println!("Size of train_dataset: {}", train_dataset.records.len());
            println!("Size of test_dataset: {}", test_dataset.records.len());

            

            
            let mut forest = ClearForest::new_ert_forest(num_trees, depth, n_classes, max_features, f, k, &train_dataset);
            forest.train(&train_dataset, 1);
            let accuracy = forest.evaluate(&test_dataset);
            println!("Accuracy on d_0: {}", accuracy);

            forest.clean_leaves();

            // Train the model by accumulating the counts on d_1

            forest.train_with_overflow(&d_1, 1);
            let accuracy_d_1 = forest.evaluate(&test_dataset);
            println!("Accuracy on d_1: {}", accuracy_d_1);
        }
        


    }



    #[test]
    pub fn train_gini_only() {
        // let dataset_name = "iris";
        let dataset_name = "wine";
        let dataset_path = format!("data/{}-uci/{}.csv", dataset_name, dataset_name);
        let dataset = ClearDataset::from_file(dataset_path.to_string());
        // Hyperparameters
        let num_trees = 64;
        let depth = 4;
        let k = 3;
        let mut n_classes = 3;
        let mut f = 4;
        let max_features = dataset.max_features;

        if dataset_name == "wine" {
            n_classes = 3;
            f = 13;
        }
        if dataset_name == "cancer" {
            n_classes = 2;
            f = 30;
        }
        
        
        print_hyperparameters(dataset_name, num_trees, depth, n_classes, f, max_features, k);

        
        
        let num_trials = 10;
        for _ in 0..num_trials {
        
            let (d_0, d_1) = dataset.split(0.3);
            let (train_dataset, test_dataset) = d_0.split(0.8);
            let train_dataset = train_dataset.join(&d_1);

            println!("Size of train_dataset: {}", train_dataset.records.len());
            println!("Size of test_dataset: {}", test_dataset.records.len());
            
            let mut forest = ClearForest::new_ert_forest(num_trees, depth, n_classes, max_features, f, k, &train_dataset);
            forest.train_with_overflow(&train_dataset, 1);
            let accuracy = forest.evaluate(&test_dataset);
            println!("Accuracy: {}", accuracy);
        }
        


    }
}
