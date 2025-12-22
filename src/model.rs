// REVOLUT
use revolut::*;

pub struct Root {
    pub threshold: u64,
    pub feature_index: u64,
}

impl Root {
    pub fn print(&self) {
        println!("({},{})", self.threshold, self.feature_index);
    }
}

pub struct InternalNode {
    pub threshold: u64,
    pub feature_index: u64,
}

impl InternalNode {
    pub fn print(&self) {
        print!("({},{})", self.threshold, self.feature_index);
    }
}

pub struct Leaf {
    pub label: u64,
}

impl Leaf {
    pub fn print(&self) {
        print!("{}", self.label);
    }
}

pub struct Tree {
    pub root: Root,
    pub nodes: Vec<Vec<InternalNode>>,
    pub leaves: Vec<Leaf>,
    pub depth: u64,
    pub n_classes: u64,
}

impl Tree {
    pub fn new() -> Self {
        Self {
            root: Root {
                threshold: 0,
                feature_index: 0,
            },
            nodes: Vec::new(),
            leaves: Vec::new(),
            depth: 0,
            n_classes: 0,
        }
    }

    #[allow(dead_code)]
    pub fn generate_random_tree(depth: u64, n_classes: u64, ctx: &Context) -> Self {
        let mut tree = Self::new();
        tree.depth = depth;
        tree.n_classes = n_classes;

        // Generate the root
        tree.root.threshold = rand::random::<u64>() % ctx.full_message_modulus() as u64;
        tree.root.feature_index = rand::random::<u64>() % ctx.full_message_modulus() as u64;

        // Generate the nodes
        // Generate internal nodes for each level
        for _ in 1..depth {
            let mut stage = Vec::new();

            // Number of nodes at this level is 2^level_index
            let num_nodes = 2u64.pow(tree.nodes.len() as u32 + 1);

            for _ in 0..num_nodes {
                stage.push(InternalNode {
                    threshold: rand::random::<u64>() % ctx.full_message_modulus() as u64,
                    feature_index: rand::random::<u64>() % ctx.full_message_modulus() as u64,
                });
            }
            tree.nodes.push(stage);
        }

        // Generate the leaves
        let num_leaves = 2u64.pow(depth as u32);
        for _ in 0..num_leaves {
            tree.leaves.push(Leaf { label: rand::random::<u64>() % n_classes });
        }

        tree
    }

    pub fn print_tree(&self) {
        println!("-----------[(t,f)]-----------");
        self.root.print();
        for stage in self.nodes.iter() {
            for node in stage {
                node.print();
                print!(" ");
            }
            println!("");
        }
        for leaf in self.leaves.iter() {
            leaf.print();
            print!(" ");
        }
        println!("");
        println!("-----------------------------");
    }

    #[allow(dead_code)]
    pub fn to_json(&self) -> serde_json::Value {
        let mut tree_json = serde_json::Map::new();

        // Serialize depth and n_classes
        tree_json.insert(
            "depth".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.depth)),
        );
        tree_json.insert(
            "n_classes".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.n_classes)),
        );

        // Serialize leaves
        let leaves_json: Vec<serde_json::Value> = self
            .leaves
            .iter()
            .map(|leaf| {
                serde_json::json!({
                    "type": "leaf",
                    "label": leaf.label
                })
            })
            .collect();
        tree_json.insert("leaves".to_string(), serde_json::Value::Array(leaves_json));

        // Serialize internal nodes
        let mut nodes_json = Vec::new();
        for stage in &self.nodes {
            let stage_json: Vec<serde_json::Value> = stage
                .iter()
                .map(|node| {
                    serde_json::json!({
                        "threshold": node.threshold,
                        "feature_index": node.feature_index
                    })
                })
                .collect();
            nodes_json.push(stage_json);
        }
        tree_json.insert(
            "nodes".to_string(),
            serde_json::Value::Array(nodes_json.concat()),
        );

        // Serialize root
        let root_json = serde_json::json!({
            "threshold": self.root.threshold,
            "feature_index": self.root.feature_index
        });
        tree_json.insert("root".to_string(), root_json);

        serde_json::Value::Object(tree_json)
    }

    #[allow(dead_code)]
    pub fn save_to_file(&self, filepath: &str) {
        let json_value = self.to_json();
        let json_string = serde_json::to_string_pretty(&json_value).unwrap();
        std::fs::write(filepath, json_string).unwrap();
    }

    #[allow(dead_code)]
    pub fn from_json(json: &serde_json::Value) -> Self {
        let mut tree = Tree::new();

        // Deserialize depth and n_classes
        let depth = json.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u64;
        let n_classes = json.get("n_classes").and_then(|v| v.as_u64()).unwrap_or(0) as u64;
        tree.depth = depth;
        tree.n_classes = n_classes;

        // Deserialize root
        if let Some(root) = json.get("root") {
            tree.root.threshold = root.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0);
            tree.root.feature_index = root
                .get("feature_index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
        }

        // Deserialize internal nodes
        if let Some(nodes) = json.get("nodes").and_then(|v| v.as_array()) {
            let mut node_index = 0;
            for level in 1..depth {
                let mut stage = Vec::new();
                let num_nodes = 2u64.pow(level as u32);

                for _ in 0..num_nodes {
                    if let Some(node_json) = nodes.get(node_index) {
                        let threshold = node_json
                            .get("threshold")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let feature_index = node_json
                            .get("feature_index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        stage.push(InternalNode {
                            threshold,
                            feature_index,
                        });
                        node_index += 1;
                    }
                }
                tree.nodes.push(stage);
            }
        }

        // Deserialize leaves
        if let Some(leaves) = json.get("leaves").and_then(|v| v.as_array()) {
            for leaf_json in leaves {
                tree.leaves.push(Leaf {
                    label: leaf_json.get("label").and_then(|v| v.as_u64()).unwrap_or(0),
                });
            }
        }

        tree
    }

    #[allow(dead_code)]
    pub fn load_from_file(filepath: &str) -> std::io::Result<Self> {
        let json_content = std::fs::read_to_string(filepath).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Tree file does not exist")
        })?;
        let json_value: serde_json::Value = serde_json::from_str(&json_content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::from_json(&json_value))
    }
}
