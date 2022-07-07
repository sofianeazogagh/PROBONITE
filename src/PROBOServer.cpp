#include<string>
#include<map>
#include<vector>
#include<iostream>
#include <fstream>

#include "../include/util/literal.hpp"
// #include "util/Timer.hpp"
#include "../include/network/PROBO.hpp"

#include <tfhe/tfhe_core.h>
#include <tfhe/numeric_functions.h>

struct Node {

    Node() : threshold(-1), feature_index(-1), id(-1), acc(-1), left(nullptr), right(nullptr) {}
    ~Node() {} //TODO free node

    int32_t threshold;
    int feature_index; 
    int id; // indice du noeud
    int acc; // accumulateur de bit de comparaisons 
    Node *left;
    Node *right;

};


struct Tree { //JEREMY
    
    int threshold;
    int feature_index; 
    int id; // indice du noeud
    int acc; // accumulateur de bit de comparaisons 
    struct Tree *left;
    struct Tree *right;
    bool is_leaf() const {
        return !this->left and !this->right;
    }

    void free_tree(Tree *root) {
        if (!root)
            return;
        if (root->is_leaf()) {
            delete root;
        } else {
            free_tree(root->left);
            free_tree(root->right);
        }
    }

    void print(Tree *root, std::string path) {
        if (!root)
            return;
        if (root->is_leaf()) {
            std::cout << path << " " << root->id << std::endl;
        } else {
            path = path + " " + std::to_string(root->id);
            print(root->right, path);
            print(root->left, path);
        }
    }
};



struct PROBOServer::Imp{
    // using ctx_ptr_t = std::unique_ptr<Ctxt>; // a remplacer par l'equivalent en TFHE : Ctx = LweSample
    Imp() {}
    ~Imp() {root->free_tree(root); delete root;}

    // read the file and put the threshold into threshold_ and the mapping id:feature_index into id_2_feature_index_

    bool load(std::string const& tree_file) {
        std::ifstream fd(tree_file);
        if (!fd.is_open())
            return false;
        bool ok = true;
        ok &= load_threshold(fd);
        ok &= load_mapping(fd);
        // ok &= build_tree(); //JEREMY
        fd.close();
        return ok;
    }

    bool load_threshold(std::istream &fd) {
        std::string line;
        std::getline(fd, line, '\n');
        auto fields = util::split_by(line, ',');
        if (fields.empty())
            return false;
        thresholds_.resize(fields.size());
        bool ok = true;
        std::transform(fields.cbegin(), fields.cend(), thresholds_.begin(),
                       [&ok](const std::string &field) -> long {
                           auto f = util::trim(field);
                           size_t pos;
                           long val = std::stol(f, &pos, 10);
                           if (pos != f.size())
                               ok = false;
                           return val;
                       });
        return ok;
    }

    bool load_mapping(std::istream &fd) {
        std::string line;
        std::getline(fd, line, '\n');
        auto fields = util::split_by(line, ',');
        if (fields.empty())
            return false;
        id_2_feature_index_.clear();
        bool ok = true;
        for (const auto &field : fields) {
            auto pair = util::split_by(field, ':');
            if (pair.size() != 2)
                return false;
            long id = std::stol(pair[0], nullptr, 10);
            long feature_index = std::stol(pair[1], nullptr, 10);
            id_2_feature_index_.insert({id, feature_index});
        }
        return ok;
    }
    
    bool build_tree(){
        int depth = log2(thresholds_.size()+1)-1; // Profondeur de l'arbre
        std::vector<Node*> Tree[depth + 1]; // Tree = Tableau de d+1 étages


        // Initialisation de la racine : unique element de l'etage B_0
        Node *root = new Node();
        root->id = 0;
        root->threshold = thresholds_.at(root->id);
        root->feature_index = id_2_feature_index_.find(root->id)->second;
        root->acc = 1;
        Tree[0].push_back(root);
        int pos = 1;

        // Construction de l'arbre par etage
        for (int j = 1; j < depth + 1; j++) // Etage B_j cf. paper PROBONITE
        {
           for (int l = 1 ; l <= pow(2,j); l++) // Noeud B_j^l cf. paper PROBONITE
           {
            Node *node = new Node();
            node->id = pos; // pow(2,j-1) + l;
            node->threshold = thresholds_.at(node->id);
            node->feature_index = id_2_feature_index_.find(node->id)->second;
            node->acc = 1;
            Tree[j].push_back(node);
            pos++;
           }
        }
        
        // Linkage entre parents et enfants
        for (int j = 0; j < depth ; j++)
        {
            std::vector<Node*> Bj = Tree[j];
            for (int l = 0; l < Bj.size(); l++)
            {
               Node* parent_node = Bj.at(l);
               parent_node->left = Tree[j+1].at(2*l);
               parent_node->right = Tree[j+1].at(2*l + 1);
            }
        }
        return true ;
    }

    bool receive_bootstrapping_key(const LweBootstrappingKey *bk, std::iostream &conn);

    // read the client's stream and put the encrypted features into features_
    bool receive_feature(std::vector<LweSample*> &features, std::iostream &conn);

    // Attendre que JEREMY implemente la structre Node
    // std::vector<LweSample*> BlindNodeSelection(LweSample* b, 
    //                                             std::vector<Node*> CurrentStageOfAccumulator, 
    //                                             std::vector<Node*> NextStageOfAccumulator);

    int BlindArrayAccess(std::vector<LweSample*> features, LweSample* enc_feature_index);

    // give the bit b = feature < enc_threshold
    LweSample* Compare(LweSample* feature, LweSample* enc_threshold, LweBootstrappingKey* BK);




    void run(tcp::iostream &conn);


    std::vector<int> thresholds_ ; //contient les thresholds en clair
    std::map<int, int> id_2_feature_index_; //contient les mapping id::feature_index
    std::vector<LweSample*> const features_ ; // vecteur de features du client chiffré
    Tree *root;
    
};


