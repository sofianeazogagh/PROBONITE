#include<string>
#include<map>
#include<vector>
#include<iostream>

#include<network/PROBO.hpp>

#include <tfhe/tfhe_core.h>




struct Tree {

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

    ~Imp() { root->free_tree(root); delete root;}

    bool load(std::string const& tree_file);// read the file and put :
                                            // the threshold into threshold_ 
                                            // the mapping id:feature_index into id_2_feature_index_


    bool receive_feature(std::string features_file);// read the client file and put
                                                    // the encrypted features into features_

    std::vector<LweSample*> BlindNodeSelection(LweSample* b, std::vector<LweSample> CurrentStageOfAccumulator, std::vector<LweSample> NextStageOfAccumulator);

    int BlindArrayAccess(std::vector<LweSample*> features, LweSample* enc_feature_index);

    LweSample* CMP(LweSample* feature, LweSample* enc_threshold);

    void run(tcp::iostream &conn);


    std::vector<int> threshold_ ; //contient les thresholds en clair
    std::map<int, int> id_2_feature_index_; //contient les mapping id::feature_index
    std::vector<LweSample*> const features_ ; // vecteur de features du client chiffré
    Tree *root;
};