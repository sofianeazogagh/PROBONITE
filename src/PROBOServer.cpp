#include<string>
#include<map>
#include<vector>
#include<iostream>
#include <fstream>

#include "util/literal.hpp"
#include "util/Timer.hpp"
#include<network/PROBO.hpp>

#include <tfhe/tfhe_core.h>




struct Tree { //JEREMY

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

    // read the file and put the threshold into threshold_ and the mapping id:feature_index into id_2_feature_index_

    bool load(std::string const& tree_file) {
        std::ifstream fd(tree_file);
        if (!fd.is_open())
            return false;
        bool ok = true;
        ok &= load_threshold(fd);
        ok &= load_mapping(fd);
        ok &= build_tree();
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

    bool build_tree(){ // JEREMY
        root = new Tree();
        // construire l'arbre avec threshold_, id_2_feature_index
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
    LweSample* Compare(LweSample* feature, LweSample* enc_threshold, LweBootstrappingKey* BK) {

    };




    void run(tcp::iostream &conn);


    std::vector<int> thresholds_ ; //contient les thresholds en clair
    std::map<int, int> id_2_feature_index_; //contient les mapping id::feature_index
    std::vector<LweSample*> const features_ ; // vecteur de features du client chiffré
    Tree *root;
};
