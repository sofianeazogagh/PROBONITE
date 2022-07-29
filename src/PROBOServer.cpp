#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>

#include "../include/util/literal.hpp"
// #include "util/Timer.hpp"
#include "../include/network/PROBO.hpp"

#include <tfhe/tfhe_core.h>
#include <tfhe/numeric_functions.h>
#include "tfhe/lwe-functions.h"
#include "tfhe/tfhe_gate_bootstrapping_functions.h"
#include "tfhe/lwesamples.h"

void encrypt_data(int data, LweSample *result, TFheGateBootstrappingSecretKeySet *secret, const LweParams *in_out_params)
{
    Torus32 mu = modSwitchToTorus32(data, 1024);
    lweSymEncrypt(result, mu, pow(2., -25), secret->lwe_key);
}

void decrypt_data(LweSample *sample, TFheGateBootstrappingSecretKeySet *secret, int* result)
{
    Torus32 mu = lweSymDecrypt(sample, secret->lwe_key, 1024);
    *result = modSwitchFromTorus32(mu, 1024);

    //lweSymEncrypt(result, mu, 128, secret->lwe_key);
}

struct Node
{

    Node() : threshold(-1), feature_index(-1), id(-1), acc(-1), left(nullptr), right(nullptr) {}
    ~Node() {} // TODO free node

    int32_t threshold;
    int feature_index;
    int id;  // indice du noeud
    int acc; // accumulateur de bit de comparaisons
    Node *left;
    Node *right;
    LweSample *oblivious_acc;
};


struct PROBOServer
{
    // using ctx_ptr_t = std::unique_ptr<Ctxt>; // a remplacer par l'equivalent en TFHE : Ctx = LweSample
    // Imp() {}
    // ~Imp() {root->free_tree(root); delete root;}

    PROBOServer()
    {
    }
    ~PROBOServer()
    {
        // root->free_tree(root); delete root;
    }

    // read the file and put the threshold into threshold_ and the mapping id:feature_index into id_2_feature_index_

    bool load(std::string const &tree_file)
    {
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

    bool load_threshold(std::istream &fd)
    {
        std::string line;
        std::getline(fd, line, '\n');
        auto fields = util::split_by(line, ',');
        if (fields.empty())
            return false;
        thresholds_.resize(fields.size());
        bool ok = true;
        std::transform(fields.cbegin(), fields.cend(), thresholds_.begin(),
                       [&ok](const std::string &field) -> long
                       {
                           auto f = util::trim(field);
                           size_t pos;
                           long val = std::stol(f, &pos, 10);
                           if (pos != f.size())
                               ok = false;
                           return val;
                       });
        return ok;
    }

    bool load_mapping(std::istream &fd)
    {
        std::string line;
        std::getline(fd, line, '\n');
        auto fields = util::split_by(line, ',');
        if (fields.empty())
            return false;
        id_2_feature_index_.clear();
        bool ok = true;
        for (const auto &field : fields)
        {
            auto pair = util::split_by(field, ':');
            if (pair.size() != 2)
                return false;
            long id = std::stol(pair[0], nullptr, 10);
            long feature_index = std::stol(pair[1], nullptr, 10);
            id_2_feature_index_.insert({id, feature_index});
        }
        return ok;
    }

    bool build_tree()
    {

        // Initialisation de la racine : unique element de l'etage B_0
        depth = log2(thresholds_.size());
        Node *root = new Node();
        root->id = 0;
        root->threshold = thresholds_.at(root->id);
        root->feature_index = id_2_feature_index_.find(root->id)->second;
        root->acc = 1;


        std::vector<Node *> stage_1 = {root};
        tree.push_back(stage_1);
        // Tree[0].push_back(root);
        int pos = 1;

        // Construction de l'arbre par etage
        for (int j = 1; j < depth + 1; j++) // Etage B_j cf. paper PROBONITE
        {
            std::vector<Node *> stage_elements = {};
            for (int l = 1; l <= pow(2, j); l++) // Noeud B_j^l cf. paper PROBONITE
            {
                Node *node = new Node();
                node->id = pos; // pow(2,j-1) + l;
                node->threshold = thresholds_.at(node->id);
                node->feature_index = id_2_feature_index_.find(node->id)->second;
                node->acc = 1;
                stage_elements.push_back(node);
                pos++;
            }

            tree.push_back(stage_elements);
        }

        // Linkage entre parents et enfants
        for (int j = 0; j < depth; j++)
        {
            std::vector<Node *> Bj = tree[j];
            for (int l = 0; l < Bj.size(); l++)
            {
                Node *parent_node = Bj.at(l);
                parent_node->left = tree[j + 1].at(2 * l);
                parent_node->right = tree[j + 1].at(2 * l + 1);
            }
        }
        return true;
    }

    void intialize_accs(); // initialiser les accumulateur dans les noeuds

    std::vector<LweSample *> BlindNodeSelection(LweSample *b,
                                                std::vector<Node *> CurrentStageOfNode,
                                                std::vector<Node *> NextStageOfNode,
                                                const LweParams *params,
                                                const TFheGateBootstrappingCloudKeySet* cloud_keyset)
    {

        LweSample *theta = new_LweSample(params);
        LweSample *not_b = new_LweSample(params);
        LweSample *index = new_LweSample(params);
        LweSample *acc = new_LweSample(params);

        Node *selected_node = new Node();

        int j = std::log2(CurrentStageOfNode.size());

        bootsNOT(not_b, b, cloud_keyset);
        //printf("%d, %d\n", *(b->a), b->b);

        for (size_t i = 0; i < CurrentStageOfNode.size(); i++)
        {
            Node *parent = CurrentStageOfNode.at(i);

            parent->left->oblivious_acc = new_LweSample(params);
            parent->right->oblivious_acc = new_LweSample(params);
            parent->oblivious_acc = new_LweSample(params);
            
            // initialier l'accumulateur de la racine à un chiffré trivial.
            if(i==0) lweNoiselessTrivial(parent->oblivious_acc, 1, params); 
            

            // mettre à jour les accumulateurs des noeuds du prochain étage
            bootsAND(parent->left->oblivious_acc, b, parent->oblivious_acc, cloud_keyset);
            bootsAND(parent->right->oblivious_acc, not_b, parent->oblivious_acc, cloud_keyset);

            // accumuler les threshold et index 
            lweAddMulTo(theta, parent->left->threshold, parent->left->oblivious_acc, params);
            lweAddMulTo(theta, parent->right->threshold, parent->right->oblivious_acc, params);

            lweAddMulTo(index, parent->right->feature_index, parent->right->oblivious_acc, params);
            lweAddMulTo(index, parent->left->feature_index, parent->left->oblivious_acc, params);
            
        }

        std::vector<LweSample *> result = {theta, index, acc};
        printf("Selected Node : a_theta=%d", *(result.at(0)->a));


        return result;
    }

    int BlindArrayAccess(std::vector<LweSample *> features, LweSample *enc_feature_index);

    // give the bit b = feature < enc_threshold
    LweSample *Compare(LweSample *feature, LweSample *enc_threshold, LweBootstrappingKey *BK);

    // void run(tcp::iostream &conn);

    std::vector<int> thresholds_;                 // contient les thresholds en clair
    std::map<int, int> id_2_feature_index_;       // contient les mapping id::feature_index
    std::vector<LweSample *> const features_;     // vecteur de features du client chiffré
    int depth = log2(thresholds_.size() + 1) - 1; // Profondeur de l'arbre
    std::vector<std::vector<Node *>> tree;        // tree = vecteur de d+1 étages
    //const LweParams* params;                            // paramètres reçus du client
    
};

int main(int argc, char const *argv[])
{

    PROBOServer server;
    server.thresholds_ = {1, 2, 9, 0, 8, 10, 5};

    server.id_2_feature_index_.insert({0, 1});
    server.id_2_feature_index_.insert({1, 4});
    server.id_2_feature_index_.insert({2, 2});
    server.id_2_feature_index_.insert({3, 1});
    server.id_2_feature_index_.insert({4, 3});
    server.id_2_feature_index_.insert({5, 2});
    server.id_2_feature_index_.insert({6, 3});

    // server.id_2_feature_index_.insert({0, 1});

    server.build_tree();

    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(128);
    const LweParams *in_out_params = params->in_out_params;
    TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(params);
    const LweBootstrappingKey *bk = secret->cloud.bk;
    LweSample *b = new_LweSample(in_out_params);
    //server.params = in_out_params;
    // bootsSymEncrypt(carry, 0, secret); // first carry initialized to 0

    encrypt_data(2, b, secret, in_out_params);

    int decrypted_b = 0;
    decrypt_data(b, secret, &decrypted_b);

    printf("Valeur de b déchiffré : %d", decrypted_b);

    //server.BlindNodeSelection(b, server.tree.at(0), server.tree.at(1), in_out_params, &(secret->cloud));

    // encrypt_data(10, b, secret, in_out_params);
    // int result = bootsSymDecrypt(sum, secret);

    // printf("The result is %d", );

    return 0;
}
