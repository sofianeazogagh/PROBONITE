#include "../include/network/PROBO.hpp"
#include "../include/util/literal.hpp"


#include "tfhe/tfhe_core.h"
#include "tfhe/numeric_functions.h"
#include "tfhe/lwe-functions.h"
#include "tfhe/tfhe_gate_bootstrapping_functions.h"

#include<fstream>
#include<vector>



#define SECALPHA pow(2., -20) // A modifier plus tard
#define SEC_PARAMS_N 1024                   /// TLweParams
#define SECLEVEL 128 // security level lambda 



struct PROBOClient::Imp{

    Imp() {}
    ~Imp() {}
    bool load(std::string const& file) {
        std::ifstream fd(file);
        if (!fd.is_open())
            return false;

        std::string line;
        std::getline(fd, line);
        if (line.empty())
            return false;
        auto fields = util::split_by(line, ',');
        
        features_.resize(fields.size());
        bool ok = true;
        std::transform(fields.cbegin(), fields.cend(), features_.begin(),
                        [&ok](const std::string &field) -> long {
                            auto f = util::trim(field);
                            size_t pos;
                            long v = std::stol(f, &pos, 10);
                            if (pos != f.size())
                                ok = false;
                            return v; 
                        });
        fd.close();
        return ok;
    }

    void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn)
    {
        conn << &params;
    }

    void send_bootstrapping_key(const LweBootstrappingKey *bk, std::ostream &conn) const
    {
        conn << &bk;
    }

    void encrypt_features(TFheGateBootstrappingSecretKeySet *secret, const LweParams *in_out_params)
    {   
       
        enc_features_ = new_LweSample_array(features_.size(),in_out_params);
        for (size_t i = 0; i < features_.size(); i++)
        {   
            Torus32 mu = modSwitchToTorus32(features_[i], SEC_PARAMS_N);
            lweSymEncrypt(enc_features_ + i, mu, SECALPHA, secret->lwe_key);
        }
    }

    void send_encrypted_features(std::ostream &conn) const {
        int32_t nummber_of_features = features_.size();
        conn << nummber_of_features << '\n';
        for (size_t i=0 ; i< nummber_of_features; i++)
            conn << (enc_features_ + i);
    }

    void run(tcp::iostream &conn){
        // Generate parameters by giving security level
        TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(SECLEVEL);
        const LweParams *in_out_params = params->in_out_params;
        // Send these parameters
        send_params(params, conn); 

        // Generate the secret keyset by giving params
        TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(params);
        const LweBootstrappingKey *bk = secret->cloud.bk;
        send_bootstrapping_key(bk, conn);

        // in loop do-while : send BK, encrypt features, send encrypted features and wait result
        send_bootstrapping_key(bk, conn);
        encrypt_features(secret, in_out_params);
        send_encrypted_features(conn);
    }

    std::vector<int32_t> features_;
    LweSample *enc_features_;

};

void test_encrypt_features(LweSample* enc_features, std::vector<int32_t> features)
{
    // Generate parameters by giving security level
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(SECLEVEL);
    const LweParams *in_out_params = params->in_out_params;

    // Generate the secret keyset by giving params
    TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(params);
    const LweBootstrappingKey *bk = secret->cloud.bk;

    enc_features = new_LweSample_array(features.size(),in_out_params);
    for (size_t i = 0; i < features.size(); i++)
    {   
        Torus32 mu = modSwitchToTorus32(features[i], SEC_PARAMS_N);
        lweSymEncrypt(enc_features + i, mu, SECALPHA, secret->lwe_key);
        printf("the encrypted features %d are (%p,%d)\n",features[i],(enc_features + i )->a, (enc_features +i)->b);
    }

    std::vector<int32_t> dec_features;
    for (size_t i = 0; i < features.size(); i++)
    {   
        Torus32 dec = lweSymDecrypt(enc_features + i,secret->lwe_key,SEC_PARAMS_N);
        dec_features.push_back(modSwitchFromTorus32(dec,SEC_PARAMS_N));
        printf("the decrypted features (%p,%d) are %d\n",(enc_features + i)->a,(enc_features + i )->b, dec_features[i]);
    }

}


int main(int argc, char **argv)
{   
    
    std::vector<int32_t> features = {2, 3, 6, 9, 256, 90};
    LweSample* enc_features;
    test_encrypt_features(enc_features, features);

    return 0;
        
}