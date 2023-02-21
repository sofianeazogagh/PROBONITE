#include "../include/network/PROBO.hpp"
#include "../include/util/literal.hpp"


#include "tfhe/tfhe_core.h"
#include "tfhe/numeric_functions.h"
#include "tfhe/lwe-functions.h"
#include "tfhe/tfhe_gate_bootstrapping_functions.h"

#include<fstream>
#include<vector>







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
