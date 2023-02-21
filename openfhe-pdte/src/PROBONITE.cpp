

// #include<string>
// #include<map>
// #include<vector>

#include<string>
#include<map>
#include<vector>
#include<iostream>
#include <fstream>

// #include "../include/network/PROBO.hpp"


#include "binfhe/binfhecontext.h"
#include "binfhe/lwe-pke.h"
#include "binfhe/binfhe-base-scheme.h"



using namespace lbcrypto;

using namespace std;


struct Node{
    int threshold;
    int feature_index;
    int acc;
    struct Node *left;
    struct Node *right;
};




void AbsorptionInPlace(LWECiphertext& ctx, NativeInteger cst)
{
    ctx->GetA().ModMulEq(cst);
    ctx->GetB().ModMulFastEq(cst, ctx->GetModulus());
}

void AdditionInPlace(LWECiphertext& ct1, LWECiphertext ct2)
{   
    ct1->GetA().ModAddEq(ct2->GetA());
    ct1->GetB().ModAddFastEq(ct2->GetB(), ct1->GetModulus());
}

void SubInPlace(LWECiphertext& ct1, LWECiphertext ct2)
{
    ct1->GetA().ModSubEq(ct2->GetA());
    ct2->GetB().ModSubFastEq(ct2->GetB(), ct1->GetModulus());
}

void AddInPlaceConst(LWECiphertext& ct1, NativeInteger cst)
{
    ct1->GetB().ModAddFastEq(cst, ct1->GetModulus());
}

void SubInPlaceConst(LWECiphertext& ct1, NativeInteger cst)
{
    ct1->GetB().ModSubFastEq(cst, ct1->GetModulus());
}

NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q){
    return NativeInteger(
               static_cast<uint64_t>(std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble())))
        .Mod(q);
}

LWECiphertext ModSwitch(NativeInteger q, ConstLWECiphertext ctQ){
    auto n = ctQ->GetLength();
    auto Q = ctQ->GetModulus();
    NativeVector a(n, q);

    for (size_t i = 0; i < n; ++i)
        a[i] = RoundqQ(ctQ->GetA()[i], q, Q);

    NativeInteger b = RoundqQ(ctQ->GetB(), q, Q);

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

LWECiphertext KeySwitch(const std::shared_ptr<LWECryptoParams> params, ConstLWESwitchingKey K,
                                             ConstLWECiphertext ctQN){
    uint32_t n          = params->Getn();
    uint32_t N          = params->GetN();
    NativeInteger Q     = params->GetqKS();
    uint32_t baseKS     = params->GetBaseKS();
    uint32_t digitCount = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseKS)));

    // creates an empty vector
    NativeVector a(n, Q);
    NativeInteger b = ctQN->GetB();
    for (size_t i = 0; i < N; ++i) {
        NativeInteger atmp = ctQN->GetA(i);
        for (size_t j = 0; j < digitCount; ++j, atmp /= baseKS) {
            uint64_t a0 = (atmp % baseKS).ConvertToInt();
            for (size_t k = 0; k < n; ++k)
                a[k].ModSubFastEq(K->GetElementsA()[i][a0][j][k], Q);
            b.ModSubFastEq(K->GetElementsB()[i][a0][j], Q);
        }
    }

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(std::move(a), b));
}

template <typename Func>
RLWECiphertext BootstrapFuncCore(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWACCKey ek,
                                               ConstLWECiphertext ct, const Func f, const NativeInteger fmod){
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    NativeInteger Q = LWEParams->GetQ();
    uint32_t N      = LWEParams->GetN();
    NativeVector m(N, Q);
    // For specific function evaluation instead of general bootstrapping
    NativeInteger ctMod    = ct->GetModulus();
    uint32_t factor        = (2 * N / ctMod.ConvertToInt());
    const NativeInteger& b = ct->GetB();
    for (size_t j = 0; j < (ctMod >> 1); ++j) {
        NativeInteger temp = b.ModSub(j, ctMod);
        m[j * factor]      = Q.ConvertToInt() / fmod.ConvertToInt() * f(temp, ctMod, fmod);
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));
    // ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());
    return acc;
}


template <typename Func>
LWECiphertext BootstrapFunc(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                          ConstLWECiphertext ct, const Func f, const NativeInteger fmod){
    auto acc = BootstrapFuncCore(params, EK.BSkey, ct, f, fmod);

    std::vector<NativePoly>& accVec = acc->GetElements();
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    auto ctExt      = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
    auto& LWEParams = params->GetLWEParams();
    // Modulus switching to a middle step Q'
    auto ctMS = ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return ModSwitch(fmod, ctKS);
}


// Evaluate large-precision sign
LWECiphertext EvalSignModified(ConstLWECiphertext ct,
                                     BinFHEContext cc){


    auto params        = cc.GetParams();
    NativeInteger beta = cc.GetBeta();
    auto EKs = map<uint32_t, RingGSWBTKey>(*(cc.GetBTKeyMap()));
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();

    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    while (mod > q) {
        cttmp = cc.EvalFloor(cttmp);
        mod   = mod / q * 2 * beta;
        // round Q to 2betaQ/q
        cttmp = ModSwitch(mod, cttmp);

        if (EKs.size() == 3) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    AddInPlaceConst(cttmp, beta);

    // if the ended q is smaller than q, we need to change the param for the final boostrapping
    auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (x < q / 2) ? (0) : (1);
    };
    cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    SubInPlaceConst(cttmp, q >> 2);
    return cttmp;
}





struct Server{


    /**
     * @brief aggregation des accumulateur de Ej
     * @param ACC vecteur d'accumulateur chiffré de l'étage E_{j-1}
     * @param b bit de comparaison chiffré
     * @return vecteur d'accumulateur de E_{j}
    */
    vector<LWECiphertext> AccAggregation(vector<LWECiphertext> ACC, LWECiphertext b)
    {
        vector<LWECiphertext> NewACC;
        for (auto acc : ACC)
        {
            auto acc_right = cc.EvalBinGate(AND,acc,cc.EvalNOT(b));
            auto acc_left = cc.EvalBinGate(AND,acc,b);
            NewACC.push_back(acc_right);
            NewACC.push_back(acc_left);
        }
        return NewACC;
    }


    /**
     * @brief Blind Node Selection
     * 
     * @param ACC vecteur d'accumulateur aggregé 
     * @param current_nodes Vecteurs de Noeuds de l'étage
     * @return vecteur de 2 chiffrés : threshold et feature_index
     */
    auto BlindNodeSelection(vector<LWECiphertext> ACC, vector<Node> current_nodes)
    {
        vector<LWECiphertext> result;

        // Initialization of the result
        auto threshold_enc = make_shared<LWECiphertextImpl>(*ACC.at(0));
        AbsorptionInPlace(threshold_enc,current_nodes.at(0).threshold);
        auto index_enc = make_shared<LWECiphertextImpl>(*ACC.at(0));
        AbsorptionInPlace(index_enc,current_nodes.at(0).feature_index);
        for(int i = 1; i < ACC.size(); i++)
        {
            auto tmp1 = make_shared<LWECiphertextImpl>(*(ACC.at(i)));
            auto tmp2 = make_shared<LWECiphertextImpl>(*(ACC.at(i)));
            AbsorptionInPlace(tmp1,current_nodes.at(i).threshold);
            AbsorptionInPlace(tmp2,current_nodes.at(i).feature_index);
            AdditionInPlace(threshold_enc,tmp1);
            AdditionInPlace(index_enc,tmp2);
        }

        result.push_back(threshold_enc);
        result.push_back(index_enc);
        return result;
    }

    /**
     * @brief Blind Array Access
     * 
     * @param index indice chiffré de la feature
     * @param enc_features vecteur des features du client
     * @return feature[index] chiffré 
     */
    LWECiphertext BlindArrayAccess(LWECiphertext index, vector<LWECiphertext> enc_features);

    /**
     * @brief Comparaison privée entre deux chiffrés : feature < threshold
     * 
     * @param feature feature du client
     * @param threshold threshold du noeud selectionné
     * @return bit de comparaison : 1 si feature < threshold et 0 sinon
     */
    LWECiphertext Comparison(LWECiphertext feature, LWECiphertext threshold, int p)
    {
        auto diff = make_shared<LWECiphertextImpl>(*feature);
        //feature - threshold
        SubInPlace(diff,threshold);

        // auto f3 = [](NativeInteger x, NativeInteger q) -> NativeInteger {
        //     return 1;
        // };

        // auto lut = cc.GenerateLUTviaFunction(f3,q);
        // auto sign = cc.EvalFunc(diff,lut);
        // AddInPlaceConst(diff,p/2);

        auto sign = cc.EvalSign(diff);
        // auto sign = EvalSignModified(diff,cc);

        
        return sign;

    }

    BinFHEContext cc;
    std::vector<int> thresholds_ ;
    std::vector<int> feature_index_;
    std::vector<LWECiphertext> enc_features_;

};


vector<LWECiphertext> encrypt_features(LWEPrivateKey sk, BinFHEContext cc, vector<LWEPlaintext> features_)
{   
    vector<LWECiphertext> enc_features_ ;
    auto p = cc.GetMaxPlaintextSpace().ConvertToInt();
    for (size_t i = 0; i < features_.size(); i++)
    {   
        enc_features_.push_back(cc.Encrypt(sk, features_.at(i), FRESH, p));
    }
    return enc_features_;
}

vector<LWEPlaintext> decrypt_features(LWEPrivateKey sk, BinFHEContext cc, vector<LWECiphertext> enc_features_)
{
    vector<LWEPlaintext> features_;
    auto p = cc.GetMaxPlaintextSpace().ConvertToInt();
    for (size_t i = 0; i < enc_features_.size(); i++)
    {
        LWEPlaintext result;
        cc.Decrypt(sk, enc_features_.at(i), &result, p);
        cout << "Decrypted = " << result << endl;
    }
    return features_;
}


void UniTEST_AccAggregation(Server s, LWEPrivateKey sk)
{
    

    // Essayer avec EvalSign
    vector<LWEPlaintext> ACC_clear = {0,0,1,0};
    vector<LWECiphertext> ACC_enc;

    // First we encrypt the accumulator
    for (auto acc : ACC_clear)
    {
        auto acc_enc = s.cc.Encrypt(sk,acc);
        ACC_enc.push_back(acc_enc);
    }

    // Then we creat an encrypted bit
    auto b = s.cc.Encrypt(sk,0);
    auto NewACC_enc = s.AccAggregation(ACC_enc,b);


    // finally we test the aggregation function
    for (auto acc_enc : NewACC_enc)
    {
        LWEPlaintext acc_res;
        s.cc.Decrypt(sk,acc_enc,&acc_res);
        cout << acc_res << " ";
    }
    cout << endl;

}


void UniTEST_Absorption(Server s, LWEPrivateKey sk, int p)
{
    for (int i = 0; i < p; i++)
    {
        LWEPlaintext ptxt = 1;
        LWECiphertext ctx = s.cc.Encrypt(sk,ptxt, BOOTSTRAPPED, p);
        NativeInteger cst = i;
        auto res_ctx = make_shared<LWECiphertextImpl>(*ctx);
        AbsorptionInPlace(res_ctx,cst);
        LWEPlaintext result;
        s.cc.Decrypt(sk,res_ctx,&result, p);
        cout << "Decrypted = " << result << ". Expected = " << cst % p << endl;
    }
}


void UniTEST_Addition(Server s, LWEPrivateKey sk, int p)
{
    for (int i = 0; i < p; i++)
    {
        LWEPlaintext ptxt1 = 1;
        LWEPlaintext ptxt2 = i;
        LWECiphertext ctx1 = s.cc.Encrypt(sk,ptxt1, BOOTSTRAPPED, p);
        LWECiphertext ctx2 = s.cc.Encrypt(sk,ptxt2, BOOTSTRAPPED, p);
        auto res_ctx = make_shared<LWECiphertextImpl>(*ctx1);
        AdditionInPlace(res_ctx,ctx2);
        LWEPlaintext result;
        s.cc.Decrypt(sk,res_ctx,&result, p);
        cout << "Decrypted = " << result << ". Expected = " << ptxt1 + ptxt2 << endl;
    }
}




void UniTEST_BlindNodeSelection(Server s, LWEPrivateKey sk, int p)
{

    // Creating encrypted accumulator
    vector<LWEPlaintext> ACC_clear = {0,0,0,1};
    vector<LWECiphertext> ACC_enc;
    // First we encrypt the accumulator
    for (auto acc : ACC_clear)
    {
        auto acc_enc = s.cc.Encrypt(sk,acc, BOOTSTRAPPED, p);
        ACC_enc.push_back(acc_enc);
    }

    
    // Creating Nodes
    vector<Node> nodes(ACC_clear.size());

    nodes.at(0).threshold = 1;
    nodes.at(0).feature_index = 2;
    nodes.at(1).threshold = 3;
    nodes.at(1).feature_index = 4;
    nodes.at(2).threshold = 5;
    nodes.at(2).feature_index = 6;
    nodes.at(3).threshold = 7;
    nodes.at(3).feature_index = 8;

    // testing BNS
    auto node_selected = s.BlindNodeSelection(ACC_enc,nodes);


    //verifying result
    LWEPlaintext result_threshold, result_index;
    s.cc.Decrypt(sk,node_selected.at(0),&result_threshold, p);
    s.cc.Decrypt(sk,node_selected.at(1),&result_index, p);
    cout << "Decrypted threshold = " << result_threshold << endl;
    cout << "Decrypted index = " << result_index << endl;

}



void UniTEST_Comparison(Server s, LWEPrivateKey sk, int p, int q, int Q)
{
    LWEPlaintext ptx1 = 3;
    LWEPlaintext ptx2 = 2;

    // auto ct1 = s.cc.Encrypt(sk,ptx1,BOOTSTRAPPED,p);
    // auto ct2 = s.cc.Encrypt(sk,ptx2,BOOTSTRAPPED,p);
    cout << "Q = " << Q << endl;
    auto ct1 = s.cc.Encrypt(sk,ptx1,BOOTSTRAPPED,p,Q);
    auto ct2 = s.cc.Encrypt(sk,ptx2,BOOTSTRAPPED,p,Q);


    auto b = s.Comparison(ct1,ct2, p);

    // AbsorptionInPlace(b,3);

    LWEPlaintext result;
    s.cc.Decrypt(sk,b,&result, p);
    cout << "(" << ptx1 << " < " << ptx2 << ") = " << result << endl;

}



void UniTEST_CompAndAccAggregation(Server s, LWEPrivateKey sk, int p, int Q)
{

    LWEPlaintext ptx1 = 4;
    LWEPlaintext ptx2 = 1;


    auto ct1 = s.cc.Encrypt(sk,ptx1,BOOTSTRAPPED,p,Q);
    auto ct2 = s.cc.Encrypt(sk,ptx2,BOOTSTRAPPED,p,Q);
    auto b = s.Comparison(ct1,ct2, p);
    
    vector<LWEPlaintext> ACC_clear = {0,1};
    vector<LWECiphertext> ACC_enc;

    // First we encrypt the accumulator
    for (auto acc : ACC_clear)
    {
        auto acc_enc = s.cc.Encrypt(sk,acc,BOOTSTRAPPED,p,Q);
        ACC_enc.push_back(acc_enc);
    }

    // auto b = s.cc.Encrypt(sk,0);
    auto NewACC_enc = s.AccAggregation(ACC_enc,b);


    // finally we test the aggregation function
    for (auto acc_enc : NewACC_enc)
    {
        LWEPlaintext acc_res;
        s.cc.Decrypt(sk,acc_enc,&acc_res);
        cout << acc_res << " ";
    }
    cout << endl;

}

int main()
{

    Server s;

    //Set CryptoContext
    cout << "Setup the CryptoContext..." << endl;
    s.cc = BinFHEContext();
    uint32_t logQ = 17;
    s.cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);


    int Q      = 1 << logQ;
    int q      = 4096;                                               // q
    int factor = 1 << int(logQ - log2(q));                           // Q/q
    int p      = s.cc.GetMaxPlaintextSpace().ConvertToInt() * factor;  // Obtain the maximum plaintext space
    cout << "p = " << p << endl;

    // Key generation
    cout << "Generating the seceret key..." << endl;
    auto sk = s.cc.KeyGen();

    cout << "Generating the bootstrapping key..." << endl;
    s.cc.BTKeyGen(sk);

    // cout << "Completed the key generation." << endl;
    // vector<LWEPlaintext> features_ = {0, 1, 2, 3, 4, 5, 6, 7};

    // cout << "Encrypting the features..." << endl;
    // s.enc_features_ = encrypt_features(sk, s.cc, features_);

    // cout<< "Decrypting the features..."<< endl;
    // auto features_decrypted = decrypt_features(sk,s.cc,s.enc_features_);

    // cout << "Test Accumulator Aggregation Function" << endl;
    // UniTEST_AccAggregation(s,sk);

    // cout << "Test absorption" << endl;
    // UniTEST_Absorption(s,sk,p);

    // cout << "Test addition" << endl;
    // UniTEST_Addition(s,sk,p);

    // cout << "Test Blind Node selection" << endl;
    // UniTEST_BlindNodeSelection(s,sk,p);

    cout << "Test Comparison Function" << endl;
    UniTEST_Comparison(s,sk,p,q,Q);

    // cout << "Test Comparison and Aggregation Functions" << endl;
    // UniTEST_CompAndAccAggregation(s,sk,p,Q);
    

}