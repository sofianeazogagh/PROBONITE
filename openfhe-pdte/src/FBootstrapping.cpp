#include<string>
#include<map>
#include<vector>
#include<iostream>
#include <fstream>

// #include "../include/network/PROBO.hpp"


#include "binfhe/binfhecontext.h"


using namespace lbcrypto;
using namespace std;


// Check what type of function the input function is.
int checkInputFunction(std::vector<NativeInteger> lut, NativeInteger bigger_q) {
    int ret = 0;  // 0 for negacyclic, 1 for periodic, 2 for arbitrary
    if (lut[0] == (bigger_q - lut[lut.size() / 2])) {
        for (size_t i = 1; i < lut.size() / 2; i++) {
            if (lut[i] != (bigger_q - lut[lut.size() / 2 + i])) {
                ret = 2;
                break;
            }
        }
    }
    else if (lut[0] == lut[lut.size() / 2]) {
        ret = 1;
        for (size_t i = 1; i < lut.size() / 2; i++) {
            if (lut[i] != lut[lut.size() / 2 + i]) {
                ret = 2;
                break;
            }
        }
    }
    else {
        ret = 2;
    }

    return ret;
}




std::vector<NativeInteger> GenerateLUTviaVector(std::vector<NativeInteger> A, NativeInteger p, BinFHEContext cc)
{
    if (ceil(log2(p.ConvertToInt())) != floor(log2(p.ConvertToInt()))) {
        std::string errMsg("ERROR: Only support plaintext space to be power-of-two.");
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger q        = cc.GetParams()->GetLWEParams()->Getq();
    cout << "q = " << q << endl;
    // NativeInteger q = 4096;
    NativeInteger interval = q / p;
    usint vecSize          = q.ConvertToInt();
    std::vector<NativeInteger> vec(vecSize);
    for(usint i =0; i<vecSize; i++)
    {
        auto index = i/(interval).ConvertToInt();
        vec[i] = A[index]*interval;
        cout << "i = " << i << ". vec[i] = " << vec[i] << endl;
    }
    return vec;
}




int main()
{

    //Set CryptoContext
    cout << "Setup the CryptoContext..." << endl;
    auto cc = BinFHEContext();
    uint32_t logQ = 12; // Q = input ciphertext modulus
    cc.GenerateBinFHEContext(STD128, true, logQ);

    // Key generation
    cout << "Generating the seceret key..." << endl;
    auto sk = cc.KeyGen();

    cout << "Generating the bootstrapping key..." << endl;
    cc.BTKeyGen(sk);

    cout << "Completed the key generation." << endl;

    int q      = cc.GetParams()->GetLWEParams()->Getq().ConvertToInt();
    int factor = 1 << int(logQ - log2(q)); // Delta ??
    cout << "factor =" << factor << endl;
    int p = cc.GetMaxPlaintextSpace().ConvertToInt() * factor; // le plus grand plaintext space
    // int p = cc.GetMaxPlaintextSpace().ConvertToInt();

    /* GENERATE LUT VIA VECTOR START */

    cout << "Generate LUT via vector.." << endl;
    vector<NativeInteger> my_vector = {0, 1, 2, 3, 4, 5, 6, 7};
    auto lut = GenerateLUTviaVector(my_vector,p,cc);
    cout << "lut size = " << lut.size() << endl;


    cout << "p = " << p << endl;
    cout<< " Evaluate the LUT" << endl;

    for(int i = 0; i<my_vector.size(); i++)
    {
        auto ct1 = cc.Encrypt(sk, i, FRESH, p);
        auto ct_lut = cc.EvalFunc(ct1,lut);

        LWEPlaintext result;
        cc.Decrypt(sk, ct_lut, &result, p);
        cout << "Input: " << i << ". Expected: " << my_vector.at(i) << ". Evaluated = " << result << endl;


    }

    return 0;

}



