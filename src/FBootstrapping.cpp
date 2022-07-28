#include<string>
#include<map>
#include<vector>
#include<iostream>
#include <fstream>

#include "../include/network/PROBO.hpp"



#include "tfhe/tfhe.h"
#include "tfhe/tfhe_garbage_collector.h"
#include "tfhe/tlwe.h"
#include "tfhe/tgsw.h"
#include "tfhe/lwesamples.h"
#include "tfhe/lwekey.h"
#include "tfhe/lweparams.h"
#include "tfhe/polynomials.h"




void print_LUT(TorusPolynomial *LUT, int size)
{   
    printf("\n[");
    // for (int i = 0; i < size; i++){printf("%d,",modSwitchFromTorus32(LUT->coefsT[i],size));}
    for (int i = 0; i < size; i++){printf("%d,",LUT->coefsT[i]);}
    printf("]\n");
}



/**
     * @brief Cmux operation giving acc*X^ai if bki = 1 or acc if bk = 0
     * @param result the output LWE sample
     * @param accum the Torus Polynomial encrypting in TLWE Sample
     * @param bki the selector of the CMux encrypting in TGSW Sample
     * @param barai the integer ai modulo 2N
     * @param bk_params the parameters of the bootstrapping key
*/
void Cmux(TLweSample *result, const TLweSample *accum, const TGswSample *bki, const int32_t barai,
                    const TGswParams *bk_params, TLweKey *tlwekey) {

    

    // TorusPolynomial *polytest = new_TorusPolynomial(SEC_PARAMS_N);
    // printf("\n barai = %d",barai);
    // tLweSymDecrypt(polytest,accum,tlwekey,SEC_PARAMS_N);
    // print_LUT(polytest,SEC_PARAMS_N);




    // ACC = BKi*[(X^barai-1)*ACC]+ACC
    // temp = (X^barai-1)*ACC
    tLweMulByXaiMinusOne(result, barai, accum, bk_params->tlwe_params);
    // temp = temp * BKi
    tGswExternMulToTLwe(result, bki, bk_params);
    // ACC = ACC + temp
    tLweAddTo(result, accum, bk_params->tlwe_params);
}

/**
     * multiply the accumulator by X^sum(bara_i.s_i)
     * @param accum the TLWE sample to multiply
     * @param bk An array of n TGSW samples where bk_i encodes s_i
     * @param bara An array of n coefficients between 0 and 2N-1
     * @param bk_params The parameters of bk
*/
void BlindRotation(TLweSample *accum, const TGswSample *bk, const int32_t *bara, const int32_t n, const TGswParams *bk_params, TLweKey *tlwekey) {

    //TGswSampleFFT* temp = new_TGswSampleFFT(bk_params);
    TLweSample *temp = new_TLweSample(bk_params->tlwe_params);
    TLweSample *temp2 = temp;
    TLweSample *temp3 = accum;
    TorusPolynomial *polytest = new_TorusPolynomial(SEC_PARAMS_N);


    // print_LUT(temp3->b,SEC_PARAMS_N);

    printf("temp3 = ");
    tLweSymDecrypt(polytest,temp3,tlwekey,SEC_PARAMS_N);
    print_LUT(polytest,SEC_PARAMS_N);

    
    for (int32_t i = 0; i < n; i++) {
        const int32_t barai = bara[i];
        if (barai == 0) continue;
        // printf("\n a[%d] = %d",i,barai);

        Cmux(temp2, temp3, bk + i, barai, bk_params,tlwekey);
        std::swap(temp2, temp3);
        // printf("\n a[%d] = %d",i,barai);
        // tLweSymDecrypt(polytest,temp3,tlwekey,SEC_PARAMS_N);
        // print_LUT(polytest,SEC_PARAMS_N);
    }
    if (temp3 != accum) {
        tLweCopy(accum, temp3, bk_params->tlwe_params);
    }

    delete_TorusPolynomial(polytest);
    delete_TLweSample(temp);
}


/**
     * @brief Extract a chosen coefficient of a Torus Polynomial
     * @param result a LWE Sample encrypting the chosen coefficient
     * @param x a TLWE sample encrypting the Torus polynomial
     * @param index the index of the chosen coefficient
     * @param params the parameters of the LWE sample target
     * @param rparams the parameters of the TLWE sample
*/
void SampleExtraction(LweSample* result, const TLweSample* x, const int32_t index, const LweParams* params,  const TLweParams* rparams) {
    const int32_t N = rparams->N;
    const int32_t k = rparams->k;
    assert(params->n == k*N);

    for (int32_t i=0; i<k; i++) {
      for (int32_t j=0; j<=index; j++)
        result->a[i*N+j] = x->a[i].coefsT[index-j];
      for (int32_t j=index+1; j<N; j++)
        result->a[i*N+j] = -x->a[i].coefsT[N+index-j];
    }
    result->b = x->b->coefsT[index];
}


/**
     * @brief Functionnal Bootstrapping on a public LUT without Key Switching
     * @param result The resulting LWE sample
     * @param LUT the public polynomial LUT
     * @param x The input LWE sample
     * @param bk The bootstrapping + keyswitch key
 */
void Public_FB_woKS(LweSample *result, TorusPolynomial *LUT, const LweSample *x, const LweBootstrappingKey *bk, TLweKey *tlwekey) {

    const TGswParams *bk_params = bk->bk_params;
    const TLweParams *accum_params = bk_params->tlwe_params;
    const LweParams *extract_params = &accum_params->extracted_lweparams;
    const LweParams *in_params = bk->in_out_params;
    const int32_t N = accum_params->N;
    const int32_t Nx2 = 2 * N;
    const int32_t n = in_params->n;


    int32_t *bara = new int32_t[N];
    int32_t barb = 10;//modSwitchFromTorus32(x->b, Nx2);
    for (int32_t i = 0; i < n; i++) {
        bara[i] = modSwitchFromTorus32(x->a[i], Nx2);
    }

    // testvect = LUT*X^{-b}
    TorusPolynomial *testvect = new_TorusPolynomial(N);
    if (barb != 0) torusPolynomialMulByXai(testvect, Nx2 - barb, LUT);
    else torusPolynomialCopy(testvect, LUT);


    printf("\n -b = %d \n",-barb);
    print_LUT(testvect,N);

    //acc = (0,testvect) 
    TLweSample *acc = new_TLweSample(accum_params);
    tLweNoiselessTrivial(acc,testvect,accum_params);

    BlindRotation(acc,bk->bk,bara,n,bk_params,tlwekey);
    SampleExtraction(result,acc,0,extract_params,accum_params);


    delete[] bara;
    delete_TorusPolynomial(testvect);
    delete_TLweSample(acc);
}

void Public_FB(LweSample* result, TorusPolynomial *LUT, const LweSample *x, const LweBootstrappingKey *bk, TLweKey *tlwekey)
{
    LweSample* u = new_LweSample(&bk->accum_params->extracted_lweparams);
    Public_FB_woKS(u,LUT,x,bk,tlwekey);
    lweKeySwitch(result,bk->ks,u);

    delete_LweSample(u);
}


/// Generate gate bootstrapping parameters for FHE_NN
TFheGateBootstrappingParameterSet *our_default_gate_bootstrapping_parameters(int minimum_lambda)
{
    if (minimum_lambda > 128)
        std::cerr << "Sorry, for now, the parameters are only implemented for about 128bit of security!\n";

    static const int n = SEC_PARAMS_n;
    static const int N = SEC_PARAMS_N;
    static const int k = SEC_PARAMS_k;
    static const double max_stdev = SEC_PARAMS_STDDEV;

    static const int bk_Bgbit    = SEC_PARAMS_BK_BASEBITS;  //<-- ld, thus: 2^10
    static const int bk_l        = SEC_PARAMS_BK_LENGTH;
    static const double bk_stdev = SEC_PARAMS_BK_STDDEV; 

    static const int ks_basebit  = SEC_PARAMS_KS_BASEBITS; //<-- ld, thus: 2^1
    static const int ks_length   = SEC_PARAMS_KS_LENGTH;
    static const double ks_stdev = SEC_PARAMS_KS_STDDEV;


    LweParams  *params_in    = new_LweParams (n,    ks_stdev, max_stdev);
    TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
    TGswParams *params_bk    = new_TGswParams(bk_l, bk_Bgbit, params_accum);

    TfheGarbageCollector::register_param(params_in);
    TfheGarbageCollector::register_param(params_accum);
    TfheGarbageCollector::register_param(params_bk);

    return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

//////////////////////////////////////// DEBUG Start /////////////////////////////////////////////

void tfhe_blindRotateAndExtract_modified(LweSample *result,
                                       const TorusPolynomial *v,
                                       const TGswSample *bk,
                                       const int32_t barb,
                                       const int32_t *bara,
                                       const int32_t n,
                                       const TGswParams *bk_params) {

    const TLweParams *accum_params = bk_params->tlwe_params;
    const LweParams *extract_params = &accum_params->extracted_lweparams;
    const int32_t N = accum_params->N;
    const int32_t _2N = 2 * N;

    TorusPolynomial *testvectbis = new_TorusPolynomial(N);
    TLweSample *acc = new_TLweSample(accum_params);

    if (barb != 0) torusPolynomialMulByXai(testvectbis, _2N - barb, v);
    else torusPolynomialCopy(testvectbis, v);
    printf("-b = %d",-barb);
    print_LUT(testvectbis,accum_params->N);
    tLweNoiselessTrivial(acc, testvectbis, accum_params);
    tfhe_blindRotate(acc, bk, bara, n, bk_params);
    tLweExtractLweSample(result, acc, extract_params, accum_params);

    delete_TLweSample(acc);
    delete_TorusPolynomial(testvectbis);
}

void tfhe_bootstrap_woKS_modified(LweSample *result,
                                const LweBootstrappingKey *bk,
                                Torus32 mu, const LweSample *x) {

    const TGswParams *bk_params = bk->bk_params;
    const TLweParams *accum_params = bk->accum_params;
    const LweParams *in_params = bk->in_out_params;
    const int32_t N = accum_params->N;
    const int32_t Nx2 = 2 * N;
    const int32_t n = in_params->n;

    TorusPolynomial *testvect = new_TorusPolynomial(N);
    int32_t *bara = new int32_t[N];

    int32_t barb = modSwitchFromTorus32(x->b, Nx2);
    for (int32_t i = 0; i < n; i++) {
        bara[i] = modSwitchFromTorus32(x->a[i], Nx2);
    }

    //the initial testvec = [mu,mu,mu,...,mu]
    for (int32_t i = 0; i < N; i++) testvect->coefsT[i] = mu;

    printf("Initial test vector with mu = %d",mu);
    print_LUT(testvect,N);

    tfhe_blindRotateAndExtract_modified(result, testvect, bk->bk, barb, bara, n, bk_params);

    delete[] bara;
    delete_TorusPolynomial(testvect);
}



void tfhe_bootstrap_modified(LweSample *result,
                           const LweBootstrappingKey *bk,
                           Torus32 mu, const LweSample *x) {

    LweSample *u = new_LweSample(&bk->accum_params->extracted_lweparams);

    tfhe_bootstrap_woKS_modified(u, bk, mu, x);
    // Key Switching
    lweKeySwitch(result, bk->ks, u);

    delete_LweSample(u);
}

//////////////////////////////////////// DEBUG End /////////////////////////////////////////////

int main()
{   


    const int space_msg = MSG_SLOTS;
    const int space_torus = TORUS_SLOTS;

    // // Generate parameters by giving security level
    // TFheGateBootstrappingParameterSet *params = our_default_gate_bootstrapping_parameters(SECLEVEL);
    // const LweParams *in_out_params = params->in_out_params;

    // // Generate the secret keyset by giving params
    // TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(params);
    // const LweBootstrappingKey *bk = secret->cloud.bk;
    // const int N = bk->accum_params->N;

    // const TLweKey *tlwe_key = &secret->tgsw_key->tlwe_key;


    const int32_t N = 1024;
    const int32_t k = 1;
    const int32_t n = 500;
    const int32_t l_bk = 3; //ell
    const int32_t Bgbit_bk = 10;
    const int32_t ks_t = 15;
    const int32_t ks_basebit = 1;
    const double alpha_in = 5e-4;
    const double alpha_bk = 9e-9;
    //const int32_t alpha_ks = 1e-6;

    const LweParams *in_params = new_LweParams(n, alpha_in, 1. / 16.);
    const TLweParams *accum_params = new_TLweParams(N, k, alpha_bk, 1. / 16.);
    const TGswParams *bk_params = new_TGswParams(l_bk, Bgbit_bk, accum_params);
    const LweParams *extract_params = &accum_params->extracted_lweparams;

    LweBootstrappingKey *bk = new_LweBootstrappingKey(ks_t,ks_basebit,in_params,bk_params);
    LweKey *key = new_LweKey(in_params);
    lweKeyGen(key);
    TGswKey *key_bk = new_TGswKey(bk_params);
    tGswKeyGen(key_bk);
    TLweKey *tlwe_key = &key_bk->tlwe_key;




        
    // Define the LUT
    TorusPolynomial *LUT = new_TorusPolynomial(N);
    for (int32_t i = 0; i < N; i++)
    {   
        LUT->coefsT[i] = i; // 1 * phase(enc) = 1 * Delta mu + e
    }
    print_LUT(LUT,N);



    Torus32 mu = 1;
    

    Torus32 message = 12345;
    printf("\n message = %d \n",message);

    // enc = [message]
    LweSample* enc = new_LweSample(in_params);
    lweSymEncrypt(enc,message,0.0001,key);

    LweSample* result_of_FB = new_LweSample(in_params);

    tfhe_bootstrap_modified(result_of_FB,bk,mu,enc);

    // Public_FB(result_of_FB,LUT,enc,bk,tlwe_key);
    
   

    Torus32 dec = lweSymDecrypt(result_of_FB,key,space_msg);
    int32_t m_test = modSwitchFromTorus32(dec,space_msg);

    printf("\n dec = %d \n",dec);
    printf("\n m_test = %d \n",m_test);

    delete_TorusPolynomial(LUT);
    delete_LweSample(enc);
    delete_LweSample(result_of_FB);
}




