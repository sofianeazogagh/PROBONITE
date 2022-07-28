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
    for (int i = 0; i < size; i++){printf("%d,",LUT->coefsT[i]);}
    printf("]\n");
}



/**
     * @brief Cmux operation giving accum*X^ai if bki = 1 or acc if bk = 0
     * @param result the output LWE sample
     * @param accum the Torus Polynomial encrypting in TLWE Sample
     * @param bki the selector of the CMux encrypting in TGSW Sample
     * @param barai the integer ai modulo 2N
     * @param bk_params the parameters of the bootstrapping key
*/
void Cmux(TLweSample *result, const TLweSample *accum, const TGswSample *bki, const int32_t barai,
                    const TGswParams *bk_params) {

    // ACC = BKi*[(X^barai-1)*ACC]+ACC
    // temp = (X^barai-1)*ACC
    tLweMulByXaiMinusOne(result, barai, accum, bk_params->tlwe_params);
    // temp = temp * BKi
    tGswExternMulToTLwe(result, bki, bk_params);
    // ACC = ACC + temp
    tLweAddTo(result, accum, bk_params->tlwe_params);
}

/**
     * Blind Rotation operation giving accum*X^sum(bara_i.s_i)
     * @param accum the TLWE sample to multiply
     * @param bk An array of n TGSW samples where bk_i encodes s_i
     * @param bara An array of n coefficients between 0 and 2N-1
     * @param bk_params The parameters of bk
*/
void BlindRotation(TLweSample *accum, const TGswSample *bk, const int32_t *bara, const int32_t n, const TGswParams *bk_params) {

    TLweSample *temp = new_TLweSample(bk_params->tlwe_params);
    TLweSample *temp2 = temp;
    TLweSample *temp3 = accum;

    for (int32_t i = 0; i < n; i++) {
        const int32_t barai = bara[i];
        if (barai == 0) continue; // easy case
        Cmux(temp2, temp3, bk + i, barai, bk_params);
        std::swap(temp2, temp3);
    }
    if (temp3 != accum) {
        tLweCopy(accum, temp3, bk_params->tlwe_params);
    }

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
void Public_FB_woKS(LweSample *result, TorusPolynomial *LUT, const LweSample *x, const LweBootstrappingKey *bk) {

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


    //acc = (0,testvect) 
    TLweSample *acc = new_TLweSample(accum_params);
    tLweNoiselessTrivial(acc,testvect,accum_params);

    BlindRotation(acc,bk->bk,bara,n,bk_params);
    SampleExtraction(result,acc,0,extract_params,accum_params);


    delete[] bara;
    delete_TorusPolynomial(testvect);
    delete_TLweSample(acc);
}


/**
     * @brief Functionnal Bootstrapping on a public LUT with Key Switching
     * @param result The resulting LWE sample
     * @param LUT the public polynomial LUT
     * @param x The input LWE sample
     * @param bk The bootstrapping + keyswitch key
 */
void Public_FB(LweSample* result, TorusPolynomial *LUT, const LweSample *x, const LweBootstrappingKey *bk)
{
    LweSample* u = new_LweSample(&bk->accum_params->extracted_lweparams);
    Public_FB_woKS(u,LUT,x,bk);
    lweKeySwitch(result,bk->ks,u);

    delete_LweSample(u);
}


int main()
{   

    // Parameters of TFHE

    const int32_t N = 1024; // size of LUT
    const int32_t k = 1;
    const int32_t n = 500;
    const int32_t l_bk = 3; //ell
    const int32_t Bgbit_bk = 10;
    const int32_t ks_t = 15;
    const int32_t ks_basebit = 1;
    const double alpha_in = 5e-4;
    const double alpha_bk = 9e-9;

    const LweParams *in_params = new_LweParams(n, alpha_in, 1. / 16.);
    const TLweParams *accum_params = new_TLweParams(N, k, alpha_bk, 1. / 16.);
    const TGswParams *bk_params = new_TGswParams(l_bk, Bgbit_bk, accum_params);
    const LweParams *extract_params = &accum_params->extracted_lweparams;

    // Keys generation

    LweBootstrappingKey *bk = new_LweBootstrappingKey(ks_t,ks_basebit,in_params,bk_params);
    LweKey *key = new_LweKey(in_params);
    lweKeyGen(key);
    TGswKey *key_bk = new_TGswKey(bk_params);
    tGswKeyGen(key_bk);




        
    // Define the LUT
    TorusPolynomial *LUT = new_TorusPolynomial(N);
    for (int32_t i = 0; i < N; i++)
    {   
        LUT->coefsT[i] = i; // LUT = [0,1,2,3,.....,N-1]
    }
    print_LUT(LUT,N);



    Torus32 message = 12;
    printf("\n message = %d \n",message);

    // enc = [message]
    LweSample* enc = new_LweSample(in_params);
    lweSymEncrypt(enc,message,0.0001,key);


    //TFHE's bootstrapping operation
    // Torus32 mu = 1; // LUT = [mu,...,mu]
    // tfhe_bootstrap(result_of_FB,bk,mu,enc);


    //Our bootstrapping
    LweSample* result_of_FB = new_LweSample(in_params);
    Public_FB(result_of_FB,LUT,enc,bk);
    

    // is dec = message ?
    Torus32 dec = lweSymDecrypt(result_of_FB,key,N);

    printf("\n dec = %d \n",dec);

    delete_TorusPolynomial(LUT);
    delete_LweSample(enc);
    delete_LweSample(result_of_FB);
}




