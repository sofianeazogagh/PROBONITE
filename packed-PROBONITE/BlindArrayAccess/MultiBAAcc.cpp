#include <iostream>
#include <string>
#include <fstream>

#include "openfhe.h"
using namespace lbcrypto;
using namespace std;

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"


#include "sys/time.h"


const std::string DATAFOLDER = "../keys(20,1to50)";
const std::string PERF = "../perf2(20,1to50).txt";



static double getMillies(timeval timestart, timeval timeend)
{
    long time1 = (timestart.tv_sec * 1000000) + (timestart.tv_usec );
    long time2 = (timeend.tv_sec * 1000000) + (timeend.tv_usec );

return (double)(time2-time1)/1000;
}

CryptoContext<DCRTPoly> Deserialization(PublicKey<DCRTPoly> *pk, PrivateKey<DCRTPoly> *sk)
{
   CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", *pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
    }
    std::cout << "The public key has been deserialized." << std::endl;

    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;

    std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
    if (!erkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
    }
    if (cc->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
    }
    std::cout << "Deserialized the eval rotation keys." << std::endl;

    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", *sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    return cc;
    printf("DEBUG\n");
}


Ciphertext<DCRTPoly> RotateAndSum(Ciphertext<DCRTPoly> ct, CryptoContext<DCRTPoly> cc)
{

  auto N = cc->GetRingDimension(); // assume N = 4
  Ciphertext<DCRTPoly> result(ct); // [a,b,c,d]
  for (int i = 1; i <= log2(N); i++)
  {
    auto permuted_ct = cc->EvalRotate(result, N/pow(2,i)); //[c,d,a,b]
    result = cc->EvalAdd(result,permuted_ct); // [a,b,c,d] + [c,d,a,b] = [a+c,b+d,c+a,d+b]
  }
  return result;
  
}


Ciphertext<DCRTPoly> ConcatCiphertexts(vector<Ciphertext<DCRTPoly>> vec, int max_slots, CryptoContext<DCRTPoly> cc)
{
  Ciphertext<DCRTPoly> result(vec.at(0)); // initialisé au premier chiffrés
  for(int i = 1; i < vec.size(); i++)
  {
    result = cc->EvalAdd(result, cc->EvalRotate(vec.at(i), -i*max_slots));
  }
  return result;
}


vector<Plaintext> GenMaskForDeconcat(int number_of_ciphertext, int max_slots, CryptoContext<DCRTPoly> cc)
{
  vector<Plaintext> Masks;
  vector<int64_t> mask(cc->GetRingDimension(),0);
  for (int i = 0; i < number_of_ciphertext; i++)
  {
    fill(mask.begin()+(i*max_slots), mask.begin()+((i+1)*max_slots),1);
    Plaintext pt_mask = cc->MakePackedPlaintext(mask);
    Masks.push_back(pt_mask);
    fill(mask.begin(),mask.end(),0);
  }

  return Masks;
  
}

vector<Ciphertext<DCRTPoly>> DeconcatCiphertexts(Ciphertext<DCRTPoly> ct_concat, vector<Plaintext> Masks, int number_of_ciphertext, int max_slots, CryptoContext<DCRTPoly> cc)
{

  vector<Ciphertext<DCRTPoly>> result;
  for (int i = 0; i < number_of_ciphertext; i++)
  {
    auto ct = cc->EvalMult(ct_concat,Masks.at(i));
    ct = cc->EvalRotate(ct, i*max_slots); // pas necessaire si on fait un rotate and sum ?
    result.push_back(ct);
  }

  return result;
}

// Fonction pour test unitaire Concat Deconcat
vector<Ciphertext<DCRTPoly>> GenVectorOfCiphertexts(int number_of_ciphertext, int number_of_slots, CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keyPair)
{
  vector<Ciphertext<DCRTPoly>> result;
  for (int i = 0; i < number_of_ciphertext; i++)
  {
    std::vector<int64_t> array(number_of_slots);
    iota(array.begin(), array.end(), 0);
    Plaintext ptarray = cc->MakePackedPlaintext(array);
    auto ctarray = cc->Encrypt(keyPair.publicKey,ptarray);
    result.push_back(ctarray);
  }
  return result;
}



void UniTESTConcatDeconcat(int number_of_client, int max_slots, CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keyPair)
{
  auto Ciphertexts = GenVectorOfCiphertexts(number_of_client,max_slots, cc, keyPair);
  auto Masks = GenMaskForDeconcat(number_of_client,max_slots,cc);
  auto ct_concat = ConcatCiphertexts(Ciphertexts,max_slots,cc);
  Plaintext concat;
  cc->Decrypt(keyPair.secretKey, ct_concat, &concat);
  cout << "Concatened ciphertexts " << concat << endl;
  auto Ciphertexts2 = DeconcatCiphertexts(ct_concat,Masks,number_of_client,max_slots,cc);
  for(int i=0;i<number_of_client;i++)
  {
    Plaintext result, result2;
    cc->Decrypt(keyPair.secretKey, Ciphertexts.at(i), &result);
    cc->Decrypt(keyPair.secretKey, Ciphertexts2.at(i), &result2);
    cout << "Expected " << result  << "Evaluated" << result2 << endl;
  }
}



// Ciphertext<DCRTPoly> Expand(Ciphertext<DCRTPoly> ct, int expansion_factor, int number_of_clients, CryptoContext<DCRTPoly> cc) //expansion factor = max slots
// {
//   vector<Ciphertext<DCRTPoly>> Ciphertexts(expansion_factor,ct);
//   Ciphertext<DCRTPoly> result = cc->EvalMerge(Ciphertexts);
//   for (int i = 1; i < number_of_clients ; i++)
//   {
//     auto ct2 = cc->EvalRotate(ct,i);
//     fill(Ciphertexts.begin(),Ciphertexts.end(),ct2);
//     auto ct3 = cc->EvalMerge(Ciphertexts); // a parallelisé
//     result = cc->EvalAdd(result, cc->EvalRotate(ct3,-i*expansion_factor));
//   }
//   return result;
// }


Ciphertext<DCRTPoly> Expand(Ciphertext<DCRTPoly> ct, int expansion_factor, int number_of_clients, 
                            CryptoContext<DCRTPoly> cc){
  vector<Ciphertext<DCRTPoly>> results_to_be_add;
#pragma omp parallel for
  for (int i = 0; i < number_of_clients; i++)
  {
    auto ct_rotate = cc->EvalRotate(ct,i);
    vector<Ciphertext<DCRTPoly>> Ciphertexts(expansion_factor,ct_rotate);
    auto ct_merge = cc->EvalRotate(cc->EvalMerge(Ciphertexts),-i*expansion_factor);
    results_to_be_add.push_back(ct_merge);
  }

  auto result = cc->EvalAddMany(results_to_be_add);
  return result;
}

// Basé sur OHS
Ciphertext<DCRTPoly> MultiOHS(Ciphertext<DCRTPoly> ct_I, int max_slots, int number_of_clients, CryptoContext<DCRTPoly> cc, Plaintext ptT, Plaintext ptoneN)
{

  auto param = cc->GetCryptoParameters();
  auto t = param->GetPlaintextModulus();
  auto N = cc->GetRingDimension();

  // Here from the evaluation
  // only a-th slot is 0
  
  timeval t_start_expand, t_end_expand;
  gettimeofday(&t_start_expand, NULL);
  auto cta = Expand(ct_I, max_slots,number_of_clients,cc);
  gettimeofday(&t_end_expand, NULL);
  
  auto ctl = cc->EvalSub(cta, ptT); // (2,..,2,1,..,1,4,..,4) - (1,..,5,1,..,5,1,..,5)

  auto ctm = ctl;
  for (int i = 0; i < log2(t - 1); i++) {
    // computed by repeated squaring modulo t (Felmat's Little Theorem)
    ctm = cc->EvalMult(ctm, ctm);
  }
  // ctm is now 0 only for the a-th slot and 1 for the other slots

  // only a-th slot is 1 and 1 for the other slots
  auto ctn = cc->EvalSub(ptoneN, ctm); // (1,1,1,1,1,1) - (1,1,1,0,1,1) = (0,0,0,1,0,0)

  return ctn;
  // result = ( 0 0 0 1 ... )
  // This is a ciphertext where only the a(=3)-th slot is 1 and all other slot
  // values are 0
}


void UniTESTMultiOHS(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keyPair, int max_slots, int number_of_clients, vector<int64_t> clear_I)
{


  ofstream fichier(PERF, ios::out | ios::app);
  Plaintext pt_I = cc->MakePackedPlaintext(clear_I);
  auto ct_I = cc->Encrypt(keyPair.publicKey, pt_I);

  vector<int64_t> vecT(cc->GetRingDimension());
  for (int i = 0; i < number_of_clients; i++)
  {
    iota(vecT.begin()+(i*max_slots), vecT.end()+((i+1)*max_slots), 0);
  }
  Plaintext ptT = cc->MakePackedPlaintext(vecT);


  vector<int64_t> oneN(cc->GetRingDimension(), 1);
  Plaintext ptoneN = cc->MakePackedPlaintext(oneN);
  timeval t_start_ohs, t_end_ohs;
  gettimeofday(&t_start_ohs, NULL);
  auto ct_OHS = MultiOHS(ct_I,max_slots,number_of_clients,cc, ptT, ptoneN);
  gettimeofday(&t_end_ohs, NULL);
  fichier << "(" << max_slots << "," << clear_I.size() <<") = ";
  fichier << std::setprecision(5) << getMillies(t_start_ohs, t_end_ohs) << " ms" << endl;
  

  // Plaintext result;
  // cc->Decrypt(keyPair.secretKey, ct_OHS, &result);
  // cout << "Input " << pt_I << endl;
  // cout << "Ouput " << result << endl;

  fichier.close();

}


Ciphertext<DCRTPoly> MultiBAAcc(Ciphertext<DCRTPoly> Features, Ciphertext<DCRTPoly> ohs , CryptoContext<DCRTPoly> cc)
{
  auto result = cc->EvalMult(Features,ohs);
  return result;
}



int main() {
  timeval t_start, t_end;

  
  // int N = std::pow(2, 15);
  // int t = 2 * N + 1;  // 65537;
  // uint32_t depth = 17;
  // double sigma = 3.2;

//   SecurityLevel securityLevel = HEStd_128_classic;
  // CCParams<CryptoContextBFVRNS> parameters;

  // parameters.SetPlaintextModulus(t);
  // parameters.SetStandardDeviation(sigma);
  // parameters.SetMultiplicativeDepth(depth);
  // parameters.SetMaxRelinSkDeg(2);
  // parameters.SetScalingModSize(60);
  // parameters.SetRingDim(N);
  
  // cout << "Generating the Crypto Context.." << endl;
  // CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  // cc->Enable(PKE);
  // cc->Enable(ADVANCEDSHE);
  // cc->Enable(KEYSWITCH);
  // cc->Enable(LEVELEDSHE);


  // cout << "Generating the KeyPair.." << endl;
  // KeyPair<DCRTPoly> keyPair;
  // keyPair = cc->KeyGen();
  // cc->EvalMultKeyGen(keyPair.secretKey);


  // cout << "Generating the Rotations Keys.." << endl;
  // std::vector<int> indexList;
  // for(int i = 0; i < log2(N); i++){indexList.push_back(pow(2,i));}
  // cc->EvalRotateKeyGen(keyPair.secretKey, indexList);

  // cout << "Generating the Rotations Keys.." << endl;
  // std::vector<int> indexList2;
  // for(int i = 1; i < number_of_clients ; i++){indexList2.push_back(-i*max_slots);}
  // for(int i = 0; i < number_of_clients ; i++){indexList2.push_back(i*max_slots);}
  // for(int i = 1; i < number_of_clients ; i++){indexList2.push_back(-i);}
  // for(int i = 0; i < number_of_clients ; i++){indexList2.push_back(i);}
  // for(int i = 1; i < max_slots ; i++){indexList2.push_back(-i);}
  // for(int i = 0; i < max_slots ; i++){indexList2.push_back(i);}
  // cc->EvalRotateKeyGen(keyPair.secretKey, indexList2);
  // UniTESTConcatDeconcat(number_of_clients,max_slots,cc,keyPair);





  PublicKey<DCRTPoly> pk;
  PrivateKey<DCRTPoly> sk;
  CryptoContext<DCRTPoly> cc = Deserialization(&pk,&sk);
  KeyPair<DCRTPoly> keyPair(pk,sk);

  // vector<int64_t> clear_I = {2,1,4,5}; // indices des features des differents clients
  // int number_of_clients_max = 6; // 100 sur Alien
  // for (int i = 3; i < number_of_clients_max; i++)
  // {
  // vector<int64_t> clear_I(i);
  // iota(clear_I.begin(), clear_I.end(),1);
  // int max_slots = 50; //100 sur Alien
  // // int max_slots = *max_element(clear_I.begin(), clear_I.end()) + 1; // nombre de feature max
  // int number_of_clients = clear_I.size();
  // UniTESTMultiOHS(cc, keyPair, max_slots, number_of_clients, clear_I);
  // }

  int number_of_clients_max = 50;
  int max_slots = 20;

  ofstream fichier(PERF, ios::out | ios::app);

  for (int number_of_clients = 33; number_of_clients < number_of_clients_max; number_of_clients++)
  {
  
  printf("--------Test for (max_slots, number_of_clients) = (%d,%d)-----------\n",max_slots,number_of_clients);
  fichier << "(" << max_slots << "," << number_of_clients << ")=";
  vector<int64_t> clear_I(number_of_clients);
  iota(clear_I.begin(), clear_I.end(),1);

  Plaintext pt_I = cc->MakePackedPlaintext(clear_I);
  auto ct_I = cc->Encrypt(keyPair.publicKey, pt_I);


  auto Features = GenVectorOfCiphertexts(number_of_clients,max_slots, cc, keyPair);

  // Off line 
  auto ct_concat = ConcatCiphertexts(Features,max_slots,cc);
  auto Masks = GenMaskForDeconcat(number_of_clients,max_slots,cc);
  vector<int64_t> vecT(cc->GetRingDimension());
  for (int i = 0; i < number_of_clients; i++){iota(vecT.begin()+(i*max_slots), vecT.end()+((i+1)*max_slots), 0);}
  Plaintext ptT = cc->MakePackedPlaintext(vecT);
  vector<int64_t> oneN(cc->GetRingDimension(), 1);
  Plaintext ptoneN = cc->MakePackedPlaintext(oneN);


  // MultiOHS
  timeval t_start_ohs, t_end_ohs;
  gettimeofday(&t_start_ohs, NULL);
  auto ohs = MultiOHS(ct_I, max_slots,number_of_clients,cc,ptT,ptoneN);
  gettimeofday(&t_end_ohs, NULL);
  fichier << std::setprecision(7) << getMillies(t_start_ohs, t_end_ohs) << endl;
  cout << "Time Multi OHS : " << std::setprecision(7) << getMillies(t_start_ohs, t_end_ohs) << " ms" << '\n';

  // MultiBaacc
  timeval t_start_baacc, t_end_baacc;
  gettimeofday(&t_start_baacc, NULL);
  auto ct_baacc = cc->EvalMult(ct_concat,ohs);
  vector<Ciphertext<DCRTPoly>> Features_selected = DeconcatCiphertexts(ct_baacc,Masks,number_of_clients,max_slots,cc);
  gettimeofday(&t_end_baacc, NULL);
  cout << "Time Multi BAAcc : " << std::setprecision(7) << getMillies(t_start_baacc, t_end_baacc) << " ms" << '\n';

  Plaintext pt_concat, pt_ohs;
  cout << "Input I " << pt_I << endl;

  // for (int i = 0; i < Features_selected.size(); i++)
  // {
  //   Plaintext result;
  //   cc->Decrypt(keyPair.secretKey, Features_selected.at(i), &result);
  //   cout << "Client " << i << " : " << result << endl;
  // }

  }

  fichier.close();

  return 0;
}
