
// One-HotSlot takes a ciphertext ⟦𝑎⟧ as input and returns a ciphertext such
// that only the a-th slot, is 1 and all others are 0.

#include "openfhe.h"
using namespace lbcrypto;
using namespace std;


#include "sys/time.h"




static double getMillies(timeval timestart, timeval timeend)
{
    long time1 = (timestart.tv_sec * 1000000) + (timestart.tv_usec );
    long time2 = (timeend.tv_sec * 1000000) + (timeend.tv_usec );

return (double)(time2-time1)/1000;
}


Ciphertext<DCRTPoly> OneHotSlot(Ciphertext<DCRTPoly> cta, CryptoContext<DCRTPoly> cc)
{


  auto param = cc->GetCryptoParameters();
  auto t = param->GetPlaintextModulus();
  auto N = cc->GetRingDimension();

  std::vector<int64_t> vecT(N);
  iota(vecT.begin(), vecT.end(), 0);
  Plaintext ptT = cc->MakePackedPlaintext(vecT);
  std::vector<int64_t> oneN(N, 1);
  Plaintext ptoneN = cc->MakePackedPlaintext(oneN);

  // Here from the evaluation
  // only a-th slot is 0
  auto ctl = cc->EvalSub(cta, ptT); // (3,3,3,3,3,3) - (0,1,2,3,4,5) = (3,2,1,0,-1,-2)

  auto ctm = ctl;
  for (int i = 0; i < log2(t - 1); i++) {
    // computed by repeated squaring modulo t (Felmat's Little Theorem)
    ctm = cc->EvalMult(ctm, ctm);
  }
  // ctm is now 0 only for the a-th slot and 1 for the other slots

  // only a-th slot is 1 and 1 for the other slots
  auto ctn = cc->EvalSub(ptoneN, ctm); // (1,1,1,1,1,1) - (1,1,1,0,1,1) = (0,0,0,1,0,0)
  // auto ctone = cc->EvalAtIndex(ctn,3);

  return ctn;
  // result = ( 0 0 0 1 ... )
  // This is a ciphertext where only the a(=3)-th slot is 1 and all other slot
  // values are 0
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

Ciphertext<DCRTPoly> ConcatCiphertext(vector<Ciphertext<DCRTPoly>> vec, int max_features, CryptoContext<DCRTPoly> cc)
{
  Ciphertext<DCRTPoly> result(vec.at(0)); // initialisé au premier chiffrés
  for(int i = 1; i < vec.size(); i++)
  {
    result = cc->EvalAdd(result, cc->EvalRotate(vec.at(i), -i*max_features));
  }
}

Ciphertext<DCRTPoly> BlindArrayAccess(Ciphertext<DCRTPoly> ctm, Ciphertext<DCRTPoly> ctarray, CryptoContext<DCRTPoly> cc)
{


  cout << "   OneHotSlot..   " << endl;
  timeval t_start_ohs, t_end_ohs;
  gettimeofday(&t_start_ohs, NULL);
  auto ct_ohs = OneHotSlot(ctm,cc);
  gettimeofday(&t_end_ohs, NULL);
  cout << "Time OHS : " << std::setprecision(5) << getMillies(t_start_ohs, t_end_ohs) << " ms" << '\n';

  cout << "   Selection of Array[m]..   " << endl;
  auto ctmult = cc->EvalMult(ct_ohs,ctarray);


  cout << "   Rotate and Sum..   " << endl;
  timeval t_start_RS, t_end_RS;
  gettimeofday(&t_start_RS, NULL);
  auto ct_res_rotsum = RotateAndSum(ctmult,cc);
  gettimeofday(&t_end_RS, NULL);
  cout << "Time RS : " << std::setprecision(5) << getMillies(t_start_RS, t_end_RS) << " ms" << '\n';

  return ct_res_rotsum;

}


int main() {
  timeval t_start, t_end;

  
  int N = std::pow(2, 15);
  int t = 2 * N + 1;  // 65537;
  uint32_t depth = 19;
  double sigma = 3.2;
  int m = 8;
//   SecurityLevel securityLevel = HEStd_128_classic;
  CCParams<CryptoContextBFVRNS> parameters;

  parameters.SetPlaintextModulus(t);
  parameters.SetStandardDeviation(sigma);
  parameters.SetMultiplicativeDepth(depth);
  parameters.SetMaxRelinSkDeg(2);
  parameters.SetScalingModSize(60);
  parameters.SetRingDim(N);
  
  cout << "Generating the Crypto Context.." << endl;
  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(ADVANCEDSHE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);


  cout << "Generating the KeyPair.." << endl;
  KeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);


  cout << "Generating the Rotations Keys.." << endl;
  std::vector<int> indexList;
  for(int i = 0; i < log2(N); i++){indexList.push_back(pow(2,i));}
  cc->EvalRotateKeyGen(keyPair.secretKey, indexList);
  // std::vector<int> indexList2; // a modifier pour plus de deux parties
  // for(int i = 0; i < int(N/max_features) ; i++){indexList2.push_back(i*max_features);}
  // cc->EvalRotateKeyGen(keyPair.secretKey, indexList2);




  cout << "Input : Encrypting [m,..,m] with m = "<< m << endl;
  std::vector<int64_t> vecm(40, m);
  Plaintext ptm = cc->MakePackedPlaintext(vecm);
  auto ctm = cc->Encrypt(keyPair.publicKey, ptm);

  cout << "Generating and encrypting Array" << endl; 
  std::vector<int64_t> array(40);
  iota(array.begin(), array.end(), 0);
  Plaintext ptarray = cc->MakePackedPlaintext(array);
  auto ctarray = cc->Encrypt(keyPair.publicKey,ptarray);
  cout << "Array = " << ptarray << endl;




  cout << "TIC : BAcc start" << endl;
  gettimeofday(&t_start, NULL);
  auto ct_res = BlindArrayAccess(ctm, ctarray,cc);
  cout << "TAC : BAcc end" << endl;
  gettimeofday(&t_end, NULL);




  Plaintext result;
  cc->Decrypt(keyPair.secretKey, ct_res, &result);
  cout << "Output " << result->GetPackedValue()[0] << endl;

  cout << "Time : " << std::setprecision(5) << getMillies(t_start, t_end) << " ms" << '\n';

  return 0;
}



