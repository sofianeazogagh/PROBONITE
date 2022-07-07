#include <iostream>
#include <boost/asio.hpp>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "tfhe/tfhe_gate_bootstrapping_functions.h"
#include "../include/network/net_io.hpp"
#include "../include/util/secparams.hpp"
#include <tfhe.h>
#include <set>
#include <tfhe_generic_streams.h>
#include <tfhe_garbage_collector.h>
#include "polynomials_arithmetic.h"



// namespace network
// {
//     int port = 12345;
//     std::string addr = "127.0.0.1";
// }

// void print_params(TFheGateBootstrappingParameterSet* param){

//     std::cout << "(alpha_max=" << param->in_out_params->alpha_max 
//     << ", alpha_min=" << param->in_out_params->alpha_min
//     << ", n=" << param->in_out_params->n
//     << ", ks_basebit=" << param->ks_basebit
//     << ", ks_t=" << param->ks_t
//     << ")\n";

// }

// void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn){
        
//         export_tfheGateBootstrappingParameterSet_toStream(conn, params);
//         std::cout << "[Client] Parameters sent from client : ";
//         print_params(params);

// }

// TFheGateBootstrappingParameterSet* receive_params(std::istream &conn){

//     std::string message_received;
//     TFheGateBootstrappingParameterSet* params = new_tfheGateBootstrappingParameterSet_fromStream(conn);
//     std::cout << "[Server] Parameters received by server : ";
//     print_params(params);
//     return params;

// }

// void assert_equals(const LweBootstrappingKey* a, const LweBootstrappingKey* b) {
//         const int32_t n = a->in_out_params->n;
//         const int32_t kpl = a->bk_params->kpl;
//         //const int32_t N = a->bk_params->tlwe_params->N;
//         const int32_t k = a->bk_params->tlwe_params->k;
//         //compare ks
//         //assert_equals(a->ks, b->ks);
//         //compute the max variance
//         double max_vara = -1;
//         double max_varb = -1;
//         for (int32_t i=0; i<n; i++)
//             for (int32_t j=0; j<kpl; j++) {
//                 TLweSample& samplea = a->bk[i].all_sample[j];
//                 TLweSample& sampleb = b->bk[i].all_sample[j];
//                 if (samplea.current_variance > max_vara)
//                     max_vara = samplea.current_variance;
//                 if (sampleb.current_variance > max_varb)
//                     max_varb = sampleb.current_variance;
//             }
//         assert_equals(max_vara, max_varb);
//         //compare the coefficients
//         for (int32_t i=0; i<n; i++)
//             for (int32_t j=0; j<kpl; j++) {
//                 TLweSample& samplea = a->bk[i].all_sample[j];
//                 TLweSample& sampleb = b->bk[i].all_sample[j];
//                 for (int32_t l=0; l<=k; l++)
//                     ASSERT_EQ(torusPolynomialNormInftyDist(samplea.a+l,sampleb.a+l),0);
//             }
//     }


TFheGateBootstrappingParameterSet *clientParams;
TFheGateBootstrappingParameterSet *serverParams;
LweBootstrappingKey *clientBk;
LweBootstrappingKey *serverBk;


void Server()
{
    using namespace boost::asio::ip;
    boost::asio::io_service ios;
    tcp::endpoint endpoint(tcp::v4(), network::port);
    tcp::acceptor acceptor(ios, endpoint);
    tcp::iostream conn;
    boost::system::error_code err;
    std::cout << "[Server] Waiting for connection \n" << std::endl;
    acceptor.accept(*conn.rdbuf(), err);
    if (!err){

        std::cout << "[Server] Client connected to server \n";
        //TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(SECLEVEL);
         
        receive_params(serverParams, conn);

        //LweBootstrappingKey *bk;
        receive_bootstrapping_key(serverBk, conn);

        conn.close();
    
    }
}


int Client(){

    using namespace boost::asio::ip;
    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "[Client] Can not connect to server!" << std::endl;
        return -1;
    }
    std::cout << "[Client] Client connected to server \n";
    //TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(110);
    clientParams = new_default_gate_bootstrapping_parameters(110);
    send_params(clientParams, conn);

    const LweParams *in_out_params = clientParams->in_out_params;
        // Send these parameters
    //send_params(params, conn); 

        // Generate the secret keyset by giving params
    TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(clientParams);
    const LweBootstrappingKey *bk = secret->cloud.bk;

    send_bootstrapping_key(bk, conn);

    conn.close();
    
    return 0;

}


int main(int argc, char **argv){
    if (argc == 1){
        std::cout << "Please specify s for server or c for client" << std::endl;
        return -1;
    }
    if (argv[1][0] == 's'){
        Server();
    }
    else{
        Client();
    }

    return 0;
}