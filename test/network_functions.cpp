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


//Paramètres TFHE envoyées par le client
TFheGateBootstrappingParameterSet *clientParams;

//Paramètres crypto reçus par le serveur
TFheGateBootstrappingParameterSet *serverParams;

//clé de bootstrapping envoyée par le client
LweBootstrappingKey *clientBk;

//Clé de bootstrapping reçue par le serveur
LweBootstrappingKey *serverBk;

//Tableau de features en clair
std::vector<int32_t> features_ ;

//Features chiffrées envoyées par le client
LweSample* client_enc_features_; 

//Features chiffrées reçues par le serveur
LweSample* server_enc_features_; 



// chiffer les features pour le test
void encrypt_features(TFheGateBootstrappingSecretKeySet *secret, const LweParams *in_out_params)
{

    client_enc_features_ = new_LweSample_array(features_.size(),in_out_params);
    
    for (size_t i = 0; i < features_.size(); i++)
    {
        Torus32 mu = modSwitchToTorus32(features_[i], SECLEVEL); 
        lweSymEncrypt(client_enc_features_ + i, mu, SECLEVEL, secret->lwe_key);
    }

}


// fonction du serveur, exécutée pour recevoir les inputs du client, et retourner la prédiction 
void Server()
{

    //initialiser les fonctions réseau : adresse ip, port, ...
    using namespace boost::asio::ip;
    boost::asio::io_service ios;
    tcp::endpoint endpoint(tcp::v4(), network::port);
    tcp::acceptor acceptor(ios, endpoint);
    tcp::iostream conn;
    boost::system::error_code err;
    std::cout << "[Server] Waiting for connection \n"
              << std::endl;
    
    acceptor.accept(*conn.rdbuf(), err);
    if (!err)
    {

        std::cout << "[Server] Client connected to server \n";

        //recevoir les paramètres crypto
        serverParams = receive_params(conn);

        //recevoir la clé de bootstrapping
        receive_bootstrapping_key(serverBk, conn);

        int number_of_features;

        //recevoir le nombre de features
        conn >> number_of_features;

        //recevoir les features chiffrées
        server_enc_features_ = new_LweSample_array(number_of_features, serverParams->in_out_params);
        receive_encrypted_features(server_enc_features_, number_of_features, conn, serverParams->in_out_params);
    }
}

int Client()
{

    //se connecter au serveur
    using namespace boost::asio::ip;
    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "[Client] Can not connect to server!" << std::endl;
        return -1;
    }
    std::cout << "[Client] Client connected to server \n";
    
    //générer les paramètres TFHE et les envoyer au serveur
    clientParams = new_default_gate_bootstrapping_parameters(SECLEVEL);
    send_params(clientParams, conn);

    //générer la clé de bootstrapping et l'enovyer au serveur
    const LweParams *in_out_params = clientParams->in_out_params;
    TFheGateBootstrappingSecretKeySet *secret = new_random_gate_bootstrapping_secret_keyset(clientParams);
    const LweBootstrappingKey *bk = secret->cloud.bk;
    send_bootstrapping_key(bk, conn);


    //chiffer les features et les envoyer au serveur
    features_ = {1,2,3,4};
    encrypt_features(secret, clientParams->in_out_params);
    conn << features_.size();
    send_encrypted_features(client_enc_features_, features_.size(), conn,  clientParams->in_out_params);

    conn.close();

    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        std::cout << "Please specify 's' for server or 'c' for client after the executable" << std::endl;
        return -1;
    }

    if (argv[1][0] == 's')
    {
        Server();
    }
    else if (argv[1][0] == 'c')
    {
        Client();
    }
    
    else{
        std::cout << "Please specify 's' for server or 'c' for client after the executable" << std::endl;
    }

    return 0;
}