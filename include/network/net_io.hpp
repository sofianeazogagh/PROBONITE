#ifndef PRIVATE_DECISION_TREE_NETWORK_NET_IO_HPP
#define PRIVATE_DECISION_TREE_NETWORK_NET_IO_HPP
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <functional>
#include <iostream>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "tfhe/tfhe_gate_bootstrapping_functions.h"
#include "tfhe/tfhe_gate_bootstrapping_structures.h"
#include "tfhe/tfhe_core.h"

using boost::asio::ip::tcp;
using routine_t = std::function<void(tcp::iostream &)>;

namespace network {
    extern int port;
    extern std::string addr;
};

void print_params(TFheGateBootstrappingParameterSet* param);

void print_lwe_sample(LweSample *cyphertext);

void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn);

TFheGateBootstrappingParameterSet *receive_params(std::istream &conn);

void receive_bootstrapping_key(LweBootstrappingKey *bk, std::istream &conn);

void send_bootstrapping_key(const LweBootstrappingKey *bk, std::ostream &conn);

void send_encrypted_features(LweSample* enc_features, int number_of_features, std::ostream &conn, const LweParams *params);

void receive_encrypted_features(LweSample* enc_features, int number_of_features, std::istream &conn, const LweParams *params);

void wait_result(LweSample *enc_response, std::istream &conn, const LweParams *params);

void send_result(LweSample *enc_reponse, std::ostream &conn, const LweParams *params);

int run_server(routine_t server_routine);

int run_client(routine_t client_routine);
#endif // PRIVATE_DECISION_TREE_NETWORK_NET_IO_HPP
