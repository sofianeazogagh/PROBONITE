#include <iostream>
#include <vector>
#include <boost/asio.hpp>
#include "tfhe.h"
#include "tfhe_io.h"
#include "tfhe_gate_bootstrapping_functions.h"


namespace network
{
    int port = 12345;
    std::string addr = "127.0.0.1";
}

void print_params(TFheGateBootstrappingParameterSet* param){

    std::cout << "(alpha_max=" << param->in_out_params->alpha_max 
    << ", alpha_min=" << param->in_out_params->alpha_min
    << ", n=" << param->in_out_params->n
    << ", ks_basebit=" << param->ks_basebit
    << ", ks_t=" << param->ks_t
    << ")\n";

}

void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn){
        
        export_tfheGateBootstrappingParameterSet_toStream(conn, params);
        std::cout << "[Client] Parameters sent from client : ";
        print_params(params);

}

TFheGateBootstrappingParameterSet* receive_params(std::istream &conn){

    std::string message_received;
    TFheGateBootstrappingParameterSet* params = new_tfheGateBootstrappingParameterSet_fromStream(conn);
    std::cout << "[Server] Parameters received by server : ";
    print_params(params);
    return params;

}

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
        TFheGateBootstrappingParameterSet* params = receive_params(conn);
        conn.close();
    
    }
}

int Client()
{

    using namespace boost::asio::ip;
    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "[Client] Can not connect to server!" << std::endl;
        return -1;
    }
    std::cout << "[Client] Client connected to server \n";
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(110);
    send_params(params, conn);
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