#include <iostream>
#include <vector>
#include <boost/asio.hpp>
#include "tfhe.h"
#include "tfhe_io.h"
#include "tfhe_gate_bootstrapping_functions.h"

std::vector<char> buff(256);

void SendHandler(boost::system::error_code ex)
{
    std::cout << " do something here" << std::endl;
}

void ReadHandler(boost::system::error_code ex)
{
    std::cout << " print the buffer data..." << std::endl;
    std::cout << buff.data() << std::endl;
}

namespace network
{
    int port = 12345;
    std::string addr = "127.0.0.1";
}

void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn){
        
        export_tfheGateBootstrappingParameterSet_toStream(conn, params);
        std::cout << "[Client] Parameters sent from client";

}

TFheGateBootstrappingParameterSet* receive_params(std::istream &conn){

    std::string message_received;
    TFheGateBootstrappingParameterSet* params = new_tfheGateBootstrappingParameterSet_fromStream(conn);
    std::cout << "[Server] Parameters received by server";

    return params;

}

void print_parameters(TFheGateBootstrappingParameterSet* param){

    std::cout << "(alpha_max=" << param->in_out_params->alpha_max 
    << ", alpha_min=" << param->in_out_params->alpha_min
    << ", n=" << param->in_out_params->n
    << ", ks_basebit=" << param->ks_basebit
    << ", ks_t=" << param->ks_t
    << ")\n";

}

void Server()
{
    // boost::asio::io_service service;
    // using namespace boost::asio::ip;
    // tcp::endpoint endpoint(tcp::v4(), 4000);
    // tcp::acceptor acceptor(service, endpoint);
    // tcp::socket socket(service);
    // std::cout << "[Server] Waiting for connection" << std::endl;

    // acceptor.accept(socket);
    // std::cout << "[Server] Accepted a connection from client" << std::endl;

    // std::string msg = "Message from server";
    // // socket.async_send(boost::asio::buffer(msg), SendHandler);
    // service.run();

    
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
        
        print_parameters(params);

        conn.close();
    
    }
}

int Client()
{
    int message_to_send = 10;

    using namespace boost::asio::ip;

    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "[Client] Can not connect to server!" << std::endl;
        return -1;
    }

    std::cout << "[Client] Client connected to server \n";
    
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(110);

    print_parameters(params);
    
    send_params(params, conn);

    conn.close();
    return 0;

}



int main(int argc, char **argv){
    if (argc == 1)
    {
        std::cout << "Please specify s for server or c for client" << std::endl;
        return -1;
    }
    if (argv[1][0] == 's')
    {
        Server();
    }
    else
    {
        Client();
    }
    return 0;
}