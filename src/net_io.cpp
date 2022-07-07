#include "../include/util/literal.hpp"
#include "../include/network/net_io.hpp"

namespace network
{
    int port = 12345;
    std::string addr = "127.0.0.1";
}

// void print_bootstraping_key(LweBootstrappingKey *bk){

//     std::cout << "(alpha_max=" << bk->accum_pa
//     << ", alpha_min=" << bk->bk_params->Bg
//     << ", n=" << bk->in_out_params->n
//     << ", ks_basebit=" << bk->ks_basebit
//     << ", ks_t=" << bk->ks_t
//     << ")\n";

// }

void print_params(TFheGateBootstrappingParameterSet *param)
{

    std::cout << "(alpha_max=" << param->in_out_params->alpha_max
              << ", alpha_min=" << param->in_out_params->alpha_min
              << ", n=" << param->in_out_params->n
              << ", ks_basebit=" << param->ks_basebit
              << ", ks_t=" << param->ks_t
              << ")\n";
}

void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn)
{

    export_tfheGateBootstrappingParameterSet_toStream(conn, params);
    std::cout << "[Client] Parameters sent : ";
    print_params(params);
}

void receive_params(TFheGateBootstrappingParameterSet *params, std::istream &conn)
{

    params = new_tfheGateBootstrappingParameterSet_fromStream(conn);
    std::cout << "[Server] Parameters received : ";
    print_params(params);
}

void send_bootstrapping_key(const LweBootstrappingKey *bk, std::ostream &conn)
{

    export_lweBootstrappingKey_toStream(conn, bk);
    std::cout << "[Client] Bootstraping key sent : ";
}

void receive_bootstrapping_key(LweBootstrappingKey *bk, std::istream &conn)
{

    bk = new_lweBootstrappingKey_fromStream(conn);
    std::cout << "[Server] Boostraping key received : ";
}

void send_encrypted_features(LweSample *enc_features, std::ostream &conn, LweParams *params)
{

    export_lweSample_toStream(conn, enc_features, params);
    std::cout << "[Client] Encrypted features sent : ";
}

void receive_encrypted_features(LweSample *enc_features, std::istream &conn, LweParams *params)
{

    import_lweSample_fromStream(conn, enc_features, params);
    std::cout << "[Server] Encrypted features received : ";
}

int run_server(routine_t server_routine)
{
    boost::asio::io_service ios;
    tcp::endpoint endpoint(tcp::v4(), network::port);
    tcp::acceptor acceptor(ios, endpoint);
    for (;;)
    {
        tcp::iostream conn;
        boost::system::error_code err;
        acceptor.accept(*conn.rdbuf(), err);
        if (!err)
        {
            server_routine(conn);
            conn.close();
            break;
        }
    }
    return 0;
}

int run_client(routine_t client_routine)
{
    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "Can not connect to server!" << std::endl;
        return -1;
    }
    client_routine(conn);
    conn.close();
    return 1;
}
