#include "../include/util/literal.hpp"
#include "../include/network/net_io.hpp"

namespace network
{
    int port = 12345;
    std::string addr = "127.0.0.1";
}

void print_params(TFheGateBootstrappingParameterSet *param)
{

    printf("(alpha_max=%f, alpha_min=%f, n=%d, ks_basebit=%d, ks_t=%d)\n",
           param->in_out_params->alpha_max,
           param->in_out_params->alpha_min,
           param->in_out_params->n,
           param->ks_basebit,
           param->ks_t);
}

void print_lwe_sample(LweSample *cyphertext)
{
     printf("(a=%d, b=%d, variance=%f)\n", *(cyphertext ->a), cyphertext->b, cyphertext->current_variance);
}

// fonction d'envoi des paramètres TFHE
void send_params(TFheGateBootstrappingParameterSet *params, std::ostream &conn)
{
    export_tfheGateBootstrappingParameterSet_toStream(conn, params);
    std::cout << "[Client] Parameters sent : " << std::endl;
    print_params(params);
    std::cout << std::endl;
}

// fonction de réception des paramètres TFHE
TFheGateBootstrappingParameterSet *receive_params(std::istream &conn)
{
    TFheGateBootstrappingParameterSet *params = new_tfheGateBootstrappingParameterSet_fromStream(conn);
    std::cout << "[Server] Parameters received : " << std::endl;
    print_params(params);
    std::cout << std::endl;
    return params;
}

// fonction d'envoi de la clé de bootstrapping
void send_bootstrapping_key(const LweBootstrappingKey *bk, std::ostream &conn)
{
    export_lweBootstrappingKey_toStream(conn, bk);
    std::cout << "[Client] Bootstraping key sent : " << std::endl;
    printf("(k=%d,l=%d)\n", bk->bk->k, bk->bk->l);
    std::cout << std::endl;
}

// fonction de réception de la clé de bootsrapping
void receive_bootstrapping_key(LweBootstrappingKey *bk, std::istream &conn)
{
    bk = new_lweBootstrappingKey_fromStream(conn);
    std::cout << "[Server] Boostraping key received : " << std::endl;
    printf("(k=%d, l=%d)\n", bk->bk->k, bk->bk->l);
    std::cout << std::endl;
}

// fonction d'envoi des features chiffées
void send_encrypted_features(LweSample *enc_features, int number_features, std::ostream &conn, const LweParams *params)
{
    std::cout << "[Client] Encrypted features sent : " << std::endl;
    for (size_t i = 0; i < number_features; i++)
    {
        export_lweSample_toStream(conn, enc_features + i, params);
        printf("(a=%d, b=%d, variance=%f)\n", *((enc_features + i)->a), (enc_features + i)->b, (enc_features + i)->current_variance);
    }
    std::cout << std::endl;
}

// fonction de réception des features chiffrées
void receive_encrypted_features(LweSample *enc_features, int number_of_features, std::istream &conn, const LweParams *params)
{

    std::cout << "[Server] Encrypted features received : " << std::endl;
    for (size_t i = 0; i < number_of_features; i++)
    {
        import_lweSample_fromStream(conn, enc_features + i, params);
        printf("(a=%d, b=%d, variance=%f)\n", *((enc_features + i)->a), (enc_features + i)->b, (enc_features + i)->current_variance);
    }
    std::cout << std::endl;
    
}

void send_result(LweSample *enc_label_index,
                     std::ostream &conn, const LweParams *params)
{
    export_lweSample_toStream(conn, enc_label_index, params);
    printf("[Server] Prediction sent : ");
    print_lwe_sample(enc_label_index);
    std::cout << std::endl;
}

void wait_result(LweSample *enc_label_index,
                     std::istream &conn, const LweParams *params)
{

    import_lweSample_fromStream(conn, enc_label_index, params);
    printf("[Client] Prediction received :");
    print_lwe_sample(enc_label_index);
    std::cout << std::endl;
    
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
