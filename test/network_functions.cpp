#include <iostream>
#include <vector>
#include <boost/asio.hpp>

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

    int message_received;
    using namespace boost::asio::ip;
    boost::asio::io_service ios;
    tcp::endpoint endpoint(tcp::v4(), network::port);
    tcp::acceptor acceptor(ios, endpoint);

    tcp::iostream conn;
    boost::system::error_code err;

    std::cout << "[Server] Waiting for connection" << std::endl;

    acceptor.accept(*conn.rdbuf(), err);
    if (!err){

        std::cout << "[Server] Client connected to server";
        conn >> message_received;

        std::cout << "The received message is " << message_received;
        conn.close();
    
    }
}

int Client()
{
    // boost::asio::io_service service;
    // using namespace boost::asio::ip;
    // tcp::endpoint endpoint(address::from_string("127.0.0.1"), 4000);
    // tcp::socket socket(service);
    // std::cout << "[Client] Connecting to server..." << std::endl;
    // socket.connect(endpoint);
    // std::cout << "[Client] Connection successful" << std::endl;

    // //socket.async_read_some(boost::asio::buffer(buff), ReadHandler);
    // service.run();


    int message_to_send = 10;

    using namespace boost::asio::ip;

    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn)
    {
        std::cerr << "[Client] Can not connect to server!" << std::endl;
        return -1;
    }

    std::cout << "[Client] Client connected to server";
    conn << message_to_send;
    conn.close();
    return 0;
}

int main(int argc, char **argv)
{
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