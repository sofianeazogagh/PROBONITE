// #include <boost/asio.hpp>
// #include <boost/asio/ip/tcp.hpp>
// #include <functional>
// #include <iostream>
// #include <string>
// #include <memory>

// using boost::asio::ip::tcp;

// class PROBOServer {
// public:
//     PROBOServer() {}

//     ~PROBOServer() {}

//     bool load(std::string const& file);

//     void run(tcp::iostream &conn) ;

// // private:
// //     struct Imp;
// //     std::shared_ptr<Imp> imp_;
// };

// class PROBOClient {
// public:
//     PROBOClient() {}

//     ~PROBOClient() {}
//     /// Client's input is one line splitted with comma.
//     bool load(std::string const& file);

//     void run(tcp::iostream &conn);

// // private:
// //     struct Imp;
// //     std::shared_ptr<Imp> imp_;
// };