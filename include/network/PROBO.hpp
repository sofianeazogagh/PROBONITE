#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <functional>
#include <iostream>
#include <string>
#include <memory>

using boost::asio::ip::tcp;


#define SECLEVEL 80
#define SECNOISE true
#define SECALPHA pow(2., -25)
#define SEC_PARAMS_STDDEV    pow(2., -25)
#define SEC_PARAMS_n  500                   ///  LweParams
#define SEC_PARAMS_N 1024                   /// TLweParams
#define SEC_PARAMS_k    1                   /// TLweParams
#define SEC_PARAMS_BK_STDDEV pow(2., -55)   /// TLweParams
#define SEC_PARAMS_BK_BASEBITS 4           /// TGswParams
#define SEC_PARAMS_BK_LENGTH    7           /// TGswParams
#define SEC_PARAMS_KS_STDDEV pow(2., -55)   /// Key Switching Params
#define SEC_PARAMS_KS_BASEBITS  4           /// Key Switching Params
#define SEC_PARAMS_KS_LENGTH   8           /// Key Switching Params
#define MSG_SLOTS   1024                    /// Size message space --> m \in [0,MSG_SLOTS[
#define TORUS_SLOTS pow(2., 32)-1          /// Size torus 


class PROBOServer {
public:
    PROBOServer() {}

    ~PROBOServer() {}

    bool load(std::string const& file);
    
    void run(tcp::iostream &conn) ;

private:
    struct Imp;
    std::shared_ptr<Imp> imp_;
};

class PROBOClient {
public:
    PROBOClient() {}

    ~PROBOClient() {}
    /// Client's input is one line splitted with comma.
    bool load(std::string const& file);

    void run(tcp::iostream &conn);

private:
    struct Imp;
    std::shared_ptr<Imp> imp_;
};