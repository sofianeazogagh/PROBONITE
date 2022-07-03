#include "net_io.hpp"

#include <string>
#include <memory>

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