#include <vector>
#include <string>
#include <boost/algorithm/string.hpp>

namespace util {
std::string trim(const std::string &line); 
std::vector<std::string> split_by(std::string const& str, char delimiter); 
std::vector<std::string> split_by_space(std::string const& str); 
}
