#include <exception>
#include <unordered_set>
#include <yaml-cpp/yaml.h>
#include "third-party/cxxopts.hpp"
#include "third-party/aixlog.hpp"
#include "utils.h"
#include "msg.h"

using namespace boost;
using namespace boost::asio;

int main(int argc, char **argv) {
    cxxopts::Options options("4over6_server", "Server side of 4over6 tunnel");
    options.add_options()
            ("d,debug", "Enable debugging", cxxopts::value<bool>()->default_value("false"))
            ("c,conf", "File name", cxxopts::value<std::string>())
            ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");
    auto default_log_sink = AixLog::Log::init<AixLog::SinkCout>(AixLog::Severity::trace, AixLog::Type::all);
    try {
        auto result = options.parse(argc, argv);
        if (!result["debug"].as<bool>()) default_log_sink->severity = AixLog::Severity::warning;
        if (!result["verbose"].as<bool>()) default_log_sink->set_type(AixLog::Type::normal);
        // parse config
        YAML::Node config = YAML::LoadFile(result["conf"].as<std::string>());

        // pool range
        std::string address_range = config["address_range"].as<std::string>();
        auto pos = address_range.find('-');
        std::string start_addr = address_range.substr(0, pos);
        std::string end_addr = address_range.substr(pos + 1);
        // gateway, dns, ...
        ip::address_v4 gateway = ip::address_v4::from_string(config["gateway"].as<std::string>());
        ip::address_v4 dns_0 = ip::address_v4::from_string(config["dns0"].as<std::string>());
        ip::address_v4 dns_1 = ip::address_v4::from_string(config["dns1"].as<std::string>());
        ip::address_v4 dns_2 = ip::address_v4::from_string(config["dns2"].as<std::string>());
        ip::address_v4 netmask = ip::address_v4::from_string(config["netmask"].as<std::string>());

        ConfigPayload server_conf{"", gateway.to_string(), netmask.to_string(),
                                  {dns_0.to_string(), dns_1.to_string(), dns_2.to_string()}};

        auto pool = std::make_shared<utils::AddressPool>(ip::address_v4::from_string(start_addr),
                                                         ip::address_v4::from_string(end_addr));
        io_service io_serv;
        utils::Server server{pool, server_conf, io_serv,
                             ip::address_v6::from_string(config["listen_address"].as<std::string>()),
                             config["port"].as<uint16_t>()};
        io_serv.run();
    }
    catch (const cxxopts::OptionException &ex) {
        LOG_FATAL(ex.what());
        LOG(INFO) << options.help();
    }
    catch (const std::exception &ex) {
        LOG_FATAL(ex.what());
    }
    catch (...) {
        LOG_FATAL("An exception has occurred");
    }
    return 0;
}
