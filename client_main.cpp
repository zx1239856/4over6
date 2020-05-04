//
// Created by zx on 2020/5/4.
//

#include <exception>
#include <unordered_set>
#include <yaml-cpp/yaml.h>
#include <boost/uuid/uuid.hpp>
#include "third-party/cxxopts.hpp"
#include "third-party/aixlog.hpp"
#include "client.h"

using namespace boost;
using namespace boost::asio;

int main(int argc, char **argv) {
    cxxopts::Options options("4over6_client", "Client side of 4over6 tunnel");
    options.add_options()
            ("d,debug", "Enable debugging", cxxopts::value<bool>()->default_value("false"))
            ("c,conf", "File name", cxxopts::value<std::string>())
            ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");
    auto default_log_sink = AixLog::Log::init<AixLog::SinkCout>(AixLog::Severity::trace, AixLog::Type::all);
    try {
        auto result = options.parse(argc, argv);
        bool help = result.count("help");
        if(result.count("conf") == 0) {
            help = true;
            LOG_WARN("Please provide configuration file.");
        }
        if (help) {
            std::cout << options.help() << std::endl;
            exit(0);
        }
        if (!result["debug"].as<bool>()) default_log_sink->severity = AixLog::Severity::info;
        if (!result["verbose"].as<bool>()) default_log_sink->set_type(AixLog::Type::normal);
        // parse config
        YAML::Node config = YAML::LoadFile(result["conf"].as<std::string>());

        // pool range
        auto server = config["server"].as<std::string>();
        auto port = config["port"].as<uint16_t>();
        KeyType key;
        bool encrypt = false;
#ifdef SUPPORT_ENCRYPTION
        if (config["pk"].IsDefined()) {
            LOG(INFO) << "Starting client with encryption support" << std::endl;
            std::string pk = config["pk"].as<std::string>();
            boost::uuids::uuid uuid;
            if(utils::is_valid_uuid(pk, uuid)) {
                for(int i = 0; i < 16; ++i) key.at(i) = uuid.data[i];
                encrypt = true;
            } else {
                LOG_FATAL("Invalid pre-shared key. Expected a valid UUID");
            }
        } else {
            LOG(INFO) << "No pre-shared key in config file, disabling encryption support" << std::endl;
        }
#endif
        io_service io_serv;
        Client client(io_serv, server, port, encrypt, key);
        client.start();
    }
    catch (const cxxopts::OptionException &ex) {
        LOG_WARN(ex.what());
        LOG(INFO) << options.help();
        exit(EXIT_FAILURE);
    }
    catch (const std::exception &ex) {
        LOG_FATAL(ex.what());
    }
    catch (...) {
        LOG_FATAL("An exception has occurred");
    }
    return 0;
}
