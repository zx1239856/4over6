/*
 * Created by zx on 2020/3/12.
 */
#ifndef SERVER_UTILS_HPP
#define SERVER_UTILS_HPP

#include <unordered_set>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "third-party/aixlog.hpp"
#include "msg.h"

#define LOG_FATAL(fmt) LOG(FATAL) << COLOR(red) << fmt << COLOR(none)
#define LOG_WARN(fmt) LOG(WARNING) << COLOR(yellow) << fmt << COLOR(none)

namespace utils {
    struct UserInfo {
        uint32_t count;
        uint32_t secs;
        std::string v6addr;
    };

    class AddressPool {
    public:
        AddressPool(const boost::asio::ip::address_v4 &start_addr, const boost::asio::ip::address_v4 &end_addr);

        size_t size() const {
            return pool.size();
        }

        boost::asio::ip::address_v4 obtain_ip_address();

        void return_ip_address(const boost::asio::ip::address_v4 &addr);

        std::string get_range() const {
            return start.to_string() + "-" + end.to_string();
        }

    private:
        boost::asio::ip::address_v4 start, end;
        std::unordered_set<unsigned long> pool{};
    };

    class Server;

    class Session
            : public std::enable_shared_from_this<Session> {
    public:
        Session(Server &server, boost::asio::ip::tcp::socket s);

        void start();

        void close(bool remove=true);

        bool expires() { return time(nullptr) - info.secs > 60; }

        uint32_t heartbeat_tick() { return info.count != 0 ? --info.count : 0; }

        void send_heartbeat();
    private:
        void do_read();

        void do_write(std::size_t length);

        boost::asio::ip::tcp::socket socket;
        Server &server;
        enum {
            max_length = sizeof(Msg)
        };
        struct Msg read_data{0};
        struct Msg write_data{0};
        struct UserInfo info = {};
    };

    class Server {
        friend class Session;

    public:
        Server(std::shared_ptr<AddressPool> pool, const ConfigPayload &config, boost::asio::io_service &io_service, const boost::asio::ip::address_v6 & address, ushort port);
    private:
        void clear_session(const std::string &v6addr) {
            auto it = v6_v4_mappings.find(v6addr);
            if(it != v6_v4_mappings.end()) {
                user_sessions.erase(user_sessions.find(it->second.to_ulong()));
                v6_v4_mappings.erase(it);
            }
        }

        void accept();

        void handle_client(boost::system::error_code ec);

        void handle_heartbeat();

        boost::asio::ip::tcp::acceptor acceptor;
        boost::asio::ip::tcp::socket socket;
        // user session and address mappings
        std::unordered_map<unsigned long, std::shared_ptr<Session>> user_sessions;
        std::unordered_map<std::string, boost::asio::ip::address_v4> v6_v4_mappings;
        // v4 address pool
        std::shared_ptr<AddressPool> pool;
        // configs
        ConfigPayload config;

        // heartbeat timer
        boost::asio::deadline_timer heartbeat_timer;
    };
}

#endif //SERVER_UTILS_HPP
