/*
 * Created by zx on 2020/3/12.
 */
#ifndef SERVER_UTILS_HPP
#define SERVER_UTILS_HPP

#include <unordered_set>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#ifdef SUPPORT_ENCRYPTION

#include <sodium.h>

#endif

#include "third-party/aixlog.hpp"
#include "msg.h"

#define LOG_FATAL(fmt) LOG(FATAL) << COLOR(red) << fmt << COLOR(none) << std::endl; exit(EXIT_FAILURE);
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

#ifdef SUPPORT_ENCRYPTION

    class SecurityHandler {
    public:
        explicit SecurityHandler(const uint8_t uuid[16]);

        bool encrypt_msg(struct Msg &dst, const struct Msg &src);

        bool decrypt_msg(struct Msg &dst, const struct Msg &src);

    private:
        uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    };

#endif

    class Session
            : public std::enable_shared_from_this<Session> {
    public:
#if BOOST_VERSION >= 107000

        Session(Server &server, boost::asio::executor io_service);

#else
        Session(Server &server, boost::asio::io_service &io_service);
#endif

        void start();

        void close(bool remove = true);

        bool expires() { return time(nullptr) - info.secs > 60; }

        uint32_t heartbeat_tick() { return info.count != 0 ? --info.count : 0; }

        void send_heartbeat();

        void send_tunnel_data(uint8_t *buffer, size_t length);

        boost::asio::ip::tcp::socket &get_socket() {
            return socket;
        }

    private:
        void on_data_read_done(boost::system::error_code ec);

        void do_read();

        void do_write(std::size_t length);

#ifdef SUPPORT_ENCRYPTION
        struct Msg buffer{0};
#endif
        Server &server;
        boost::asio::ip::tcp::socket socket;
        enum {
            max_length = sizeof(Msg)
        };
        struct Msg read_data{0};
        struct Msg write_data{0};
        struct UserInfo info = {};
        bool encrypt = false;
    };

    class TunDevice {
    public:
        typedef std::function<void(uint8_t *, size_t)> packet_handler;

        TunDevice(boost::asio::io_service &io_service, packet_handler handler, const std::string &if_name,
                  const std::string &tun_ip, const std::string &net_mask);

        const std::string &device() { return if_name; };

        void send_packet(const uint8_t *buffer, size_t length);

    private:
        boost::asio::posix::stream_descriptor stream_descriptor;
        std::string if_name;
        std::string tun_ip;
        std::string net_mask;
        uint8_t readbuf[1500]{};
        uint8_t writebuf[1500]{};

        packet_handler handler_func;

        void async_read_packet();

        void on_read_done(const boost::system::error_code &ec, size_t length);

        void assign_tun_ip();

        void assign_tun_route();
    };

    class Server {
        friend class Session;

    public:
        Server(std::shared_ptr<AddressPool> pool, const ConfigPayload &config, boost::asio::io_service &io_service,
               const boost::asio::ip::address_v6 &address, ushort port);

    private:
        void clear_session(const std::string &v6addr) {
            auto it = v6_v4_mappings.find(v6addr);
            if (it != v6_v4_mappings.end()) {
                pool->return_ip_address(it->second);
                user_sessions.erase(user_sessions.find(it->second.to_ulong()));
                v6_v4_mappings.erase(it);
            }
        }

        void accept();

        void handle_client(std::shared_ptr<Session> session, boost::system::error_code ec);

        void handle_heartbeat();

        void handle_tun_data(uint8_t *buffer, size_t length);

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

        // TUN device
        TunDevice tunnel;

#ifdef SUPPORT_ENCRYPTION
        SecurityHandler security;
#endif
    };
}

#endif //SERVER_UTILS_HPP
