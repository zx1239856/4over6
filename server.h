//
// Created by zx on 2020/5/4.
//

#ifndef SRC_SERVER_H
#define SRC_SERVER_H

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "utils.h"
#include "tun_device.h"

class Server;

class ServerSession
        : public std::enable_shared_from_this<ServerSession> {
public:
#if BOOST_VERSION >= 107000

    ServerSession(Server &server, boost::asio::executor io_service);

#else
    ServerSession(Server &server, boost::asio::io_service &io_service);
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

    void do_write();

    Server &server;
    boost::asio::ip::tcp::socket socket;
    enum {
        max_length = sizeof(Msg)
    };
    struct Msg read_data{0};
    struct Msg write_data{0};
#ifdef SUPPORT_ENCRYPTION
    struct Msg buffer{0};
#endif
    struct utils::UserInfo info = {};
    bool encrypt = false;
};

class Server {
    friend class ServerSession;

public:
    Server(std::shared_ptr<utils::AddressPool> pool, const ConfigPayload &config, boost::asio::io_service &io_service,
           const boost::asio::ip::address_v6 &address, ushort port);

    void start();

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

    void handle_client(std::shared_ptr<ServerSession> session, boost::system::error_code ec);

    void handle_heartbeat();

    void handle_tun_data(uint8_t *buffer, size_t length);

    boost::asio::io_service &io_serv;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    // user session and address mappings
    std::unordered_map<unsigned long, std::shared_ptr<ServerSession>> user_sessions;
    std::unordered_map<std::string, boost::asio::ip::address_v4> v6_v4_mappings;
    // v4 address pool
    std::shared_ptr<utils::AddressPool> pool;
    // configs
    ConfigPayload config;

    // heartbeat timer
    boost::asio::deadline_timer heartbeat_timer;

    // TUN device
    TunDevice tunnel;

#ifdef SUPPORT_ENCRYPTION
    utils::SecurityHandler security;
#endif
};


#endif //SERVER_SERVER_H
