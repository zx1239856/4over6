//
// Created by zx on 2020/5/4.
//

#ifndef SRC_CLIENT_H
#define SRC_CLIENT_H

#include "utils.h"
#include "tun_device.h"

using KeyType = std::array<uint8_t, 16>;

class Client {
public:
    Client(boost::asio::io_service &io_service, const std::string &server, ushort port, bool encrypt,
           const KeyType &key);

    void start();

    void stop();
private:
    void do_write(size_t length);

    void do_read();

    void on_data_read_done(boost::system::error_code ec);

    void handle_heartbeat();

    void handle_tun_data(uint8_t *buffer, size_t length);

    void get_ip_config();

    boost::asio::io_service &io_serv;
    boost::asio::ip::tcp::socket socket;
    // heartbeat timer
    boost::asio::deadline_timer heartbeat_timer, ip_conf_timer;
    // TUN device
    TunDevice tunnel;
    // configs
    boost::asio::ip::address_v6 server_addr;
    ushort port;
    bool encrypt;
    KeyType key;

    int tries = 3;
    uint64_t last_heartbeat_sent = 0;
    uint64_t last_heartbeat_recv = 0;
    std::string ipv4;
    std::string gateway;
    std::string dns[3];
    struct Msg read_data{0};
    struct Msg write_data{0};
#ifdef SUPPORT_ENCRYPTION
    struct Msg buffer{0};
    utils::SecurityHandler security;
#endif
};


#endif //SRC_CLIENT_H
