//
// Created by zx on 2020/5/4.
//

#include "client.h"
#include <linux/ip.h>

using namespace boost;
using namespace boost::system;
using namespace boost::asio;
using namespace boost::asio::ip;
using namespace utils;

const auto ONE_SECOND = boost::posix_time::seconds(1);

Client::Client(boost::asio::io_service &io_service, const std::string &server, ushort _port, bool _encrypt,
               const KeyType &_key) :
        io_serv(io_service),
        socket(io_service),
        heartbeat_timer(io_service, ONE_SECOND), ip_conf_timer(io_service, ONE_SECOND),
        tunnel(io_service,
               boost::bind(&Client::handle_tun_data, this, boost::placeholders::_1, boost::placeholders::_2),
               "4over6_client_tun", "", ""),
        port(_port), encrypt(_encrypt), key(_key)
#ifdef SUPPORT_ENCRYPTION
        , security(_key.data())
#endif
{
    error_code ec;
    server_addr = address_v6::from_string(server, ec);
    if (ec) {
        // try to perform DNS
        LOG(INFO) << "Performing DNS lookup for host: " << server << std::endl;
        tcp::resolver dns(io_service);
        tcp::resolver::query query(server, "http");
        tcp::resolver::iterator endpoint_iter = dns.resolve(query), end;
        bool found = false;
        while (endpoint_iter != end) {
            if ((*endpoint_iter).endpoint().address().is_v6()) {
                found = true;
                server_addr = (*endpoint_iter).endpoint().address().to_v6();
                LOG(INFO) << "Found address: " << server_addr << std::endl;
                break;
            }
        }
        if (!found) {
            LOG_FATAL("Failed to found AAAA record for host: " << server);
        }
    }
}

void Client::start() {
    LOG(INFO) << "Connecting to server: " << server_addr << std::endl;
    auto endpoint = tcp::endpoint(server_addr, port);
    error_code ec;
    socket.connect(endpoint, ec);
    if (ec) {
        LOG_WARN("Failed to connect to server");
        throw (ec);
    } else {
        LOG(INFO) << "Successfully connected to server" << std::endl;
        // start r/w and setup-tunnel
        last_heartbeat_recv = time(nullptr);
        heartbeat_timer.async_wait(boost::bind(&Client::handle_heartbeat, this));
        do_read();
        ip_conf_timer.async_wait(boost::bind(&Client::get_ip_config, this));
        io_serv.run();
    }
}

void Client::stop() {
    socket.close();
    LOG_FATAL("Client exit");
}

void Client::do_write(std::size_t length) {
#ifdef SUPPORT_ENCRYPTION
    if (encrypt) {
        if (security.encrypt_msg(buffer, write_data)) {
            memcpy(&write_data, &buffer, buffer.length);
            length = buffer.length;
        } else {
            LOG(DEBUG) << "Encryption required by config, but encryption failed" << std::endl;
        }
    }
#endif
    system::error_code ec;
    boost::asio::write(socket, boost::asio::buffer(&write_data, length), boost::asio::transfer_all(), ec);
    if (ec) {
        stop();
    }
}

void Client::handle_heartbeat() {
    // handle heartbeat
    uint64_t now = time(nullptr);
    if (now - last_heartbeat_sent >= 20) {
        // send heartbeat
        LOG(DEBUG) << "Sending heartbeat to server" << std::endl;
        write_data.type = HEARTBEAT;
        write_data.length = HEADER_LEN;
        do_write(HEADER_LEN);
        last_heartbeat_sent = now;
    }
    if (now - last_heartbeat_recv > 60) {
        LOG_WARN("Server heartbeat timeout");
        stop();
    }

    heartbeat_timer.expires_from_now(ONE_SECOND);
    heartbeat_timer.async_wait(boost::bind(&Client::handle_heartbeat, this));
}

void Client::handle_tun_data(uint8_t *buf, size_t length) {
    auto *hdr = reinterpret_cast<struct iphdr *>(buf);
    if (hdr->version == 4) {
        write_data.length = length + HEADER_LEN;
        write_data.type = REQUEST;
        memcpy(&write_data.data, buf, sizeof(uint8_t) * length);
        do_write(write_data.length);
    }
}

void Client::do_read() {
    async_read(socket, boost::asio::buffer(&read_data, HEADER_LEN),
               [this](boost::system::error_code ec, std::size_t length) {
                   if (!ec) {
                       if (length < HEADER_LEN || read_data.length < HEADER_LEN) {
                           LOG(DEBUG) << "Got invalid packet from server" << std::endl;
                       } else if (read_data.length > MAX_MSG_LEN) {
                           do_read();
                       } else {
                           async_read(socket, boost::asio::buffer(&read_data.data, std::min(DATA_LEN,
                                                                                            read_data.length -
                                                                                            HEADER_LEN)),
                                      boost::bind(&Client::on_data_read_done, this,
                                                  asio::placeholders::error));
                       }
                   } else {
                       socket.close();
                   }
               });
}

void Client::on_data_read_done(boost::system::error_code ec) {
    auto msg = &read_data;
    if (!ec) {
        uint8_t type = msg->type;
        if (type == ENCRYPTED) {
#ifdef SUPPORT_ENCRYPTION
            if (encrypt) {
                // decrypt message
                if (security.decrypt_msg(buffer, *msg)) {
                    memcpy(msg, &buffer, sizeof(uint8_t) * buffer.length);
                } else {
                    LOG(DEBUG) << "Decryption failed" << std::endl;
                }
            } else {
                LOG(DEBUG) << "Encryption not enabled on client, but received encrypted message" << std::endl;
            }
#else
            LOG(DEBUG) << "Client does not support encryption, but received encrypted message" << std::endl;
#endif
        }
        switch (msg->type) {
            case IP_RESPONSE:
            {
                msg->data[msg->length - HEADER_LEN] = '\0';
                std::string config((const char*)msg->data);
                std::istringstream iss(config);
                std::vector<std::string> results(std::istream_iterator<std::string>{iss},
                                                 std::istream_iterator<std::string>());
                if (results.size() >= 3) {
                    LOG(INFO) << "Got config: [IP] " << results[0] << ", [ROUTE] " << results[1]
                     << ", [DNS] " << results[2];
                    if(results.size() >= 4) { LOG(INFO) << "," << results[3]; dns[1] = results[3]; }
                    if(results.size() >= 5) { LOG(INFO) << "," << results[4]; dns[2] = results[4]; }
                    LOG(INFO) << std::endl;
                    ipv4 = results[0];
                    gateway = results[1];
                    dns[0] = results[2];
                } else {
                    LOG_FATAL("Got invalid IP config from server");
                }
            }
                break;
            case RESPONSE:
                tunnel.send_packet(msg->data,msg->length - HEADER_LEN);
                break;
            case HEARTBEAT:
                LOG(DEBUG) << "Received heartbeat from server" << std::endl;
                last_heartbeat_recv = time(nullptr);
                break;
            case ENCRYPTED:
                // server does not support encryption, send NAK
                write_data.type = UNSUPPORTED;
                write_data.length = HEADER_LEN;
                do_write(HEADER_LEN);
                break;
            default:
                // unsupported message type, keep silent
                break;
        }
        do_read();
    } else {
        stop();
    }
}

void Client::get_ip_config() {
    if(tries-- == 0) {
        LOG_FATAL("Failed to obtain IP config from server");
    }
    if (!ipv4.empty()) {
        tunnel.set_tunnel_ip(ipv4, "255.255.255.0");
        tunnel.assign_tun_ip();
        tunnel.assign_tun_route();
        return; // config success
    }
    LOG(INFO) << "Sending IP request to server" << std::endl;
    write_data.type = IP_REQUEST;
    write_data.length = HEADER_LEN;
    do_write(HEADER_LEN);

    ip_conf_timer.expires_from_now(boost::posix_time::seconds(3));
    ip_conf_timer.async_wait(boost::bind(&Client::get_ip_config, this));
}
