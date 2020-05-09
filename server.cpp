//
// Created by zx on 2020/5/4.
//

#include "server.h"
#include <utility>
#include <linux/ip.h>

using namespace boost;
using namespace boost::system;
using namespace boost::asio;
using ip::tcp;
using namespace utils;

const auto ONE_SECOND = boost::posix_time::seconds(1);

#if BOOST_VERSION >= 107000

ServerSession::ServerSession(Server &_server, boost::asio::executor io_service)
        : server(_server), socket(io_service) {
}

#else
ServerSession::ServerSession(Server &_server, boost::asio::io_service &io_service)
                : server(_server), socket(io_service) {
}
#endif

void ServerSession::start() {
    info.count = 20;
    info.secs = time(nullptr);
    error_code ec;
    auto endpoint = socket.remote_endpoint(ec);
    info.v6addr = endpoint.address().to_string();
    LOG(INFO) << "Accepted client: " << info.v6addr << ":" << endpoint.port() << std::endl;
    do_read();
}

void ServerSession::close(bool remove) {
    if (socket.is_open()) {
        socket.close();
        LOG(INFO) << "Connection closed by: " << info.v6addr << std::endl;
    }
    if (remove)
        server.clear_session(info.v6addr);
}

void ServerSession::do_read() {
    auto self(shared_from_this());
    async_read(socket, boost::asio::buffer(&read_data, HEADER_LEN),
               [this, self](boost::system::error_code ec, std::size_t length) {
                   if (!ec) {
                       if (length < HEADER_LEN || read_data.length < HEADER_LEN) {
                           LOG(DEBUG) << "Got invalid packet from: " << info.v6addr << std::endl;
                       } else if (read_data.length > MAX_MSG_LEN) {
                           LOG(DEBUG) << "Invalid msg size: " << read_data.length << std::endl;
                           do_read();
                       } else {
                           async_read(socket, boost::asio::buffer(&read_data.data, std::min(DATA_LEN,
                                                                                            read_data.length -
                                                                                            HEADER_LEN)),
                                      boost::bind(&ServerSession::on_data_read_done, shared_from_this(),
                                                  asio::placeholders::error));
                       }
                   } else {
                       close();
                   }
               });
}

void ServerSession::do_write() {
    auto self(shared_from_this());
#ifdef SUPPORT_ENCRYPTION
    if (encrypt) {
        if (server.security.encrypt_msg(buffer, write_data)) {
            memcpy(&write_data, &buffer, buffer.length);
        } else {
            LOG(DEBUG) << "Encryption required by client, but encryption failed" << std::endl;
        }
    }
#endif
    system::error_code ec;
    boost::asio::write(socket, boost::asio::buffer(&write_data, write_data.length), boost::asio::transfer_all(), ec);
    if (ec) {
        close();
    }
}

void ServerSession::send_heartbeat() {
    info.count = 20;
    write_data.type = HEARTBEAT;
    write_data.length = HEADER_LEN;
    do_write();
}

void ServerSession::send_tunnel_data(uint8_t *buf, size_t length) {
    write_data.length = length + HEADER_LEN;
    write_data.type = RESPONSE;
    memcpy(&write_data.data, buf, sizeof(uint8_t) * length);
    do_write();
}

void ServerSession::on_data_read_done(boost::system::error_code ec) {
    auto msg = &read_data;
    if (!ec) {
        uint8_t type = msg->type;
        if (type == ENCRYPTED) {
#ifdef SUPPORT_ENCRYPTION
            if (server.config.encrypt) {
                if (!encrypt) {
                    encrypt = true;
                    LOG(INFO) << "Enable encryption for client: " << info.v6addr << std::endl;
                }
                // decrypt message
                if (server.security.decrypt_msg(buffer, *msg)) {
                    memcpy(msg, &buffer, sizeof(uint8_t) * buffer.length);
                } else {
                    LOG(DEBUG) << "Decryption failed" << std::endl;
                }
            } else {
                LOG(DEBUG) << "Encryption not enabled on server, but received encrypted message" << std::endl;
            }
#else
            LOG(DEBUG) << "Server does not support encryption, but received encrypted message" << std::endl;
#endif
        }
        switch (msg->type) {
            case IP_REQUEST: {
                auto &conf = server.config;
                conf.lease = server.v6_v4_mappings[info.v6addr].to_string();
                write_data.type = IP_RESPONSE;
                write_data.length =
                        HEADER_LEN + conf.serialize(write_data.data, DATA_LEN);
                do_write();
            }
                break;
            case REQUEST:
                this->server.tunnel.send_packet(msg->data,
                                                msg->length - HEADER_LEN);
                break;
            case HEARTBEAT:
                LOG(DEBUG) << "Receive heartbeat from: " << info.v6addr
                           << std::endl;
                info.secs = time(nullptr);
                break;
            case ENCRYPTED:
                // server does not support encryption, send NAK
                write_data.type = UNSUPPORTED;
                write_data.length = HEADER_LEN;
                do_write();
                break;
            case UNSUPPORTED:
                // client does not support encryption, turn it off
                encrypt = false;
                break;
            default:
                // unsupported message type, keep silent
                break;
        }
        do_read();
    } else {
        close();
    }
}

Server::Server(std::shared_ptr<AddressPool> p, const ConfigPayload &conf, io_service &io_service,
               const ip::address_v6 &address, ushort port)
        : io_serv(io_service), acceptor(io_service, tcp::endpoint(address, port)),
          socket(io_service), pool(std::move(p)), config(conf),
          heartbeat_timer(io_service, ONE_SECOND),
          tunnel(io_service,
                 boost::bind(&Server::handle_tun_data, this, boost::placeholders::_1, boost::placeholders::_2),
                 "4over6_tun", conf.gateway, conf.netmask)
#ifdef SUPPORT_ENCRYPTION
        , security(conf.key)
#endif
{}

void Server::start() {
    tunnel.start();
    accept();
    heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
    io_serv.run();
}

void Server::handle_heartbeat() {
    // handle heartbeat
    for (auto it = v6_v4_mappings.begin(); it != v6_v4_mappings.end();) {
        auto &sess = user_sessions[it->second.to_ulong()];
        if (sess == nullptr) {
            LOG_FATAL("Occurred NULL session, check your memory");
        }
        if (sess->heartbeat_tick() == 0) {
            sess->send_heartbeat();
            LOG(DEBUG) << "Sending heartbeat to client: " << it->first << std::endl;
        }
        if (sess->expires()) {
            sess->close(false);
            LOG(DEBUG) << "Timed out client: " << it->first << std::endl;
            pool->return_ip_address(it->second);
            user_sessions.erase(it->second.to_ulong());
            it = v6_v4_mappings.erase(it);
        } else
            ++it;
    }

    heartbeat_timer.expires_from_now(ONE_SECOND);
    heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
}

void Server::handle_client(std::shared_ptr<ServerSession> session, boost::system::error_code ec) {
    if (!ec) {
        auto endpoint = session->get_socket().remote_endpoint();
        auto v6addr = endpoint.address().to_v6();
        ip::address_v4 v4addr;
        if (v6_v4_mappings.find(v6addr.to_string()) != v6_v4_mappings.end()) {
            // clear previous session if already exists
            auto v4 = v6_v4_mappings[v6addr.to_string()];
            auto sess = user_sessions.find(v4addr.to_ulong());
            if (sess != user_sessions.end()) {
                sess->second->close();
            }
        }
        v4addr = pool->obtain_ip_address();
        if (v4addr.to_ulong() != 0) {
            v6_v4_mappings[v6addr.to_string()] = v4addr;
            LOG(INFO) << "IPv4 lease: " << v4addr << ", remaining: " << pool->size() << std::endl;
            user_sessions[v4addr.to_ulong()] = session;
            session->start();
        }
    }
    accept();
}

void Server::accept() {
#if BOOST_VERSION >= 107000
    auto session = std::make_shared<ServerSession>(*this, acceptor.get_executor());
#else
    auto session = std::make_shared<ServerSession>(*this, acceptor.get_io_service());
#endif
    acceptor.async_accept(session->get_socket(),
                          boost::bind(&Server::handle_client, this, session, boost::asio::placeholders::error));
}

void Server::handle_tun_data(uint8_t *buffer, size_t length) {
    auto *hdr = reinterpret_cast<struct iphdr *>(buffer);
    if (hdr->version == 4) {
        auto dst = ntohl(hdr->daddr);
        auto it = user_sessions.find(dst);
        if (it != user_sessions.end() && it->second != nullptr) {
            it->second->send_tunnel_data(buffer, length);
        }
    }
}
