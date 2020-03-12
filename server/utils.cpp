/*
 * Created by zx on 2020/3/12.
 */
#include "utils.h"

#include <utility>

using namespace boost;
using namespace boost::system;
using namespace boost::asio;
using ip::tcp;

const auto ONE_SECOND = boost::posix_time::seconds(1);

namespace utils {
    AddressPool::AddressPool(const boost::asio::ip::address_v4 &start_addr, const boost::asio::ip::address_v4 &end_addr)
            : pool(), start(start_addr), end(end_addr) {
        if (start_addr > end_addr) {
            throw std::invalid_argument("Invalid ip address range");
        }
        for (auto st = start_addr.to_ulong(); st <= end_addr.to_ulong(); ++st) {
            pool.emplace(st);
        }
    }

    ip::address_v4 AddressPool::obtain_ip_address() {
        if (!pool.empty()) {
            auto res = ip::address_v4(*pool.begin());
            pool.erase(pool.begin());
            return res;
        } else {
            ip::address_v4(0);
        }
    }

    void AddressPool::return_ip_address(const ip::address_v4 &addr) {
        if (addr >= start && addr <= end) {
            pool.emplace(addr.to_ulong());
        }
    }

    Session::Session(Server &_server, boost::asio::ip::tcp::socket skt)
            : server(_server), socket(std::move(skt)) {
        info.count = 20;
        info.secs = time(nullptr);
        error_code ec;
        auto endpoint = socket.remote_endpoint(ec);
        info.v6addr = endpoint.address().to_string();
    }

    void Session::start() {
        do_read();
    }

    void Session::close(bool remove) {
        if(socket.is_open()) {
            socket.close();
            LOG(INFO) << "Connection closed by: " << info.v6addr << std::endl;
        }
        if(remove)
            server.clear_session(info.v6addr);
    }

    void Session::do_read() {
        auto self(shared_from_this());
        socket.async_read_some(boost::asio::buffer(&read_data, max_length),
                               [this, self](boost::system::error_code ec, std::size_t length) {
                                   if (!ec) {
                                       if(read_data.length < HEADER_LEN) {
                                           LOG(DEBUG) << "Got invalid packet from: " << info.v6addr << std::endl;
                                       } else {
                                           switch (read_data.type) {
                                               case IP_REQUEST: {
                                                   auto conf = server.config;
                                                   conf.lease = server.v6_v4_mappings[info.v6addr].to_string();
                                                   write_data.type = IP_RESPONSE;
                                                   write_data.length =
                                                           HEADER_LEN + conf.serialize(write_data.data, DATA_LEN);
                                                   do_write(write_data.length);
                                               }
                                                   break;
                                               case REQUEST:
                                                   // TODO: forward this to tunnel
                                                   break;
                                               case HEARTBEAT:
                                                   LOG(DEBUG) << "Receive heartbeat from: " << info.v6addr << std::endl;
                                                   info.secs = time(nullptr);
                                                   do_read();
                                                   break;
                                           }
                                       }
                                   } else {
                                       close();
                                   }
                               });
    }

    void Session::do_write(std::size_t length) {
        auto self(shared_from_this());
        boost::asio::async_write(socket, boost::asio::buffer(&write_data, length),
                                 [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec) {
                                         do_read();
                                     } else {
                                         close();
                                     }
                                 });
    }

    void Session::send_heartbeat() {
        info.count = 20;
        write_data.type = HEARTBEAT;
        write_data.length = HEADER_LEN;
        do_write(HEADER_LEN);
    }

    Server::Server(std::shared_ptr<AddressPool> p, const ConfigPayload &conf, io_service &io_service,
                   const ip::address_v6 &address, ushort port)
            : acceptor(io_service, tcp::endpoint(address, port)),
              socket(io_service), pool(std::move(p)), config(conf),
              heartbeat_timer(io_service, ONE_SECOND){
        accept();
        heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
    }

    void Server::handle_heartbeat() {
        // handle heartbeat
        for(auto it = v6_v4_mappings.begin(); it != v6_v4_mappings.end();) {
            auto & sess = user_sessions[it->second.to_ulong()];
            if(sess->heartbeat_tick() == 0) {
                sess->send_heartbeat();
                LOG(DEBUG) << "Sending heartbeat to client: " << it->first << std::endl;
            }
            if(sess->expires()) {
                sess->close(false);
                user_sessions.erase(it->second.to_ulong());
                it = v6_v4_mappings.erase(it);
                LOG(DEBUG) << "Client: timed out" << it->first << std::endl;
            } else
                ++it;
        }

        heartbeat_timer.expires_from_now(ONE_SECOND);
        heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
    }

    void Server::handle_client(boost::system::error_code ec) {
        if (!ec) {
            auto endpoint = socket.remote_endpoint();
            auto v6addr = endpoint.address().to_v6();
            LOG(INFO) << "Accepted client: " << v6addr << ":" << endpoint.port() << std::endl;
            ip::address_v4 v4addr;
            bool reuse = false;
            if (v6_v4_mappings.find(v6addr.to_string()) == v6_v4_mappings.end()) {
                v4addr = pool->obtain_ip_address();
            } else {
                reuse = true;
                v4addr = v6_v4_mappings[v6addr.to_string()];
            }
            if (v4addr.to_ulong() != 0) {
                v6_v4_mappings[v6addr.to_string()] = v4addr;
                if (reuse) LOG(INFO) << "Reuse ";
                LOG(INFO) << "IPv4 lease: " << v4addr << std::endl;
                auto sess = user_sessions.find(v4addr.to_ulong());
                if (sess != user_sessions.end()) {
                    sess->second->close();
                }
                auto session = std::make_shared<Session>(*this, std::move(socket));
                user_sessions[v4addr.to_ulong()] = session;
                session->start();
            }
        }
        accept();
    }

    void Server::accept() {
        acceptor.async_accept(socket, boost::bind(&Server::handle_client, this, boost::asio::placeholders::error));
    }
}