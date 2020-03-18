/*
 * Created by zx on 2020/3/12.
 */
#include "utils.h"

#include <utility>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_tun.h>
#include <net/route.h>

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

    Session::Session(Server &_server, boost::asio::io_service &io_service)
            : server(_server), socket(io_service) {
    }

    void Session::start() {
        info.count = 20;
        info.secs = time(nullptr);
        error_code ec;
        auto endpoint = socket.remote_endpoint(ec);
        info.v6addr = endpoint.address().to_string();
        LOG(INFO) << "Accepted client: " << info.v6addr << ":" << endpoint.port() << std::endl;
        do_read();
    }

    void Session::close(bool remove) {
        if (socket.is_open()) {
            socket.close();
            LOG(INFO) << "Connection closed by: " << info.v6addr << std::endl;
        }
        if (remove)
            server.clear_session(info.v6addr);
    }

    void Session::do_read() {
        auto self(shared_from_this());
        async_read(socket, boost::asio::buffer(&read_data, HEADER_LEN),
                   [this, self](boost::system::error_code ec, std::size_t length) {
                       if (!ec) {
                           if (length < HEADER_LEN || read_data.length < HEADER_LEN) {
                               LOG(DEBUG) << "Got invalid packet from: " << info.v6addr << std::endl;
                           } else {
                               async_read(socket, boost::asio::buffer(&read_data.data, std::min(DATA_LEN,
                                                                                                read_data.length -
                                                                                                HEADER_LEN)),
                                          boost::bind(&Session::on_data_read_done, shared_from_this(),
                                                      asio::placeholders::error));
                           }
                       } else {
                           close();
                       }
                   });
    }

    void Session::do_write(std::size_t length) {
        auto self(shared_from_this());
        system::error_code ec;
        boost::asio::write(socket, boost::asio::buffer(&write_data, length), boost::asio::transfer_all(), ec);
        if (ec) {
            close();
        }
    }

    void Session::send_heartbeat() {
        info.count = 20;
        write_data.type = HEARTBEAT;
        write_data.length = HEADER_LEN;
        do_write(HEADER_LEN);
    }

    void Session::send_tunnel_data(uint8_t *buffer, size_t length) {
        write_data.length = length + HEADER_LEN;
        write_data.type = RESPONSE;
        memcpy(&write_data.data, buffer, sizeof(uint8_t) * length);
//        LOG(DEBUG) << "Send response to client: " << info.v6addr << ", len: " << write_data.length << std::endl;
        do_write(write_data.length);
    }

    void Session::on_data_read_done(boost::system::error_code ec) {
        auto msg = &read_data;
        if (!ec) {
            switch (msg->type) {
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
                    this->server.tunnel.send_packet(msg->data,
                                                    msg->length - HEADER_LEN);
                    break;
                case HEARTBEAT:
                    LOG(DEBUG) << "Receive heartbeat from: " << info.v6addr
                               << std::endl;
                    info.secs = time(nullptr);
                    break;
            }
            do_read();
        } else {
            close();
        }
    }

    Server::Server(std::shared_ptr<AddressPool> p, const ConfigPayload &conf, io_service &io_service,
                   const ip::address_v6 &address, ushort port)
            : acceptor(io_service, tcp::endpoint(address, port)),
              socket(io_service), pool(std::move(p)), config(conf),
              heartbeat_timer(io_service, ONE_SECOND),
              tunnel(io_service,
                     boost::bind(&Server::handle_tun_data, this, boost::placeholders::_1, boost::placeholders::_2),
                     "4over6_tun", conf.gateway, conf.netmask) {
        accept();
        heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
    }

    void Server::handle_heartbeat() {
        // handle heartbeat
        for (auto it = v6_v4_mappings.begin(); it != v6_v4_mappings.end();) {
            auto &sess = user_sessions[it->second.to_ulong()];
            if (sess == nullptr)
                continue;
            if (sess->heartbeat_tick() == 0) {
                sess->send_heartbeat();
                LOG(DEBUG) << "Sending heartbeat to client: " << it->first << std::endl;
            }
            if (sess->expires()) {
                sess->close(false);
                LOG(DEBUG) << "Client: timed out" << it->first << std::endl;
                pool->return_ip_address(it->second);
                user_sessions.erase(it->second.to_ulong());
                it = v6_v4_mappings.erase(it);
            } else
                ++it;
        }

        heartbeat_timer.expires_from_now(ONE_SECOND);
        heartbeat_timer.async_wait(boost::bind(&Server::handle_heartbeat, this));
    }

    void Server::handle_client(std::shared_ptr<Session> session, boost::system::error_code ec) {
        if (!ec) {
            auto endpoint = session->get_socket().remote_endpoint();
            auto v6addr = endpoint.address().to_v6();
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
                user_sessions[v4addr.to_ulong()] = session;
                session->start();
            }
        }
        accept();
    }

    void Server::accept() {
        auto session = std::make_shared<Session>(*this, acceptor.get_io_service());
        acceptor.async_accept(session->get_socket(),
                              boost::bind(&Server::handle_client, this, session, boost::asio::placeholders::error));
    }

    void Server::handle_tun_data(uint8_t *buffer, size_t length) {
        auto *hdr = reinterpret_cast<struct iphdr *>(buffer);
        if (hdr->version == 4) {
            auto dst = ntohl(hdr->daddr);
//            LOG(DEBUG) << ip::address_v4(ntohl(hdr->saddr)) << " --> " << ip::address_v4(dst) << std::endl;
            auto it = user_sessions.find(dst);
            if (it != user_sessions.end() && it->second != nullptr) {
                it->second->send_tunnel_data(buffer, length);
            }
        }
    }

    void TunDevice::async_read_packet() {
        stream_descriptor.async_read_some(boost::asio::buffer(readbuf),
                                          boost::bind(&TunDevice::on_read_done, this, boost::asio::placeholders::error,
                                                      boost::asio::placeholders::bytes_transferred));
    }

    void TunDevice::on_read_done(const boost::system::error_code &ec, size_t length) {
        if (ec) {
            throw std::runtime_error("Failed to read from TUN device");
        }
        if (readbuf[2] == 8) {
            // ipv4 packet
            handler_func(&readbuf[4], length - 4);
        }
        async_read_packet();
    }

    void TunDevice::assign_tun_ip() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, if_name.c_str(), IF_NAMESIZE);
        ifr.ifr_addr.sa_family = AF_INET;
        sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;

        inet_pton(AF_INET, tun_ip.c_str(), &addr->sin_addr);
        ioctl(sock, SIOCSIFADDR, &ifr);

        ifr.ifr_mtu = 1500 - HEADER_LEN;
        ioctl(sock, SIOCSIFMTU, (caddr_t) &ifr);
        ifr.ifr_flags |= (IFF_TUN | IFF_NO_PI | IFF_UP | IFF_RUNNING);
        if (ioctl(sock, SIOCSIFFLAGS, &ifr)) {
            throw std::runtime_error("Failed to bring up virtual tap device");
        }

        close(sock);
    }

    void TunDevice::assign_tun_route() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);

        struct rtentry rt = {0};

        auto *sockinfo = (struct sockaddr_in *) &rt.rt_gateway;
        sockinfo->sin_family = AF_INET;
        sockinfo->sin_addr.s_addr = 0;

        sockinfo = (struct sockaddr_in *) &rt.rt_genmask;
        sockinfo->sin_family = AF_INET;
        inet_pton(AF_INET, net_mask.c_str(), &sockinfo->sin_addr);

        auto mask = sockinfo->sin_addr.s_addr;

        sockinfo = (struct sockaddr_in *) &rt.rt_dst;
        sockinfo->sin_family = AF_INET;
        inet_pton(AF_INET, tun_ip.c_str(), &sockinfo->sin_addr);
        sockinfo->sin_addr.s_addr &= mask;

        rt.rt_flags = RTF_UP;
        rt.rt_metric = 0;
        rt.rt_dev = const_cast<char *>(if_name.c_str());

        LOG(INFO) << "Add route: " << tun_ip << ", mask: " << net_mask << std::endl;

        auto err = ioctl(sock, SIOCADDRT, &rt);
        if (err) {
            throw std::runtime_error(
                    "Failed to add link-scope route for virtual tap device, errno: " + std::to_string(errno));
        }
        close(sock);
    }

    TunDevice::TunDevice(boost::asio::io_service &io_service, TunDevice::packet_handler handler,
                         const std::string &_if_name, const std::string &_tun_ip, const std::string &_net_mask)
            : stream_descriptor(io_service),
              if_name(_if_name), tun_ip(_tun_ip),
              net_mask(_net_mask), handler_func(handler) {
        int tun_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (tun_fd < 0) {
            throw std::runtime_error("Failed to open tun device node /dev/net/tun");
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN;
        if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
            close(tun_fd);
            throw std::runtime_error("Failed to create tun device");
        }
        if_name = ifr.ifr_name;

        assign_tun_ip();
        assign_tun_route();

        int opts = fcntl(tun_fd, F_GETFL);
        if (opts < 0) {
            throw std::runtime_error("Invalid options of TUN device");
        }
        opts |= O_NONBLOCK;
        if (fcntl(tun_fd, F_SETFL, opts) < 0) {
            throw std::runtime_error("Failed to set non-blocking mode of TUN device");
        }

        stream_descriptor.assign(tun_fd);
        async_read_packet();
    }

    void TunDevice::send_packet(const uint8_t *buffer, size_t length) {
        writebuf[0] = 0;
        writebuf[1] = 0;
        writebuf[2] = 8;
        writebuf[3] = 0;
        memcpy(4 + writebuf, buffer, std::min(length, sizeof(writebuf) - 4));

//        auto hdr = reinterpret_cast<const struct iphdr *>(buffer);
//        LOG(DEBUG) << ip::address_v4(ntohl(hdr->saddr)) << " --> " << ip::address_v4(ntohl(hdr->daddr)) << std::endl;
        system::error_code ec;
        boost::asio::write(stream_descriptor, boost::asio::buffer(writebuf, 4 + length), boost::asio::transfer_all(),
                           ec);
    }
}