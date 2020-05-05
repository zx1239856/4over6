//
// Created by zx on 2020/5/4.
//
#include <net/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include "tun_device.h"
#include "utils.h"

using namespace boost;
using namespace boost::system;

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

    ifr.ifr_mtu = 1500;
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

TunDevice::TunDevice(boost::asio::io_service &io_service, const TunDevice::packet_handler &handler,
                     const std::string &_if_name, const std::string &_tun_ip, const std::string &_net_mask)
        : stream_descriptor(io_service),
          if_name(_if_name), tun_ip(_tun_ip),
          net_mask(_net_mask), handler_func(handler) {}

void TunDevice::start() {
    int tun_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun_fd < 0) {
        throw std::runtime_error("Failed to open tun device node /dev/net/tun");
    }

    struct ifreq ifr{};
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