//
// Created by zx on 2020/5/4.
//

#ifndef SRC_TUN_DEVICE_H
#define SRC_TUN_DEVICE_H

#include <boost/asio.hpp>
#include <boost/bind.hpp>

class TunDevice {
public:
    typedef std::function<void(uint8_t *, size_t)> packet_handler;

    TunDevice(boost::asio::io_service &io_service, packet_handler handler, const std::string &if_name,
              const std::string &tun_ip, const std::string &net_mask);

    const std::string &device() { return if_name; };

    void send_packet(const uint8_t *buffer, size_t length);

    inline void set_tunnel_ip(const std::string &ip, const std::string &nmask) {
        tun_ip = ip;
        net_mask = nmask;
    }

    void assign_tun_ip();

    void assign_tun_route();
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
};


#endif //SERVER_TUN_DEVICE_H
