/*
 * Created by zx on 2020/3/12.
 */

#ifndef SERVER_MSG_H
#define SERVER_MSG_H

constexpr uint8_t IP_REQUEST = 100;
constexpr uint8_t IP_RESPONSE = 101;
constexpr uint8_t REQUEST = 102;
constexpr uint8_t RESPONSE = 103;
constexpr uint8_t HEARTBEAT = 104;

constexpr size_t DATA_LEN = 4096;
constexpr size_t HEADER_LEN = sizeof(uint32_t) + sizeof(uint8_t);

struct Msg {
    uint32_t length;
    uint8_t type;
    uint8_t data[DATA_LEN];
} __attribute__((packed));

struct ConfigPayload {
    std::string lease;
    std::string gateway;
    std::string netmask;
    std::string dns[3];

    size_t serialize(uint8_t *buffer, size_t max_len) {
        std::ostringstream out;
        out << lease << " " << gateway << " " << dns[0] << " " << dns[1] << " " << dns[2];
        auto str = out.str();
        auto len = std::min(max_len, str.length());
        memcpy(buffer, reinterpret_cast<const uint8_t *>(str.c_str()), len);
        return len;
    }
};

#endif //SERVER_MSG_H
