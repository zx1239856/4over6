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
constexpr uint8_t UNSUPPORTED = 199;
constexpr uint8_t ENCRYPTED = 200;
constexpr uint8_t NO_TYPE = 255;

constexpr size_t DATA_LEN = 2048;

struct Msg {
    uint32_t length;
    uint8_t type;
    uint8_t data[DATA_LEN];
} __attribute__((packed));

/**
 * Encrypted Message Format
 * | length | type == ENCRYPTED |  ------------ data ---------------- |
 *                              | nonce (24 bytes) |  encrypted data  |
 */
constexpr uint8_t ADDITIONAL_DATA[] = "19260817";
constexpr uint8_t ADDITIONAL_DATA_LEN = sizeof(ADDITIONAL_DATA) / sizeof(uint8_t);

constexpr size_t HEADER_LEN = offsetof(Msg, data);

struct ConfigPayload {
    std::string lease;
    std::string gateway;
    std::string netmask;
    std::string dns[3];
    uint8_t key[16];
    bool encrypt;

    size_t serialize(uint8_t *buffer, size_t max_len) {
        std::ostringstream out;
//        out << lease << " " << gateway << " " << dns[0] << " " << dns[1] << " " << dns[2];
        out << lease << " " << "0.0.0.0" << " " << dns[0] << " " << dns[1] << " " << dns[2];
        auto str = out.str();
        auto len = std::min(max_len, str.length());
        memcpy(buffer, reinterpret_cast<const uint8_t *>(str.c_str()), len);
        return len;
    }
};

#endif //SERVER_MSG_H
