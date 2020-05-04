/*
 * Created by zx on 2020/3/12.
 */
#include "utils.h"

using namespace boost;
using namespace boost::system;
using namespace boost::asio;
using ip::tcp;

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
            return ip::address_v4(0);
        }
    }

    void AddressPool::return_ip_address(const ip::address_v4 &addr) {
        if (addr >= start && addr <= end) {
            pool.emplace(addr.to_ulong());
        }
    }

#ifdef SUPPORT_ENCRYPTION

    SecurityHandler::SecurityHandler(const uint8_t uuid[16]) {
        memcpy(key, uuid, sizeof(uint8_t) * 16);
    }

    bool SecurityHandler::encrypt_msg(struct Msg &dst, const struct Msg &src) {
        randombytes_buf(nonce, sizeof nonce);
        unsigned long long ciphertext_len;
        if (src.length + sizeof nonce + crypto_aead_xchacha20poly1305_ietf_ABYTES > DATA_LEN) {
            return false;
        }
        memcpy(dst.data, nonce, sizeof nonce);
        memcpy(key + 16, nonce, 16 * sizeof(uint8_t));
        auto cipher = ((uint8_t *) dst.data) + sizeof nonce;
        crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, &ciphertext_len, (const uint8_t *) &src, src.length,
                                                   ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nullptr, nonce, key);
        dst.type = ENCRYPTED;
        dst.length = HEADER_LEN + sizeof nonce + ciphertext_len;
        return true;
    }

    bool SecurityHandler::decrypt_msg(struct Msg &dst, const struct Msg &src) {
        memcpy(nonce, src.data, sizeof nonce);
        unsigned long long decrypted_len;
        memcpy(key + 16, nonce, 16 * sizeof(uint8_t));
        auto cipher = ((uint8_t *) src.data) + sizeof nonce;
        if (src.length > sizeof nonce + HEADER_LEN) {
            size_t cipher_len = src.length - HEADER_LEN - sizeof nonce;
            return crypto_aead_xchacha20poly1305_ietf_decrypt((uint8_t *) &dst, &decrypted_len, nullptr, cipher,
                                                              cipher_len,
                                                              ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, key) == 0;
        }
        return false;
    }

#endif
}