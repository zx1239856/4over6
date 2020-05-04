/*
 * Created by zx on 2020/3/12.
 */
#ifndef SRC_UTILS_HPP
#define SRC_UTILS_HPP

#include <unordered_set>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid.hpp>

#ifdef SUPPORT_ENCRYPTION

#include <sodium.h>

#endif

#include "third-party/aixlog.hpp"
#include "msg.h"

#define LOG_FATAL(fmt) LOG(FATAL) << COLOR(red) << fmt << COLOR(none) << std::endl; exit(EXIT_FAILURE);
#define LOG_WARN(fmt) LOG(WARNING) << COLOR(yellow) << fmt << COLOR(none)

namespace utils {
    inline bool is_valid_uuid(std::string const& maybe_uuid, boost::uuids::uuid& result) {
        using namespace boost::uuids;
        try {
            result = string_generator()(maybe_uuid);
            return result.version() != uuid::version_unknown;
        } catch(...) {
            return false;
        }
    }

    struct UserInfo {
        uint32_t count;
        uint64_t secs;
        std::string v6addr;
    };

    class AddressPool {
    public:
        AddressPool(const boost::asio::ip::address_v4 &start_addr, const boost::asio::ip::address_v4 &end_addr);

        size_t size() const {
            return pool.size();
        }

        boost::asio::ip::address_v4 obtain_ip_address();

        void return_ip_address(const boost::asio::ip::address_v4 &addr);

        std::string get_range() const {
            return start.to_string() + "-" + end.to_string();
        }

    private:
        boost::asio::ip::address_v4 start, end;
        std::unordered_set<unsigned long> pool{};
    };

#ifdef SUPPORT_ENCRYPTION

    class SecurityHandler {
    public:
        explicit SecurityHandler(const uint8_t uuid[16]);

        bool encrypt_msg(struct Msg &dst, const struct Msg &src);

        bool decrypt_msg(struct Msg &dst, const struct Msg &src);

    private:
        uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    };

#endif
}

#endif //SERVER_UTILS_HPP
