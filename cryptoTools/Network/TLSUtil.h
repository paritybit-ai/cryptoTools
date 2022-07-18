#pragma once
#include "cryptoTools/Common/config.h"

#ifdef ENABLE_BOOST
#include <string>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#if defined(ENABLE_WOLFSSL) || defined(ENABLE_BOOST_OPENSSL)

namespace osuCrypto
{
using error_code = boost::system::error_code;
enum class TLS_errc
{
    Success = 0,
    Failure,
    ContextNotInit,
    ContextAlreadyInit,
    ContextFailedToInit,
    OnlyValidForServerContext,
    SessionIDMismatch
};
} // namespace osuCrypto

namespace boost {
    namespace system {
        template <>
        struct is_error_code_enum<osuCrypto::TLS_errc> : true_type {};
    }
}

namespace osuCrypto
{
struct TLSErrCategory : boost::system::error_category
{
    const char* name() const noexcept override
    {
        return "osuCrypto_TLS";
    }

    std::string message(int err) const override
    {
        switch (static_cast<osuCrypto::TLS_errc>(err))
        {
        case osuCrypto::TLS_errc::Success:
            return "Success";
        case osuCrypto::TLS_errc::Failure:
            return "Generic Failure";
        case osuCrypto::TLS_errc::ContextNotInit:
            return "TLS context not init";
        case osuCrypto::TLS_errc::ContextAlreadyInit:
            return "TLS context is already init";
        case osuCrypto::TLS_errc::ContextFailedToInit:
            return "TLS context failed to init";
        case osuCrypto::TLS_errc::OnlyValidForServerContext:
            return "Operation is only valid for server initialized TLC context";
        case osuCrypto::TLS_errc::SessionIDMismatch:
            return "Critical error on connect. Likely active attack by thirdparty";
        default:
            return "unknown error";
        }
    }
};
const TLSErrCategory TLSCategory{};

inline error_code make_error_code(TLS_errc e)
{
    auto ee = static_cast<int>(e);
    return { ee, TLSCategory };
}

} // namespace osuCrypto


#endif
#else 
namespace osuCrypto
{
    struct TLSContext {
        operator bool() const
        {
            return false;
        }
};
}
#endif
