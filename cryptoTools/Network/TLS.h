#pragma once
#include "cryptoTools/Common/config.h"
#include "cryptoTools/Network/TLSUtil.h"

#if defined(ENABLE_WOLFSSL) && defined(ENABLE_BOOST) && !defined(ENABLE_BOOST_OPENSSL)

#include <string>
#include <boost/system/error_code.hpp>
#include <boost/asio/strand.hpp>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <memory>

#ifndef WC_NO_HARDEN
#define WC_NO_HARDEN
#endif

#ifdef _MSC_VER
#define WOLFSSL_USER_SETTINGS
#define WOLFSSL_LIB
#endif

// #include <wolfssl/ssl.h>
#undef ALIGN16

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#if defined(_MSC_VER) && !defined(KEEP_PEER_CERT)
#error "please compile wolfSSl with KEEP_PEER_CERT. add this to the user_setting.h file in wolfssl..."
#endif

#ifdef ENABLE_NET_LOG
#define WOLFSSL_LOGGING
#endif

struct WOLFSSL_METHOD;
struct WOLFSSL_CTX;
struct WOLFSSL_X509;
struct WOLFSSL;

namespace osuCrypto
{
    error_code readFile(const std::string& file, std::vector<u8>& buffer);

    enum class WolfSSL_errc
    {
        Success = 0,
        Failure = 1
    };
}

namespace boost {
    namespace system {
        template <>
        struct is_error_code_enum<osuCrypto::WolfSSL_errc> : true_type {};
    }
}

namespace cryptoTools_network_tls {

    struct WolfSSLErrCategory : boost::system::error_category
    {
        const char* name() const noexcept override
        {
            return "osuCrypto_WolfSSL";
        }

        std::string message(int err) const override;
    };

    const WolfSSLErrCategory WolfSSLCategory{};
} // namespace cryptoTools_network_tls

namespace osuCrypto
{
    using namespace cryptoTools_network_tls;
    inline error_code make_error_code(WolfSSL_errc e)
    {
        auto ee = static_cast<int>(e);
        return { ee, WolfSSLCategory };
    }

    inline error_code wolfssl_error_code(int ret);


    struct WolfContext
    {
        enum class Mode
        {
            Client,
            Server,
            Both
        };

        struct Base
        {
            WOLFSSL_METHOD* mMethod = nullptr;
            WOLFSSL_CTX* mCtx = nullptr;
            Mode mMode = Mode::Client;

            Base(Mode mode);
            ~Base();
        };

        std::shared_ptr<Base> mBase;


        void init(Mode mode, error_code& ec);

        void loadCertFile(std::string path, error_code& ec);
        void loadCert(span<u8> data, error_code& ec);

        void loadKeyPairFile(std::string pkPath, std::string skPath, error_code& ec);
        void loadKeyPair(span<u8> pkData, span<u8> skData, error_code& ec);
        void setSNIName(const std::string& sni_name, error_code& ec);

        void requestClientCert(error_code& ec);
        void NoneVerify();


        bool isInit() const {
            return mBase != nullptr;                
        }
        Mode mode() const {
            if (isInit())
                return mBase->mMode;
            else return Mode::Both;
        }

        operator bool() const
        {
            return isInit();
        }


        operator WOLFSSL_CTX* () const
        {
            return mBase ? mBase->mCtx : nullptr;
        }

    };

    using TLSContext = WolfContext;

    struct WolfCertX509
    {
        WOLFSSL_X509* mCert = nullptr;

        std::string commonName();

        std::string notAfter();


        std::string notBefore();
    };

    struct WolfSocket : public Socket, public LogAdapter
    {

        using buffer = boost::asio::mutable_buffer;

        boost::asio::strand<boost::asio::io_context::executor_type> mStrand;
        boost::asio::io_context& mIos;
        WOLFSSL* mSSL = nullptr;
#ifdef WOLFSSL_LOGGING
        oc::Log mLog_;
#endif
        std::vector<buffer> mSendBufs, mRecvBufs;

        u64 mSendBufIdx = 0, mRecvBufIdx = 0;
        u64 mSendBT = 0, mRecvBT = 0;

        error_code mSendEC, mRecvEC, mSetupEC;

        io_completion_handle mSendCB, mRecvCB;
        completion_handle mSetupCB, mShutdownCB;

        bool mCancelingPending = false;

        struct WolfState
        {
            enum class Phase { Uninit, Connect, Accept, Normal, Closed };
            Phase mPhase = Phase::Uninit;
            span<char> mPendingSendBuf;
            span<char> mPendingRecvBuf;
            bool hasPendingSend() { return mPendingSendBuf.size() > 0; }
            bool hasPendingRecv() { return mPendingRecvBuf.size() > 0; }
        };

        WolfState mState;

        WolfSocket(boost::asio::io_context& ios, WolfContext& ctx);
        WolfSocket(boost::asio::io_context& ios, boost::asio::ip::tcp::socket&& sock, WolfContext& ctx);

        WolfSocket(WolfSocket&&) = delete;
        WolfSocket(const WolfSocket&) = delete;

        ~WolfSocket();

        void close() override;

        void cancel() override;
        
        void async_send(
            span<buffer> buffers,
            io_completion_handle&& fn) override;

        void async_recv(
            span<buffer> buffers,
            io_completion_handle&& fn) override;



        void setDHParamFile(std::string path, error_code& ec);
        void setDHParam(span<u8> paramData, error_code& ec);

        WolfCertX509 getCert();

        bool hasRecvBuffer() { return mRecvBufIdx < mRecvBufs.size(); }
        buffer& curRecvBuffer() { return mRecvBufs[mRecvBufIdx]; }

        bool hasSendBuffer() { return mSendBufIdx < mSendBufs.size(); }
        buffer& curSendBuffer() { return mSendBufs[mSendBufIdx]; }

        void send(
            span<buffer> buffers,
            error_code& ec,
            u64& bt);

        void sendNext();

        int sslRequestSendCB(char* buf, int size);

        void recv(
            span<buffer> buffers,
            error_code& ec,
            u64& bt);
        

        void recvNext();

        int sslRequestRecvCB(char* buf, int size);


        // ssl connect
        // void connect(error_code& ec);
        // socket connect + ssl connect
        void async_connect(const boost::asio::ip::tcp::endpoint& address, completion_handle&& cb) override;
        void connectNext();

        // ssl accept
        // void accept(error_code& ec);
        // socket accept + ssl accept
        void async_accept(boost::asio::ip::tcp::acceptor& acceptor, completion_handle&& cb) override;
        void acceptNext();

#ifdef WOLFSSL_LOGGING
        void LOG(std::string X);
#endif

        static int recvCallback(WOLFSSL* ssl, char* buf, int size, void* ctx)
        {
            //lout << "in recv cb with " << std::hex << u64(ctx) << std::endl;
            WolfSocket& sock = *(WolfSocket*)ctx;
            assert(sock.mSSL == ssl);
            return sock.sslRequestRecvCB(buf, size);
        }

        static int sendCallback(WOLFSSL* ssl, char* buf, int size, void* ctx)
        {
            //lout << "in send cb with " << std::hex << u64(ctx) << std::endl;
            WolfSocket& sock = *(WolfSocket*)ctx;
            assert(sock.mSSL == ssl);
            return sock.sslRequestSendCB(buf, size);
        }
    };

    using TLSSocket = WolfSocket;

    extern std::array<u8, 5010> sample_ca_cert_pem;
    extern std::array<u8, 0x26ef> sample_server_cert_pem;
    extern std::array<u8, 0x68f> sample_server_key_pem;
    extern std::array<u8, 0x594> sample_dh2048_pem;

}
#endif
