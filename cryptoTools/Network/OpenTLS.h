#pragma once
#include <cryptoTools/Network/TLSUtil.h>

#if defined(ENABLE_BOOST_OPENSSL) && defined(ENABLE_BOOST) 
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <cryptoTools/Network/SocketAdapter.h>

namespace osuCrypto {
struct OpenSSLContext;
class BoostSSLSocket;
using TLSContext = OpenSSLContext;
using TLSSocket = BoostSSLSocket;
using buffer = boost::asio::mutable_buffer;
class BoostSSLSocket : public Socket {
public:
    BoostSSLSocket(boost::asio::io_context& ios, TLSContext& ctx);

    BoostSSLSocket(BoostSSLSocket&&)=delete;
    BoostSSLSocket(const BoostSSLSocket&)=delete;

    ~BoostSSLSocket() {};

    void close() override;
    void cancel() override;

    void async_send(span<buffer> buffers, io_completion_handle&& fn) override;
    void async_recv(span<buffer> buffers, io_completion_handle&& fn) override;

    void async_connect(const boost::asio::ip::tcp::endpoint& endpoint, completion_handle&& cb) override;
    void async_connect(const boost::asio::ip::tcp::resolver::results_type& endpoints, completion_handle&& cb) override;
    void async_accept(boost::asio::ip::tcp::acceptor& acceptor, completion_handle&& cb) override;

    bool verify_certificate(bool preverified,
      boost::asio::ssl::verify_context& ctx)
    {
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        std::cout << __FILE__ << ":" << __LINE__ << "Verifying " << subject_name << std::endl;

        return preverified;
    }
private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_;
};

struct OpenSSLContext
{
    enum class Mode
    {
        Client,
        Server,
        Both
    };
    std::shared_ptr<boost::asio::ssl::context> m_boost_ctx;
    std::string m_sni_name;
    Mode m_mode = Mode::Client;
    void init(Mode mode, error_code& ec);
    Mode mode() {
        return m_mode;
    }

    void loadCertFile(std::string path, error_code& ec);
    void loadCert(span<u8> data, error_code& ec);

    void loadKeyPairFile(std::string pkPath, std::string skPath, error_code& ec);
    void loadKeyPair(span<u8> pkData, span<u8> skData, error_code& ec);
    void setSNIName(const std::string& sni_name, error_code& ec);

    void requestClientCert(error_code& ec);
    void NoneVerify();

    bool isInit() const {
        return  m_boost_ctx != nullptr;
    }

    std::string get_password() const
    {
        return "boost_cryptoTools_ssl";
    }

    operator bool() const
    {
        return isInit();
    }
};
} // osuCrypto
#endif
