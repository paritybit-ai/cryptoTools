#include "OpenTLS.h"
#include "log.h"
#ifdef ENABLE_BOOST_OPENSSL

namespace osuCrypto {
BoostSSLSocket::BoostSSLSocket(boost::asio::io_context& ios, TLSContext& ctx)
    : Socket(ios), ssl_socket_(ios, *(ctx.m_boost_ctx)) {
    if (!ctx.m_sni_name.empty() && !SSL_set_tlsext_host_name(ssl_socket_.native_handle(), ctx.m_sni_name.c_str())) {
        Log("ERROR: set sni name failed, sni name:" << ctx.m_sni_name);
    }
    ssl_socket_.set_verify_callback(std::bind(&BoostSSLSocket::verify_certificate, this, std::placeholders::_1, std::placeholders::_2));
}

void BoostSSLSocket::close() {
    boost::system::error_code ec;
    ssl_socket_.shutdown(ec);
    if (ec) {
        Log("Closed boost ssl socket, ec:" << ec.message());
    }
}

void BoostSSLSocket::cancel() {
    boost::system::error_code ec;
}

void BoostSSLSocket::async_send(span<buffer> buffers, io_completion_handle&& fn) {
    boost::asio::async_write(ssl_socket_, buffers, std::forward<io_completion_handle>(fn));
}

void BoostSSLSocket::async_recv(span<buffer> buffers, io_completion_handle&& fn) {
    boost::asio::async_read(ssl_socket_, buffers, std::forward<io_completion_handle>(fn));
}

void BoostSSLSocket::async_accept(boost::asio::ip::tcp::acceptor& acceptor, completion_handle&& cb) {
    acceptor.async_accept(ssl_socket_.lowest_layer(), [this, cb=cb](const boost::system::error_code& ec) {
        if (ec) {
            Log("Error, failed to async_accept! ec:" << ec.message());
            cb(ec);
            return;
        }
        Log("Server to async hadshake");
        ssl_socket_.async_handshake(boost::asio::ssl::stream_base::server, cb);
    });
}

void BoostSSLSocket::async_connect(const boost::asio::ip::tcp::resolver::results_type& endpoints, completion_handle&& cb) {
    boost::asio::async_connect(ssl_socket_.lowest_layer(), endpoints, [this, cb] (
            const boost::system::error_code& ec, const boost::asio::ip::tcp::endpoint& addr) {
        if (ec) {
            Log("Error, failed to async_connect! ec:" << ec.message() << ", address:" << addr);
            cb(ec);
            return;
        }
        Log("Client to async hadshake");
        ssl_socket_.async_handshake(boost::asio::ssl::stream_base::client, cb);
    });
}

void BoostSSLSocket::async_connect(const boost::asio::ip::tcp::endpoint& endpoint, completion_handle&& cb) {
    ssl_socket_.lowest_layer().async_connect(endpoint, [this, cb] (
            const boost::system::error_code& ec) {
        if (ec) {
            Log("Error, failed to async_connect! ec:" << ec.message());
            cb(ec);
            return;
        }
        Log("Client to async hadshake");
        ssl_socket_.async_handshake(boost::asio::ssl::stream_base::client, cb);
    });
}

void OpenSSLContext::init(Mode mode, error_code& ec) {
    if (isInit()) {
        ec = make_error_code(TLS_errc::ContextAlreadyInit);
        return;
    }
    m_mode = mode;
    m_boost_ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
    if (mode == Mode::Client || mode == Mode::Both) {
    }
    if (mode == Mode::Server || mode == Mode::Both){
        m_boost_ctx->set_options(
        boost::asio::ssl::context::default_workarounds
        | boost::asio::ssl::context::no_sslv2
        | boost::asio::ssl::context::single_dh_use);
        m_boost_ctx->set_password_callback(std::bind(&OpenSSLContext::get_password, this));
    }
} 

void OpenSSLContext::loadCertFile(std::string path, error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    m_boost_ctx->load_verify_file(path, ec);
}

void OpenSSLContext::loadCert(span<u8> data, error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    auto buf = boost::asio::const_buffer(data.data(), data.size());
    m_boost_ctx->use_certificate(buf, boost::asio::ssl::context::pem);
}

void OpenSSLContext::loadKeyPairFile(std::string pkPath, std::string skPath, error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    m_boost_ctx->use_certificate_chain_file(skPath, ec);
    if (ec) 
    {   
        Log("Error, loadKeyPairFile failed, ec:" << ec.message());
        return;
    }
    m_boost_ctx->use_private_key_file(pkPath, boost::asio::ssl::context::pem, ec);
    if (ec) 
    {   
        Log("Error, loadKeyPairFile failed, ec:" << ec.message());
        return;
    }
}

void OpenSSLContext::loadKeyPair(span<u8> pk, span<u8> sk, error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    auto buf_pk = boost::asio::const_buffer(pk.data(), pk.size());
    m_boost_ctx->use_private_key(buf_pk, boost::asio::ssl::context::pem, ec);
    if (ec) return;
    auto buf_sk = boost::asio::const_buffer(sk.data(), sk.size());
    m_boost_ctx->use_certificate_chain(buf_sk, ec);
}

void OpenSSLContext::setSNIName(const std::string& sni_name, error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    m_sni_name = sni_name;
}

void OpenSSLContext::NoneVerify() {
    if (isInit() == false)
    {
        return;
    }
    m_boost_ctx->set_verify_mode(boost::asio::ssl::verify_none);
}

void OpenSSLContext::requestClientCert(error_code& ec) {
    if (isInit() == false)
    {
        ec = make_error_code(TLS_errc::ContextNotInit);
        return;
    }
    m_boost_ctx->set_verify_mode(boost::asio::ssl::verify_peer);
}

} // namespace osuCrypto
#endif
