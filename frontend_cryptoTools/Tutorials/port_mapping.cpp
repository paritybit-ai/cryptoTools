#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include "flage_parser.h"

#include <atomic>
#include <vector>
#include <string>

DECLEAR_i32(client_tcp_port);
DECLEAR_str(client_tcp_address);
DECLEAR_str(ca_path);

DECLEAR_str(test_mode);
DECLEAR_i32(thread_num);
DECLEAR_i32(pkg_size);
DECLEAR_boo(use_ssl);
DEFINE_i32(client_tcp_port2, 8088);

#ifdef ENABLE_WOLFSSL
namespace port_mapping {
using namespace osuCrypto;
#define Log(s) std::cout << __FILE__ << ":" << __LINE__ << " " << s << std::endl;

class Test {
public:
    Test(const std::string& role, bool has_ssl, int thread_num)
        : thread_num_(thread_num), role_(role) {
        ios_.reset(new IOService(4));
        ios_->showErrorMessages(true);
        auto ip = flage_client_tcp_address;
        ip_ = ip;
        auto port = flage_client_tcp_port;

        SessionMode type;
        TLSContext::Mode tls_mode;

        if (role == "client") {
            type = SessionMode::Client;
            tls_mode = TLSContext::Mode::Client;
        } else {
            type = SessionMode::Server;
            tls_mode = TLSContext::Mode::Server;
        }

        has_ssl_ = has_ssl;
        type_ = type;
        tls_mode_ = tls_mode;
        error_code ec;
        if (has_ssl) {
            TLSContext ctx;
            ctx.init(tls_mode, ec);
            if (ec) {Log("error:" + ec.message());}
            ctx.loadCertFile(flage_ca_path, ec);
            if (ec) {Log("error:" + ec.message());}
            ctx.loadKeyPairFile("/export/certs/server-cert.pem", "/export/certs/server-key.pem", ec);
            if (ec) {Log("error:" + ec.message());}
            std::string sni_name = "tcp.owl.basebit.me";
            ctx.setSNIName(sni_name, ec);
            if (ec) {Log("error:" + ec.message());}
            InitRealSession(*ios_, ip, port, type, ctx);
            Log("Init ssl session");
        } else {
            InitRealSession(*ios_, ip, port, type);
            Log("Init normal session");
        }
        AddVirToRealSessionMapping(type, ip, port, ip, port);
    }
    void Run() {
        if (thread_num_ <= 0) {
            Log("error: wrong thread number, number:" << thread_num_);
            return;
        }
        static std::string pre_name = "ch_";
        for (int i = 0; i < thread_num_; i++) {
            if (role_ == "client") {
                // client端真正连接的端口和session使用的端口不一样，session使用的端口需要和server端一致
                ths_.emplace_back(&Test::Send, this, flage_client_tcp_port2 + i);
            } else {
                // server端真正监听的端口和session使用的端口一样
                ths_.emplace_back(&Test::Recv, this, flage_client_tcp_port + i);
            }
        }
        th1_ = std::thread(&Test::print, this);
        if (th1_.joinable()) {
            th1_.join();
        }
        for (auto& th : ths_) {
            if (th.joinable()) {
                th.join();
            }
        }
    }

    void Send(int port) {

        std::unique_ptr<Session> session;
        if (has_ssl_) {
            error_code ec;
            TLSContext ctx;
            ctx.init(tls_mode_, ec);
            ctx.loadCertFile(flage_ca_path, ec);
            ctx.loadKeyPairFile("/export/certs/server-cert.pem", "/export/certs/server-key.pem", ec);
            std::string sni_name = "tcp.owl.basebit.me";
            ctx.setSNIName(sni_name, ec);
            session.reset(new Session(*ios_, ip_, port, type_, ctx));
        } else {
            session.reset(new Session(*ios_, ip_, port, type_));
        }
        auto chl = session->addChannel();
        chl.waitForConnection();
        while (true) {
            std::string data(flage_pkg_size, 'c');
            chl.send(data);
            pkg_num_++;
        }
    }

    void Recv(int port) {
        std::unique_ptr<Session> session;
        if (has_ssl_) {
            TLSContext ctx;
            error_code ec;
            ctx.init(tls_mode_, ec);
            ctx.loadCertFile(flage_ca_path, ec);
            ctx.loadKeyPairFile("/export/certs/server-cert.pem", "/export/certs/server-key.pem", ec);
            std::string sni_name = "tcp.owl.basebit.me";
            ctx.setSNIName(sni_name, ec);
            session.reset(new Session(*ios_, ip_, port, type_, ctx));
            Log("virtula ssl session");
        } else {
            session.reset(new Session(*ios_, ip_, port, type_));
            Log("virtula session");
        }
        auto chl = session->addChannel();
        chl.waitForConnection();
        while (true) {
            std::string dest;
            chl.recv(dest);
            total_size_ += dest.size();
            pkg_num_++;
        }
    }
    void print() {
        while(true) {
            if (role_ != "client") {
                int64_t tmp = total_size_;
                total_size_ = 0;
                Log("recv data size:" << std::to_string(tmp));
            }

            int64_t t = pkg_num_;
            pkg_num_ = 0;
            Log(role_ << " packege number:" << std::to_string(t));
            if (role_ == "client" && t > 0) {
                int64_t time_us = 1000 * 1000;
                t = t / thread_num_;
                Log("every operation use time in us:" << (time_us / t));
            }

            sleep(1);
        }
    }
private:
    std::thread th1_;
    std::vector<std::thread> ths_;
    int thread_num_{0};
    std::string role_;
    std::string ip_;
    std::atomic<int64_t> total_size_{0};
    std::atomic<int64_t> pkg_num_{0};
    std::unique_ptr<IOService> ios_;
    std::unique_ptr<Session> session_;
    SessionMode type_;
    TLSContext::Mode tls_mode_;
    bool has_ssl_;
};

void client() {
    Test test("client", flage_use_ssl, flage_thread_num);
    test.Run();
}

void server() {
    Test test("server", flage_use_ssl, flage_thread_num);
    test.Run();
}
} // namespace port_mapping
#endif
