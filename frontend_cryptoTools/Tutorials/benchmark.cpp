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

DEFINE_str(test_mode, "send");
DEFINE_i32(thread_num, 1);
DEFINE_i32(pkg_size, 100);
DEFINE_boo(use_ssl, true);

#ifdef ENABLE_WOLFSSL
// 测试与网关通信性能；
namespace benchmark {
using namespace osuCrypto;
#define Log(s) std::cout << __FILE__ << ":" << __LINE__ << " " << s << std::endl;

class Test {
public:
    Test(const std::string& role, bool has_ssl, int thread_num) 
        : thread_num_(thread_num), role_(role) {
        ios_.reset(new IOService(4));
        ios_->showErrorMessages(true);
        auto ip = flage_client_tcp_address;
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
            session_.reset(new Session(*ios_, ip, port, type, ctx));
            Log("Init ssl session");
        } else {
            InitRealSession(*ios_, ip, port, type);
            session_.reset(new Session(*ios_, ip, port, type));
            Log("Init normal session");
        }
        AddVirToRealSessionMapping(type, ip, port, ip, port);
    }

    // client发送，server接收
    void Run() {
        if (thread_num_ <= 0) {
            Log("error: wrong thread number, number:" << thread_num_);
            return;
        }
        static std::string pre_name = "ch_";
        for (int i = 0; i < thread_num_; i++) {
            if (role_ == "client") {
                ths_.emplace_back(&Test::Send, this, pre_name + std::to_string(i));
            } else {
                ths_.emplace_back(&Test::Recv, this, pre_name + std::to_string(i));
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
    void Send(std::string name) {
        auto chl = session_->addChannel(name, name);
        chl.waitForConnection();
        while (true) {
            std::string data(flage_pkg_size, 'c');
            chl.send(data);
            pkg_num_++;
        }
    }
    void Recv(std::string name) {
        auto chl = session_->addChannel(name, name);
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
            if (role_ != "send") {
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

    // client发送并等待server响应，server接收并将原字符返回给client
    void Run2() {
        if (thread_num_ <= 0) {
            Log("error: wrong thread number, number:" << thread_num_);
            return;
        }
        static std::string pre_name = "ch_";
        for (int i = 0; i < thread_num_; i++) {
            if (role_ == "client") {
                ths_.emplace_back(&Test::SendAndRecv, this, pre_name + std::to_string(i));
            } else {
                ths_.emplace_back(&Test::RecvAndSend, this, pre_name + std::to_string(i));
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
    void SendAndRecv(std::string name) {
        auto chl = session_->addChannel(name, name);
        chl.waitForConnection();
        while (true) {
            std::string data(flage_pkg_size, 'c');
            chl.send(data);
            data.clear();
            chl.recv(data);
            pkg_num_++;
        }
    }
    void RecvAndSend(std::string name) {
        auto chl = session_->addChannel(name, name);
        chl.waitForConnection();
        while (true) {
            std::string dest;
            chl.recv(dest);
            chl.send(dest);
            total_size_ += dest.size();
            pkg_num_++;
        }
    }

private:
    std::thread th1_;
    std::vector<std::thread> ths_;
    int thread_num_{0};
    std::string role_;
    std::atomic<int64_t> total_size_{0};
    std::atomic<int64_t> pkg_num_{0};
    std::unique_ptr<IOService> ios_;
    std::unique_ptr<Session> session_;
};

void bench_client() {
    Test test("client", flage_use_ssl, flage_thread_num);
    if (flage_test_mode == "send_then_recv") {
        Log("run2");
        test.Run2();
    } else {
        Log("run");
        test.Run();
    }
    Log("End of client");
}

void bench_server() {
    Test test("server", flage_use_ssl, flage_thread_num);
    if (flage_test_mode == "send_then_recv") {
        test.Run2();
    } else {
        test.Run();
    }
}
} // namespace benchmark
#endif
