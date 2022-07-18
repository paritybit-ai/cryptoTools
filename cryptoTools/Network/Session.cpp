#include <cryptoTools/Common/config.h>
#ifdef ENABLE_BOOST

#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <boost/lexical_cast.hpp>
#include <map>

#include <sstream>
#include <random>
#include "log.h"

bool USE_PORT_MAPPING = true;

namespace osuCrypto {
    void SetPortMapping(bool is_open) {
        USE_PORT_MAPPING = is_open;
    }

    class SessionMapping {
    public:
        SessionMapping(SessionMode type) : type_(type) {
            if (SessionMode::Client == type_) {
                type_str_ = "client";
            } else {
                type_str_ = "server";
            }
        }
        std::shared_ptr<Session> GetRealSession(const Session& s);
        bool AddRealSession(const std::string& ip,
                            u32 port,
                            std::shared_ptr<Session> session);
        bool AddVirToRealSessionMapping(
                                    const std::string& vir_ip,
                                    u32 vir_port,
                                    const std::string& real_ip,
                                    u32 real_port);
        void Stop();
        void Stop(const std::string& ip, u32 port);
    private:
        std::string GenKey(const std::string& ip, u32 port) {
            return ip + ":" + std::to_string(port);
        }
    private:
        // 存储虚拟端口到真实session的映射
        std::map<std::string, std::shared_ptr<Session>> vir_to_real_session_;
        // 存储real session映射了哪些vir_session，方便删除
        std::map<std::string, std::vector<std::string>> real_to_vir_session_;
        // 一对一映射，方便通过ip:port查找真实session;
        std::map<std::string, std::shared_ptr<Session>> real_session_;

        std::mutex mutex_;
        const SessionMode type_;
        std::string type_str_;
    };
	//extern std::vector<std::string> split(const std::string &s, char delim);
    static SessionMapping g_client_mapping(SessionMode::Client);
    static SessionMapping g_server_mapping(SessionMode::Server);

    std::shared_ptr<Session> SessionMapping::GetRealSession(const Session& s) {
        u32 port = s.port_;
        std::string ip = s.remote_ip_;
        std::lock_guard<std::mutex> guard(mutex_);
        if (vir_to_real_session_.size() == 1) {
            auto iter = vir_to_real_session_.begin();
            return iter->second;
        }
        auto key = GenKey(ip, port);
        auto iter = vir_to_real_session_.find(key);
        if (iter == vir_to_real_session_.end()) {
            Log("Can not get " << type_str_ << " real session, mapping not exist"
                << ", vir_ip:" << ip
                << ", vir_port:" << port);
            return nullptr;
        }
        return iter->second;
    }
    bool SessionMapping::AddRealSession(const std::string& ip,
                        u32 port,
                        std::shared_ptr<Session> session) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key = GenKey(ip, port);
        real_session_.emplace(key, session);
        return true;
    }
    bool SessionMapping::AddVirToRealSessionMapping(
                                    const std::string& vir_ip,
                                    u32 vir_port,
                                    const std::string& real_ip,
                                    u32 real_port) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto real_key = GenKey(real_ip, real_port);
        auto real_iter = real_session_.find(real_key);
        if (real_iter == real_session_.end()) {
            Log("Can not add " << type_str_ << " session map, real session not exist"
                << ", vir_ip:" << vir_ip
                << ", vir_port:" << vir_port
                << ", real_ip:" << real_ip
                << ", real_port:" << real_port);
            return false;
        }
        auto vir_key = GenKey(vir_ip, vir_port);
        if (vir_to_real_session_.find(vir_key) != vir_to_real_session_.end()) {
            Log("Can not " << type_str_ << " add session map, map already exist"
                << ", vir_ip:" << vir_ip
                << ", vir_port:" << vir_port
                << ", real_ip:" << real_ip
                << ", real_port:" << real_port);
            return false;
        }
        vir_to_real_session_.emplace(vir_key, real_iter->second);
        Log("Add " << type_str_ << " virtual to real session mapping, "
            << ", vir_ip:" << vir_ip
            << ", vir_port:" << vir_port
            << ", real_ip:" << real_ip
            << ", real_port:" << real_port);
        auto& vir_vec = real_to_vir_session_[real_key];
        vir_vec.push_back(vir_key);
        return true;
    }
    void SessionMapping::Stop() {
        std::lock_guard<std::mutex> guard(mutex_);
        vir_to_real_session_.clear();
        real_to_vir_session_.clear();
        for (auto& item : real_session_) {
            item.second->stop();
        }
        real_session_.clear();
    }
    void SessionMapping::Stop(const std::string& ip, u32 port) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto real_key = GenKey(ip, port);
        auto vir_vec_iter = real_to_vir_session_.find(real_key);
        if (vir_vec_iter == real_to_vir_session_.end()) {
            Log("No real session to vir session map!");
            return;
        }
        for (auto& vir_key : vir_vec_iter->second) {
            auto iter = vir_to_real_session_.find(vir_key);
            if (iter == vir_to_real_session_.end()) {
                continue;
            }
            vir_to_real_session_.erase(iter);
        }
        real_to_vir_session_.erase(vir_vec_iter);
        auto real_iter = real_session_.find(real_key);
        if (real_iter == real_session_.end()) {
            Log("Stop error, real session not exist"
                << ", real_ip:" << ip
                << ", real_port:" << port);
            return;
        }
        real_iter->second->stop();
        real_session_.erase(real_iter);
    }
    
    // virtual session mapping a real session by virtual session's port
    // std::shared_ptr<Session> GetRealSession(SessionMode type, u32 port) {
    std::shared_ptr<Session> GetRealSession(const Session& s) {
        SessionMode type = s.type_;
        if (type == SessionMode::Client) {
            return g_client_mapping.GetRealSession(s);
        }
        return g_server_mapping.GetRealSession(s);
    } 

    bool InitRealSession(IOService& ioService,
                          const std::string& remoteIP,
                          u32 port,
                          SessionMode type) {
        TLSContext tls;
        return InitRealSession(ioService, remoteIP, port, type, tls);
    }
    bool InitRealSession(IOService& ioService,
                          const std::string& remoteIP,
                          u32 port,
                          SessionMode type,
                          TLSContext& tls) {
        std::shared_ptr<Session> tmp = std::make_shared<Session>(ioService, remoteIP, port, type, tls, true);
        if (type == SessionMode::Client) {
            g_client_mapping.AddRealSession(remoteIP, port, tmp);
            // g_client_mapping.AddVirToRealSessionMapping(remoteIP, port, remoteIP, port);
        } else {
            g_server_mapping.AddRealSession(remoteIP, port, tmp);
            // g_server_mapping.AddVirToRealSessionMapping(remoteIP, port, remoteIP, port);
        }
        std::string type_str = type==SessionMode::Client?"client":"server";
        Log("Init " << type_str << " real session success, port:" << port);
        return true;
    }

    void StopSessions() {
        g_client_mapping.Stop();
        g_server_mapping.Stop();
        Log("StopSessions");
    }
    void StopSession(SessionMode type, const std::string& ip, u32 port) {
        if (type == SessionMode::Client) {
            g_client_mapping.Stop(ip, port);
        } else {
            g_server_mapping.Stop(ip, port);
        }
    }

    bool AddVirToRealSessionMapping(SessionMode type,
                                    const std::string& vir_ip,
                                    u32 vir_port,
                                    const std::string& real_ip,
                                    u32 real_port) {
        if (type == SessionMode::Client) {
            return g_client_mapping.AddVirToRealSessionMapping(vir_ip, vir_port, real_ip, real_port);
        }
        return g_server_mapping.AddVirToRealSessionMapping(vir_ip, vir_port, real_ip, real_port);
    }

	SessionBase::SessionBase(IOService& ios) 
		: mRealRefCount(1)
		, mWorker(ios, "Session:" + std::to_string((u64)this)) 
	{}

	void Session::start(IOService& ioService, std::string remoteIP, u32 port, SessionMode type, std::string name)
	{
        if (USE_PORT_MAPPING) {
            return;
        }
        TLSContext ctx;
        start(ioService, remoteIP, port, type, ctx, name);
	}

	void Session::start(IOService& ioService, std::string address, SessionMode host, std::string name)
	{
        if (USE_PORT_MAPPING) {
            return;
        }
		auto vec = split(address, ':');

		auto ip = vec[0];
		auto port = 1212;
		if (vec.size() > 1)
		{
			std::stringstream ss(vec[1]);
			ss >> port;
		}

		start(ioService, ip, port, host, name);

	}

    void Session::start(IOService& ioService, std::string ip, u64 port, SessionMode type, TLSContext& tls, std::string name)
    {
        if (mBase && mBase->mStopped == false)
            throw std::runtime_error("rt error at " LOCATION);
#if defined(ENABLE_WOLFSSL) || defined(ENABLE_BOOST_OPENSSL)
        if (tls && 
            (tls.mode() != TLSContext::Mode::Both) &&
            (tls.mode() == TLSContext::Mode::Server) != (type == SessionMode::Server))
            throw std::runtime_error("TLS context isServer does not match SessionMode");
#endif


        mBase.reset(new SessionBase(ioService));
        mBase->mIP = std::move(ip);
        mBase->mPort = static_cast<u32>(port);
        mBase->mMode = (type);
        mBase->mIOService = &(ioService);
        mBase->mStopped = (false);
        mBase->mTLSContext = tls;
        mBase->mName = (name);


        if (type == SessionMode::Server)
        {
            ioService.aquireAcceptor(mBase);
        }
        else
        {
			PRNG prng(ioService.getRandom(), sizeof(block) + sizeof(u64));
			mBase->mSessionID = 100000000; // prng.get();
            boost::asio::ip::tcp::resolver resolver(ioService.mIoService);
            boost::asio::ip::tcp::resolver::query query(mBase->mIP, boost::lexical_cast<std::string>(port));
            mBase->mRemoteAddr = *resolver.resolve(query);
            Log("To get client address");
        }
    }

	// See start(...)

	Session::Session(IOService & ioService, std::string address, SessionMode type, std::string name)
	{
        if (USE_PORT_MAPPING) {
            auto vec = split(address, ':');

            auto ip = vec[0];
            auto port = 1212;
            if (vec.size() > 1)
            {
                std::stringstream ss(vec[1]);
                ss >> port;
            }
            port_ = port;
            type_ = type;
            remote_ip_ = ip;
            return;
        }
		start(ioService, address, type, name);
	}

	// See start(...)

	Session::Session(IOService & ioService, std::string remoteIP, u32 port, SessionMode type, std::string name)
	{
        if (USE_PORT_MAPPING) {
            port_ = port;
            type_ = type;
            remote_ip_ = remoteIP;
            return;
        }
		start(ioService, remoteIP, port, type, name);
	}

    Session::Session(IOService& ioService, std::string remoteIP, u32 port
        , SessionMode type, TLSContext& ctx, std::string name)
    {
        if (USE_PORT_MAPPING) {
            port_ = port;
            type_ = type;
            remote_ip_ = remoteIP;
            return;
        }
        start(ioService, remoteIP, port, type, ctx, name);
    }


	// Default constructor

	Session::Session()
	{ }

    // To construct real session;
    Session::Session(IOService & ioService, 
                     std::string remoteIP,
                     u32 port,
                     SessionMode type,
                     TLSContext& tls,
                     bool flage) {
        remote_ip_ = remoteIP;
        start(ioService, remoteIP, port, type, tls, "");
    }

	Session::Session(const Session & v)
		: mBase(v.mBase)
	{
        if (USE_PORT_MAPPING) {
            port_ = v.port_;
            type_ = v.type_;
            remote_ip_ = remote_ip_;
        }
        if(mBase)
		    ++mBase->mRealRefCount;
	}

	Session::Session(const std::shared_ptr<SessionBase>& c)
		: mBase(c)
	{
        ++mBase->mRealRefCount;
    }

	Session::~Session()
	{
        if (mBase)
        {
		    --mBase->mRealRefCount;
		    if (mBase->mRealRefCount == 0)
			    mBase->stop();
        }
	}

	std::string Session::getName() const
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return "";
            }
            return real_session->getName();
        }
		if (mBase)
			return mBase->mName;
		else
			throw std::runtime_error(LOCATION);
	}

	u64 Session::getSessionID() const
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return 0;
            }
            return real_session->getSessionID();
        }
		if (mBase)
			return mBase->mSessionID;
		else
			throw std::runtime_error(LOCATION);
	}

	IOService & Session::getIOService() {
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                throw std::runtime_error(LOCATION);
            }
            return real_session->getIOService();
        }
		if (mBase)
			return *mBase->mIOService;
		else
			throw std::runtime_error(LOCATION);
	}

    Channel Session::addChannel(u32 port, const std::string& localName, const std::string& remoteName) {
        std::string l_name = localName.empty() ? std::to_string(port) : localName;
        std::string r_name = remoteName.empty() ? std::to_string(port) : remoteName;
        return addChannel(l_name, r_name);
    }

	Channel Session::addChannel(std::string localName, std::string remoteName)
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                throw std::runtime_error(LOCATION);
            }
            return real_session->addChannel(port_, localName, remoteName);
        }
        Log("To add channel, localName:" << localName << ", remoteName:" << remoteName << ", real session ip:" << remote_ip_);
        if (mBase == nullptr)
            throw std::runtime_error("Session is not initialized");

		// if the user does not provide a local name, use the following.
		if (localName == "") {
			if (remoteName != "") throw std::runtime_error("remote name must be empty is local name is empty. " LOCATION);

			std::lock_guard<std::mutex> lock(mBase->mAddChannelMtx);
			localName = "_autoName_" + std::to_string(mBase->mAnonymousChannelIdx++);
		}


		// make the remote name match the local name if empty
		if (remoteName == "") remoteName = localName;

		if (mBase->mStopped == true) throw std::runtime_error("rt error at " LOCATION);


		// construct the basic channel. Has no socket.
		Channel chl(*this, localName, remoteName);
		return (chl);
	}


	void Session::stop()
	{
        if (USE_PORT_MAPPING) {
            return;
        }
		mBase->stop();
	}

	void SessionBase::stop()
	{
		if (mStopped == false)
		{
			mStopped = true;
			if (mAcceptor) {
                Log("To unsubscribe acceptor");
				mAcceptor->unsubscribe(this);
            }
			mWorker.reset();
		}
	}

	SessionBase::~SessionBase()
	{
		stop();
	}

	bool Session::stopped() const
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return true;
            }
            return real_session->stopped();
        }
		return mBase->mStopped;
	}

	u32 Session::port() const
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return 0;
            }
            return real_session->port();
        }
		return mBase->mPort;
	}
	std::string Session::IP() const
	{
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return "";
            }
            return real_session->IP();
        }
		return mBase->mIP;
	}
	bool Session::isHost() const {
        if (USE_PORT_MAPPING && port_ != 0) {
            auto real_session = GetRealSession(*this);
            if (!real_session) {
                // TODO: Log
                return true;
            }
            return real_session->isHost();
        }
        return mBase->mMode == SessionMode::Server;
    }

	//void SessionBase::cancelPendingConnection(ChannelBase * chl)
	//{
	//}

}
#endif
