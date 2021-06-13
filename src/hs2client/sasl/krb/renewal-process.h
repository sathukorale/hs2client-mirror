#pragma once

#include <string>
#include <thread>
#include <mutex>
#include <boost/optional.hpp>

#include "hs2client/status.h"
#include "hs2client/sasl/krb/kinit-context.h"

namespace hs2client 
{
    namespace krb
    {
        class RenewalProcess
        {
			private:
				class IAuthenticationDetails { };
				RenewalProcess() { }

			public:
				RenewalProcess(const RenewalProcess& obj)
				{
					throw std::runtime_error("Invalid operation. Unacceptable operation to copy instance of Renewal Process");
				}

				RenewalProcess& operator=(const RenewalProcess& other)
				{
					throw std::runtime_error("Invalid operation. Unacceptable operation to copy instance of Renewal Process");
				}

            private:
                static std::string kKrb5CCName;
                static RenewalProcess _instance;

				std::mutex _instant_lock = {};
                boost::shared_ptr<KinitContext> _kinit_ctx = nullptr;
                boost::shared_ptr<std::thread> _renewal_thread = nullptr;

				boost::shared_ptr<hs2client::krb::AuthenticationDetails> _authentiation_details = nullptr;

                hs2client::Status InitKerberos(const std::string& krb5ccname = kKrb5CCName, bool disable_krb5_replay_cache = true);
                void RenewalThread();

                boost::optional<std::string> GetLoggedInPrincipalFromKeytab();
				boost::optional<std::string> GetLoggedInUsernameFromKeytab();

				hs2client::Status GetHostname(std::string* hostname);
				hs2client::Status GetFQDN(std::string* hostname);
				hs2client::Status GetAddrInfo(const std::string& hostname, const addrinfo& hints, const std::string& op_description, AddrInfo* info);

				hs2client::Status GetConfiguredPrincipal(const std::string& in_principal, std::string& out_principal);

            public:
                static RenewalProcess& get_instance() { return _instance; }
				
				bool is_active() 
				{
					std::lock_guard<std::mutex> guard(_instant_lock);
					return _renewal_thread != nullptr;
				}

				std::mutex& get_lock()
				{
					return _instant_lock;
				}

				/* At the moment we only support a single set of details (key-tab + principal) */
				void start(const std::string& raw_principal, boost::shared_ptr<hs2client::krb::AuthenticationDetails> auth_details, const std::string& krb5ccname = kKrb5CCName, bool disable_krb5_replay_cache = true);
				void start_with_password_based_authentication(const std::string& raw_principal, const std::string& keytab_file, const std::string& krb5ccname = kKrb5CCName, bool disable_krb5_replay_cache = true);
				void start_with_keytab_based_authentication(const std::string& keytab_location, const std::string& password, const std::string& krb5ccname = kKrb5CCName, bool disable_krb5_replay_cache = true);
        };
    }
}