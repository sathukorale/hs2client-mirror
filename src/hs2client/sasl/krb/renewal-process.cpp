#include <iostream>
#include <stdio.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <ostream>
#include <random>
#include <string>
#include <type_traits>
#include <utility>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>

#include <gflags/gflags.h>
#include <krb5/krb5.h>
#include <boost/algorithm/string.hpp>

#include "hs2client/sasl/krb/status.h"
#include "hs2client/logging.h"
#include "hs2client/sasl/krb/kinit-context.h"
#include "hs2client/sasl/krb/renewal-process.h"

using namespace std;
using namespace hs2client;

std::string hs2client::krb::RenewalProcess::kKrb5CCName = "MEMORY:kudu";
hs2client::krb::RenewalProcess hs2client::krb::RenewalProcess::_instance;

boost::optional<std::string> hs2client::krb::RenewalProcess::GetLoggedInPrincipalFromKeytab() 
{
  if (!_kinit_ctx) return boost::none;
  return _kinit_ctx->principal_str();
}

boost::optional<std::string> hs2client::krb::RenewalProcess::GetLoggedInUsernameFromKeytab()
{
  if (!_kinit_ctx) return boost::none;
  return _kinit_ctx->username_str();
}

void hs2client::krb::RenewalProcess::RenewalThread()
{
    uint32_t failure_retries = 0;
    while (true)
    {
        int64_t renew_interval_s = _kinit_ctx->GetNextRenewInterval(failure_retries);
        if (failure_retries > 0)
            LOG(WARNING) << "Renew thread sleeping after " << failure_retries << " failures for " << renew_interval_s;

		std::this_thread::sleep_for(std::chrono::seconds(renew_interval_s));
		
		std::lock_guard<std::mutex> l(_instant_lock);
        Status s = _kinit_ctx->DoRenewal();
        if (! s.ok())
        {
			LOG(WARNING) << "Kerberos reacquire error. (Reason='" << s.GetMessage() << "')";
            ++failure_retries;
        }
        else
            failure_retries = 0;

        if (failure_retries > 5 /* should be made configurable*/)
        {
            std::stringstream str;
            str << "Kerberos reacquire error. (Reason='" << s.GetMessage() << "')";

            throw new std::runtime_error(str.str());
        }
    }
}

Status hs2client::krb::RenewalProcess::InitKerberos(const std::string& krb5ccname, bool disable_krb5_replay_cache) 
{
	if (!_authentiation_details)
		return Status::RuntimeError("Authentication details should be provided before starting renewal thread.");

    setenv("KRB5CCNAME", krb5ccname.c_str(), 1);

    if (disable_krb5_replay_cache) 
    {
        // KUDU-1897: disable the Kerberos replay cache. The KRPC protocol includes a
        // per-connection server-generated nonce to protect against replay attacks
        // when authenticating via Kerberos. The replay cache has many performance and
        // implementation issues.
        setenv("KRB5RCACHETYPE", "none", 1);
    }

    _kinit_ctx.reset(new KinitContext());
    std::string configured_principal;

    RETURN_NOT_OK(GetConfiguredPrincipal(_authentiation_details->get_principal(), configured_principal));
    RETURN_NOT_OK_PREPEND(_kinit_ctx->Kinit(_authentiation_details), "unable to kinit");

	_renewal_thread.reset(new std::thread(&hs2client::krb::RenewalProcess::RenewalThread, std::ref(*this)));
    return Status::OK();
}

Status hs2client::krb::RenewalProcess::GetConfiguredPrincipal(const std::string& in_principal, std::string& out_principal)
{
	out_principal = in_principal;
	const auto& kHostToken = "_HOST";

	if (in_principal.find(kHostToken) != string::npos) 
	{
		string hostname;
		// Try to fill in either the FQDN or hostname.
		if (!GetFQDN(&hostname).ok())
		{
			RETURN_NOT_OK(GetHostname(&hostname));
		}

		// Hosts in principal names are canonicalized to lower-case.
		std::transform(hostname.begin(), hostname.end(), hostname.begin(), [](unsigned char c) { return std::tolower(c); });
		boost::replace_all(out_principal, kHostToken, hostname);
	}

	return Status::OK();
}

Status hs2client::krb::RenewalProcess::GetHostname(string* hostname)
{
	char name[HOST_NAME_MAX];
	int ret = gethostname(name, HOST_NAME_MAX);
	if (ret != 0)
		return Status::RuntimeError("Unable to determine local hostname");

	*hostname = name;
	return Status::OK();
}

Status hs2client::krb::RenewalProcess::GetFQDN(string* hostname)
{
	// Start with the non-qualified hostname
	RETURN_NOT_OK(GetHostname(hostname));

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;

	std::stringstream str;
	str << "look up canonical hostname for localhost '" << *hostname << "'";

	AddrInfo result;
	const string op_description = str.str();
	RETURN_NOT_OK(GetAddrInfo(*hostname, hints, op_description, &result));

	*hostname = result->ai_canonname;
	return Status::OK();
}

Status hs2client::krb::RenewalProcess::GetAddrInfo(const string& hostname, const addrinfo& hints, const string& op_description, AddrInfo* info)
{
	// ThreadRestrictions::AssertWaitAllowed();
	addrinfo* res = nullptr;
	const int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
	// const int err = errno; // preserving the errno from the getaddrinfo() call
	AddrInfo result(res, ::freeaddrinfo);

	if (rc == 0) 
	{
		if (info != nullptr)
			info->swap(result);

		return Status::OK();
	}

	std::stringstream str;
	str << "unable to " << op_description;

	const string err_msg = str.str();
	/*if (rc == EAI_SYSTEM) {
	return Status::NetworkError(err_msg, ErrnoToString(err), err);
	}*/
	return Status::RuntimeError(err_msg);
}

void krb::RenewalProcess::start(const std::string& raw_principal, boost::shared_ptr<hs2client::krb::AuthenticationDetails> auth_details, const std::string& krb5ccname, bool disable_krb5_replay_cache /*= true*/)
{
	std::lock_guard<std::mutex> guard(_instant_lock);

	if (_renewal_thread != nullptr)
		return; // throw new std::runtime_error("The kerberos ticket renewal thread has already started.");

	_authentiation_details = auth_details;

	if (InitKerberos(krb5ccname, disable_krb5_replay_cache).ok() == false)
		throw new std::runtime_error("Failed to start Kerberos renewal thread.");
}

void krb::RenewalProcess::start_with_password_based_authentication(const std::string& raw_principal, const std::string& password, const std::string& krb5ccname, bool disable_krb5_replay_cache /*= true*/)
{
	auto auth_details = boost::shared_ptr<hs2client::krb::AuthenticationDetails>(new hs2client::krb::PasswordAuthenticationDetails(raw_principal, password));
	start(raw_principal, auth_details, krb5ccname, disable_krb5_replay_cache);
}

void krb::RenewalProcess::start_with_keytab_based_authentication(const std::string& raw_principal, const std::string& keytab_location, const std::string& krb5ccname, bool disable_krb5_replay_cache /*= true*/)
{
	auto auth_details = boost::shared_ptr<hs2client::krb::AuthenticationDetails>(new hs2client::krb::KeytabAuthenticationDetails(raw_principal, keytab_location));
	start(raw_principal, auth_details, krb5ccname, disable_krb5_replay_cache);
}