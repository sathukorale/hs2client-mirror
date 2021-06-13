// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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

#include <boost/shared_ptr.hpp>
#include <boost/optional/optional.hpp>
#include <gflags/gflags.h>
#include <krb5/krb5.h>

#include "hs2client/sasl/krb/status.h"
#include "hs2client/logging.h"
#include "hs2client/sasl/krb/kinit-context.h"
#include "hs2client/sasl/krb/renewal-process.h"

static constexpr bool kDefaultSystemAuthToLocal = true;
static constexpr bool use_system_auth_to_local = kDefaultSystemAuthToLocal;

using std::mt19937;
using std::random_device;
using std::string;
using std::uniform_int_distribution;
using std::uniform_real_distribution;

using namespace std;
using namespace hs2client;

#define KRB5_RETURN_NOT_OK_PREPEND(call, prepend) \
        RETURN_NOT_OK_PREPEND(hs2client::krb::KinitContext::Krb5CallToStatus(_krb5_ctx, (call)), (prepend))

hs2client::krb::KinitContext::KinitContext() {}

hs2client::krb::KinitContext::~KinitContext()
{
  // Free memory associated with these objects.
  if (principal_ != nullptr) krb5_free_principal(_krb5_ctx, principal_);
  if (_authentication_details != nullptr) _authentication_details->cleanup(_krb5_ctx);//krb5_kt_close(_krb5_ctx, keytab_);
  if (ccache_ != nullptr) krb5_cc_close(_krb5_ctx, ccache_);
  if (opts_ != nullptr) krb5_get_init_creds_opt_free(_krb5_ctx, opts_);
}

int32_t hs2client::krb::KinitContext::GetNextRenewInterval(uint32_t num_retries)
{
  int32_t halfway_time = ticket_start_timestamp_ + ((ticket_end_timestamp_ - ticket_start_timestamp_) / 2);
  int32_t current_time = time(nullptr);

  if (current_time < halfway_time) 
	  return (halfway_time - current_time);

  int32_t time_remaining = ticket_end_timestamp_ - current_time;

  // If the last ticket reacqusition was a failure, we back off our retry attempts exponentially.
  if (num_retries > 0) return GetBackedOffRenewInterval(time_remaining, num_retries);

  // If the time remaining between now and ticket expiry is:
  // * > 10 minutes:   We attempt to reacquire the ticket between 5 seconds and 5 minutes before the
  //                   ticket expires.
  // * 5 - 10 minutes: We attempt to reacquire the ticket between 5 seconds and 1 minute before the
  //                   ticket expires.
  // * < 5 minutes:    Attempt to reacquire the ticket every 'time_remaining'.
  //                   ^ The above is corrected by the first check as this would lead to
  //                     connection failures depending on who grabs the lock first, because 
  //                     this is renewing (actually recreating) after the ticket expiry.
  // The jitter is added to make sure that every server doesn't flood the KDC at the same time.
  random_device rd;
  mt19937 generator(rd());
  
  if (time_remaining > 600) 
  {
    uniform_int_distribution<> dist(5, 300);
    return time_remaining - dist(generator);
  }
  else if (time_remaining > 300)
  {
    uniform_int_distribution<> dist(5, 60);
    return time_remaining - dist(generator);
  }

  return time_remaining;
}

int32_t hs2client::krb::KinitContext::GetBackedOffRenewInterval(int32_t time_remaining, uint32_t num_retries)
{
  // The minimum sleep interval after a failure will be 60 seconds.
  int32_t next_interval = std::max(time_remaining, 60);
  // Don't back off more than 30 minutes.
  int32_t base_time = std::min(next_interval * (1 << num_retries), 1800);
  random_device rd;
  mt19937 generator(rd());
  uniform_real_distribution<> dist(0.5, 1.5);
  return static_cast<int32_t>(base_time * dist(generator));
}

hs2client::Status hs2client::krb::KinitContext::DoRenewal() 
{
  bool found_in_cache;
  RETURN_NOT_OK(DoRenewalInternal(&found_in_cache));

  if (!found_in_cache) 
  {
    RETURN_NOT_OK_PREPEND(KinitInternal(), "redoing kinit after error");
    RETURN_NOT_OK(DoRenewalInternal(&found_in_cache));

    if (!found_in_cache) return Status::RuntimeError("Could not find TGT in cache after kinit");
  }

  return Status::OK();
}

Status hs2client::krb::KinitContext::DoRenewalInternal(bool* found_in_cache) 
{
  *found_in_cache = false;
  krb5_cc_cursor cursor;
  // Setup a cursor to iterate through the credential cache.
  Status status = Krb5CallToStatus(_krb5_ctx, krb5_cc_start_seq_get(_krb5_ctx, ccache_, &cursor));
  if (!status.ok()) {
    LOG(WARNING) << "Error while opening credential cache '" << krb5_cc_get_name(_krb5_ctx, ccache_) << "' of type " << krb5_cc_get_type(_krb5_ctx, ccache_) << ": " << status.GetMessage();
    return Status::OK();
  }

  SCOPED_CLEANUP({ krb5_cc_end_seq_get(_krb5_ctx, ccache_, &cursor); });

  krb5_creds creds;
  memset(&creds, 0, sizeof(krb5_creds));

  krb5_error_code rc;
  // Iterate through the credential cache.
  while (!(rc = krb5_cc_next_cred(_krb5_ctx, ccache_, &cursor, &creds))) 
  {
    SCOPED_CLEANUP({ krb5_free_cred_contents(_krb5_ctx, &creds); });

    if (krb5_is_config_principal(_krb5_ctx, creds.server)) continue;

    // We only want to reacquire the TGT (Ticket Granting Ticket). Ignore all other tickets.
    // This follows the same format as is_local_tgt() from krb5:src/clients/klist/klist.c
    if (creds.server->length != 2 ||
        data_eq(creds.server->data[1], principal_->realm) == 0 ||
        data_eq_string(creds.server->data[0], KRB5_TGS_NAME) == 0 ||
        data_eq(creds.server->realm, principal_->realm) == 0) {
      continue;
    }
    *found_in_cache = true;

    krb5_creds new_creds;
    memset(&new_creds, 0, sizeof(krb5_creds));
    SCOPED_CLEANUP({ krb5_free_cred_contents(_krb5_ctx, &new_creds); });
    // Acquire a new ticket using the keytab. This ticket will automatically be put into the
    // credential cache.
    {
      std::lock_guard<std::mutex> l(_kerberos_reinit_lock);
	  RETURN_NOT_OK_PREPEND(_authentication_details->kinit(_krb5_ctx, new_creds, principal_, nullptr, opts_), "Reacquire error: see previous details");
#if !defined(HAVE_KRB5_GET_INIT_CREDS_OPT_SET_OUT_CCACHE)
      // Heimdal krb5 doesn't have the 'krb5_get_init_creds_opt_set_out_ccache' option,
      // so use this alternate route.
      KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_initialize(_krb5_ctx, ccache_, principal_), "Reacquire error: could not init ccache");
      KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_store_cred(_krb5_ctx, ccache_, &new_creds), "Reacquire error: could not store creds in cache");
#endif
	}
	LOG(INFO) << "Successfully reacquired a new kerberos TGT (ExpiryTime='" << new_creds.times.endtime << "')";
	ticket_start_timestamp_ = new_creds.times.starttime;
	ticket_end_timestamp_ = new_creds.times.endtime;
    break;
  }

  if (! *found_in_cache)
    LOG(WARNING) << "Could not find kerberos principal in credential cache '" << krb5_cc_get_name(_krb5_ctx, ccache_) << "' of type " << krb5_cc_get_type(_krb5_ctx, ccache_);

  return Status::OK();
}

Status hs2client::krb::KinitContext::Kinit(boost::shared_ptr<hs2client::krb::AuthenticationDetails> authentication_details) 
{
	_authentication_details = authentication_details;

	InitKrb5Ctx();

	KRB5_RETURN_NOT_OK_PREPEND(krb5_parse_name(_krb5_ctx, _authentication_details->get_principal().c_str(), &principal_), "could not parse principal");

	// TODO: Have to check whether setenv should happen before InitKrb5Ctx
	RETURN_NOT_OK_PREPEND(_authentication_details->pre_kinit(_krb5_ctx), "failed to prepare authentication details. please see previous errors.");
	KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_default(_krb5_ctx, &ccache_), "unable to get default credentials cache");
	KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_opt_alloc(_krb5_ctx, &opts_), "unable to allocate get_init_creds_opt struct");

	return KinitInternal();
}

Status hs2client::krb::KinitContext::MapPrincipalToLocalName(const std::string& principal, std::string* local_name) 
{
    InitKrb5Ctx();
    krb5_principal princ;

    KRB5_RETURN_NOT_OK_PREPEND(krb5_parse_name(_krb5_ctx, principal.c_str(), &princ), "could not parse principal");
    SCOPED_CLEANUP({ krb5_free_principal(_krb5_ctx, princ); });

    char buf[1024];
    krb5_error_code rc = KRB5_LNAME_NOTRANS;
    if (use_system_auth_to_local)
        rc = krb5_aname_to_localname(_krb5_ctx, princ, arraysize(buf), buf);

    if (rc == KRB5_LNAME_NOTRANS || rc == KRB5_PLUGIN_NO_HANDLE) 
    {
        if (princ->length > 0) 
        {
            local_name->assign(princ->data[0].data, princ->data[0].length);
            return Status::OK();
        }

        return Status::RuntimeError("unable to find first component of principal");
    }

    if (rc == KRB5_CONFIG_NOTENUFSPACE) 
        return Status::RuntimeError("mapped username too large");

    KRB5_RETURN_NOT_OK_PREPEND(rc, "krb5_aname_to_localname");
    if (strlen(buf) == 0)
        return Status::RuntimeError("principal mapped to empty username");

    local_name->assign(buf);
    return Status::OK();
}

Status hs2client::krb::KinitContext::KinitInternal() 
{
#if defined(HAVE_KRB5_GET_INIT_CREDS_OPT_SET_OUT_CCACHE)
  KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_opt_set_out_ccache(_krb5_ctx, opts_, ccache_),
                             "unable to set init_creds options");
#endif

  krb5_creds creds;
  //KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_keytab(_krb5_ctx, &creds, principal_, keytab_, 0 /* valid from now */, nullptr /* TKT service name */, opts_), "unable to login from keytab");
  RETURN_NOT_OK_PREPEND(_authentication_details->kinit(_krb5_ctx, creds, principal_, nullptr, opts_), "see previous details");
  SCOPED_CLEANUP({ krb5_free_cred_contents(_krb5_ctx, &creds); });

  ticket_start_timestamp_ = creds.times.starttime;
  ticket_end_timestamp_ = creds.times.endtime;

#if !defined(HAVE_KRB5_GET_INIT_CREDS_OPT_SET_OUT_CCACHE)
  // Heimdal krb5 doesn't have the 'krb5_get_init_creds_opt_set_out_ccache' option,
  // so use this alternate route.
  KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_initialize(_krb5_ctx, ccache_, principal_), "could not init ccache");
  KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_store_cred(_krb5_ctx, ccache_, &creds), "could not store creds in cache");
#endif

  // Convert the logged-in principal back to a string. This may be different than
  // 'principal', since the default realm will be filled in based on the Kerberos
  // configuration if not originally specified.
  RETURN_NOT_OK_PREPEND(Krb5UnparseName(principal_, &principal_str_),  "could not stringify the logged-in principal");
  RETURN_NOT_OK_PREPEND(MapPrincipalToLocalName(principal_str_, &username_str_), "could not map own logged-in principal to a short username");

  auto auth_details = _authentication_details.get();
  if (dynamic_cast<hs2client::krb::PasswordAuthenticationDetails*>(auth_details) != nullptr)
  {
	  LOG(INFO) << "Logged in from password as " << principal_str_ << " (short username " << username_str_ << ")";
  }
  else if (dynamic_cast<hs2client::krb::KeytabAuthenticationDetails*>(auth_details) != nullptr)
  {
	  LOG(INFO) << "Logged in from key-tab as " << principal_str_ << " (short username " << username_str_ << ")";
  }
  else
  {
	  LOG(WARNING) << "Application in incorrect state. Invalid authentication handler. Logged in as " << principal_str_ << " (short username " << username_str_ << ")";
  }

  return Status::OK();
}

Status hs2client::krb::KinitContext::Krb5CallToStatus(krb5_context ctx, krb5_error_code code) 
{
  if (code == 0) return Status::OK();

  const char* error_msg = krb5_get_error_message(ctx, code);
  std::unique_ptr<const char, std::function<void(const char*)>> err_msg(error_msg, std::bind(krb5_free_error_message, ctx, std::placeholders::_1));

  return Status::RuntimeError(err_msg.get());
}

void hs2client::krb::KinitContext::InitKrb5Ctx() 
{
  static std::once_flag once;
  std::call_once(once, [&]() 
  {
    DCHECK_EQ(krb5_init_context(&_krb5_ctx), 0);
    // Work around the lack of thread safety in krb5_parse_name() by implicitly
    // initializing _krb5_ctx->default_realm once. The assumption is that this
    // function is called once in a single thread environment during initialization.
    //
    // TODO(KUDU-2706): Fix unsafe sharing of '_krb5_ctx'.
    // According to Kerberos documentation
    // (https://github.com/krb5/krb5/blob/master/doc/threads.txt), any use of
    // krb5_context must be confined to one thread at a time by the application code.
    // The current way of sharing of '_krb5_ctx' between threads is actually unsafe.
    char* unused_realm;
    DCHECK_EQ(krb5_get_default_realm(_krb5_ctx, &unused_realm), 0);
    krb5_free_default_realm(_krb5_ctx, unused_realm);
  });
}

Status hs2client::krb::KinitContext::Krb5ParseName(const std::string& principal, std::string* service_name, std::string* hostname, std::string* realm)
{
	krb5_principal princ;
	KRB5_RETURN_NOT_OK_PREPEND(krb5_parse_name(_krb5_ctx, principal.c_str(), &princ), "could not parse principal");

	SCOPED_CLEANUP({ krb5_free_principal(_krb5_ctx, princ); });

	if (princ->length != 2)
	{
		std::stringstream str;
		str << principal << ": principal should include service name, hostname and realm";

		return Status::Error(str.str());
	}

	realm->assign(princ->realm.data, princ->realm.length);
	service_name->assign(princ->data[0].data, princ->data[0].length);
	hostname->assign(princ->data[1].data, princ->data[1].length);
	return Status::OK();
}

Status hs2client::krb::KinitContext::Krb5UnparseName(krb5_principal princ, string* name) 
{
  char* c_name;
  KRB5_RETURN_NOT_OK_PREPEND(krb5_unparse_name(_krb5_ctx, princ, &c_name), "krb5_unparse_name");
  SCOPED_CLEANUP({ krb5_free_unparsed_name(_krb5_ctx, c_name); });
  *name = c_name;
  return Status::OK();
}

Status hs2client::krb::KinitContext::CanonicalizeKrb5Principal(std::string* principal) 
{
  InitKrb5Ctx();
  krb5_principal princ;

  KRB5_RETURN_NOT_OK_PREPEND(krb5_parse_name(_krb5_ctx, principal->c_str(), &princ), "could not parse principal");

  SCOPED_CLEANUP({ krb5_free_principal(_krb5_ctx, princ); });

  RETURN_NOT_OK_PREPEND(Krb5UnparseName(princ, principal), "failed to convert principal back to string");

  return Status::OK();
}