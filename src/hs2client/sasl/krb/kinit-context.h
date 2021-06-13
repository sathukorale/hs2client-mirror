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
#pragma once

#include <string.h>
#include <cstdint>
#include <string>
#include <mutex>

#include <krb5/krb5.h>
#include <netdb.h>
#include <netinet/in.h>
#include <boost/shared_ptr.hpp>

#include "hs2client/status.h"
#include "hs2client/sasl/krb/authentication-details.h"

namespace hs2client 
{
	namespace krb
	{
		using AddrInfo = std::unique_ptr<addrinfo, std::function<void(addrinfo*)>>;

		class KinitContext 
		{
			public:
				KinitContext();
				~KinitContext();

				Status Kinit(boost::shared_ptr<AuthenticationDetails> authentication_details);
				Status DoRenewal();

				int32_t GetNextRenewInterval(uint32_t num_retries);

				const std::string& principal_str() const { return principal_str_; }
				const std::string& username_str() const { return username_str_; }

				static int32_t GetBackedOffRenewInterval(int32_t time_remaining, uint32_t num_retries);
				static Status Krb5CallToStatus(krb5_context ctx, krb5_error_code code);

			private:
				krb5_context _krb5_ctx = {};
				krb5_principal principal_ = nullptr;
				krb5_ccache ccache_ = nullptr;
				krb5_get_init_creds_opt* opts_ = nullptr;

				boost::shared_ptr<AuthenticationDetails> _authentication_details = nullptr;

				std::mutex _kerberos_reinit_lock = {};

				// The stringified principal and username that we are logged in as.
				std::string principal_str_, username_str_;

				// This is the time that the current TGT in use expires.
				int32_t ticket_start_timestamp_;
				int32_t ticket_end_timestamp_;

				std::mutex& KerberosReinitLock() { return _kerberos_reinit_lock; }

				Status KinitInternal();

				Status DoRenewalInternal(bool* found_in_cache);
				Status MapPrincipalToLocalName(const std::string& principal, std::string* local_name);
				Status Krb5UnparseName(krb5_principal princ, std::string* name);
				Status Krb5ParseName(const std::string& principal, std::string* service_name, std::string* hostname, std::string* realm);
				Status CanonicalizeKrb5Principal(std::string* principal);

				void InitKrb5Ctx();

				inline static int data_eq(krb5_data d1, krb5_data d2)
				{
					return (d1.length == d2.length && !memcmp(d1.data, d2.data, d1.length));
				}

				inline static int data_eq_string(krb5_data d, const char *s)
				{
					return (d.length == strlen(s) && !memcmp(d.data, s, d.length));
				}
		};
	}
}