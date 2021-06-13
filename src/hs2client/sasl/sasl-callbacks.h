/****************************************************************************
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************
 */

#pragma once

#include <vector>
#include <sasl/sasl.h>
#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>

#include "hs2client/sasl/thrift/TSasl.h"
#include "hs2client/sasl/krb/authentication-details.h"

namespace sasl
{
	struct CallbackWrapper;

	class GenericSaslCallbackHandler
	{
		friend struct CallbackWrapper;

		public:
			virtual ~GenericSaslCallbackHandler();
			sasl_callback_t* create_sasl_callback_handlers();

		private:
			int on_internal_handle(void* context, int id, const char** result, unsigned* len);
			int on_internal_handle_canon_user(sasl_conn_t* conn, void* context, const char* in, unsigned inlen, unsigned flags, const char* user_realm, char* out, unsigned out_max, unsigned* out_len);

		protected:
			virtual void setup_callbacks() = 0;
			virtual int on_handle(void* context, int id, const char** result, unsigned int& len) { return SASL_FAIL; };
			virtual int on_handle_canon_user(sasl_conn_t& conn, void* context, const char* in, unsigned inlen, unsigned flags, const char* user_realm, char* out, unsigned out_max, unsigned int& out_len) { return SASL_FAIL; }

			void register_available_parameter_id(int sasl_parameter_id, void* context_data = nullptr);

			std::vector<sasl_callback_t>* _callbacks = new std::vector<sasl_callback_t>();
	};

	class SimpleSaslCallbackHandler : public GenericSaslCallbackHandler
	{
		public:
			SimpleSaslCallbackHandler(const std::string& username, const std::string& password);

		protected:
			void setup_callbacks() override;

			const std::string& get_usename() const { return _username; }
			const std::string& get_secret() const { return _password; }

		private:
			int on_handle(void* context, int id, const char** result, unsigned int& len) override;

			std::string _username;
			std::string _password;
	};

	class GssapiSaslCallbackHandler : public GenericSaslCallbackHandler
	{
		public:
			GssapiSaslCallbackHandler(const std::string& kerberos_realm,
									  const std::string& kerberos_fully_qualified_domain_name,
									  boost::shared_ptr<hs2client::krb::AuthenticationDetails> authentication_details,
									  const std::string& kerberos_service_name = "impala");

		protected:
			void setup_callbacks() override;

		private:
			int on_handle(void* context, int id, const char** result, unsigned int& len) override;
			int on_handle_canon_user(sasl_conn_t& conn, void* context, const char* in, unsigned inlen, unsigned flags, const char* user_realm, char* out, unsigned out_max, unsigned int& out_len) override;

			std::string _kerberos_realm = "";
			std::string _kerberos_fully_qualified_domain_name = "";
			std::string _kerberos_service_name = "";
			std::string _kerberos_username = "";

			std::string _kerberos_principal = "";

			boost::shared_ptr<hs2client::krb::AuthenticationDetails> _authentication_details;
	};

	struct CallbackWrapper
	{			
		private:
			GenericSaslCallbackHandler* _callback_handler;
			void* _context_data;

		public:
			CallbackWrapper(GenericSaslCallbackHandler* callback_handler, void* context_data) :
			_callback_handler(callback_handler),
			_context_data(context_data)
			{
			}

			inline int on_handle(int id, const char** result, unsigned* len)
			{
				return _callback_handler->on_internal_handle(_context_data, id, result, len);
			}

			inline int on_handle_canon_user(sasl_conn_t* conn, void* context, 
											const char* in, unsigned inlen, 
											unsigned flags, const char* user_realm, 
											char* out, unsigned out_max, 
											unsigned* out_len)
			{
				return _callback_handler->on_internal_handle_canon_user(conn, context, in, inlen, flags, user_realm, out, out_max, out_len);
			}
	};
}
