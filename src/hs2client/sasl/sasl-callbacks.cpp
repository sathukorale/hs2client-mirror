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
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>

#include "hs2client/sasl/sasl-callbacks.h"

int passthrough_handler(void* context, int id, const char** result, unsigned* len)
{
	sasl::CallbackWrapper* callback_wrapper = static_cast<sasl::CallbackWrapper*>(context);
	if (callback_wrapper == NULL)
		return SASL_BADPARAM;

	return callback_wrapper->on_handle(id, result, len);
}

int passthrough_handler_on_canon_user(sasl_conn_t* conn, void* context, 
                                      const char* in, unsigned inlen, 
									  unsigned flags, const char* user_realm, 
									  char* out, unsigned out_max, 
									  unsigned* out_len)
{
	sasl::CallbackWrapper* callback_wrapper = static_cast<sasl::CallbackWrapper*>(context);
	if (callback_wrapper == NULL)
		return SASL_FAIL;

	return callback_wrapper->on_handle_canon_user(conn, context, in, inlen, flags, user_realm, out, out_max, out_len);
}

sasl::GenericSaslCallbackHandler::~GenericSaslCallbackHandler()
{
	for (sasl_callback_t& callback : *_callbacks)
	{
		delete static_cast<CallbackWrapper*>(callback.context);
		callback.context = nullptr;
	}
}

sasl_callback_t* sasl::GenericSaslCallbackHandler::create_sasl_callback_handlers()
{
	setup_callbacks();
	register_available_parameter_id(SASL_CB_LIST_END);

	return &(*_callbacks)[0];
}

int sasl::GenericSaslCallbackHandler::on_internal_handle(void* context, int id, const char** result, unsigned* len)
{
	uint32_t invalid = static_cast<uint32_t>(-1);
	uint32_t length = invalid;
	int return_code = on_handle(context, id, result, length);

	if (len && length != invalid) *len = length;
	return return_code;
}

int sasl::GenericSaslCallbackHandler::on_internal_handle_canon_user(sasl_conn_t* conn, void* context, const char* in, unsigned inlen, unsigned flags, const char* user_realm, char* out, unsigned out_max, unsigned* out_len)
{
	uint32_t invalid = static_cast<uint32_t>(-1);
	uint32_t length = invalid;
	int return_code = on_handle_canon_user(*conn, context, in, inlen, flags, user_realm, out, out_max, length);

	if (out_len && length != invalid) *out_len = length;
	return return_code;
}

void sasl::GenericSaslCallbackHandler::register_available_parameter_id(int sasl_parameter_id, void* context_data /*= nullptr*/)
{
	sasl_callback_t callback { 0, (sasl_callback_ft)NULL, NULL };

	callback.id = sasl_parameter_id;

	if (sasl_parameter_id != SASL_CB_LIST_END)
	{
		if (sasl_parameter_id == SASL_CB_CANON_USER)
			callback.proc = (sasl_callback_ft)&passthrough_handler_on_canon_user;
		else
			callback.proc = (sasl_callback_ft)&passthrough_handler;

		callback.context = new CallbackWrapper(this, context_data);
	}

	_callbacks->push_back(callback);
}

sasl::SimpleSaslCallbackHandler::SimpleSaslCallbackHandler(const std::string& username, const std::string& password) :
_username(username),
_password(password)
{
	if (username.empty() || password.empty())
		throw new std::runtime_error("The username and password parameters cannot be empty.");
}

void sasl::SimpleSaslCallbackHandler::setup_callbacks()
{
	/*TODO: Have to check whether sasl_getsimple_t matters here */
	register_available_parameter_id(SASL_CB_USER);
	register_available_parameter_id(SASL_CB_PASS);
}

int sasl::SimpleSaslCallbackHandler::on_handle(void* context, int id, const char** result, unsigned int& len)
{
	if (!result)
		return SASL_BADPARAM;

	switch (id)
	{
		case SASL_CB_USER:
		{
			*result = _username.c_str();
			len = _username.length();
		}
		break;

		case SASL_CB_PASS:
		{
			const std::string& password = get_secret();
			*result = password.c_str();
			len = password.length();
		}
		break;

		default:
			return SASL_BADPARAM;
	}

	return SASL_OK;
}

sasl::GssapiSaslCallbackHandler::GssapiSaslCallbackHandler(const std::string& kerberos_realm,
														   const std::string& kerberos_fully_qualified_domain_name,
														   boost::shared_ptr<hs2client::krb::AuthenticationDetails> authentication_details,
														   const std::string& kerberos_service_name) :
_kerberos_realm(kerberos_realm),
_kerberos_fully_qualified_domain_name(kerberos_fully_qualified_domain_name),
_kerberos_service_name(kerberos_service_name),
_kerberos_username(authentication_details->get_principal()),
_authentication_details(authentication_details)
{
	std::stringstream strPrincipal;
	strPrincipal << kerberos_service_name << "/" << _kerberos_fully_qualified_domain_name << "@" << _kerberos_realm;

	_kerberos_principal = strPrincipal.str();
}

void sasl::GssapiSaslCallbackHandler::setup_callbacks()
{
	register_available_parameter_id(SASL_CB_USER);
	register_available_parameter_id(SASL_CB_PASS);
	/*register_available_parameter_id(SASL_CB_AUTHNAME);
	register_available_parameter_id(SASL_CB_LOG);
	register_available_parameter_id(SASL_CB_CANON_USER);*/
}

int sasl::GssapiSaslCallbackHandler::on_handle(void* context, int id, const char** result, unsigned int& len)
{
	if (!result)
		return SASL_BADPARAM;

	switch (id)
	{
		case SASL_CB_USER:
			*result = _kerberos_username.c_str();
			len = _kerberos_username.length();

			break;

		case SASL_CB_PASS:
		{
			auto auth_details = _authentication_details.get();
			auto password_authentication_details = dynamic_cast<hs2client::krb::PasswordAuthenticationDetails*>(auth_details);

			if (password_authentication_details != nullptr)
			{
				*result = password_authentication_details->get_password().c_str();
				len = password_authentication_details->get_password().length();
			}

			break;
		}
		case SASL_CB_LANGUAGE:
		case SASL_CB_AUTHNAME:
		case SASL_CB_CANON_USER:
			/* TODO: have to check whether _username fits here,
			according to https://github.com/cyrusimap/cyrus-sasl/issues/334
			this is a open bug. Check https://www.sendmail.org/~ca/email/cyrus2/programming.html
			*/
			*result = _kerberos_username.c_str();
			len = _kerberos_username.length();

			break;

		default:
			return SASL_BADPARAM;
	}

	return SASL_OK;
}

int sasl::GssapiSaslCallbackHandler::on_handle_canon_user(sasl_conn_t& conn, void* context, const char* in, unsigned inlen, unsigned flags, const char* user_realm, char* out, unsigned out_max, unsigned int& out_len)
{
	if((NULL !=out) && (NULL != in))
	{
		strncpy(out, _kerberos_username.c_str(), _kerberos_username.length());
		out_max = _kerberos_username.length();
		out_len = _kerberos_username.length();
		
		return SASL_OK;
	}

	return SASL_BADPROT;
}