/****************************************************************************
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License") { you may not use this file except in compliance
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
#include <iostream>

#include "hs2client/sasl/sasl-client.h"
#include "hs2client/sasl/krb/renewal-process.h"

using namespace std;

sasl::SaslClient::SaslClient(string mechanisms, string authorizationId,
                             string protocol, string serverName, map<string, string> props, 
                             boost::shared_ptr<sasl::GenericSaslCallbackHandler> callbackHandler) :
_callbackHandler(callbackHandler)
{
  int result;

  static std::once_flag once;
  std::call_once(once, [&]()
  {
	  result = sasl_client_init(NULL);
	  if (result != SASL_OK)
		  throw SaslImplException(sasl_errstring(result, NULL, NULL));
  });

  result = sasl_client_new(protocol.c_str(), serverName.c_str(), NULL, NULL, _callbackHandler->create_sasl_callback_handlers(), 0, &conn);
  if (result != SASL_OK)
    throw SaslImplException(sasl_errstring(result, NULL, NULL));
  
  if (!authorizationId.empty()) {
    /* TODO: setup security property */
    /*
    sasl_security_properties_t secprops;
    // populate  secprops
    result = sasl_setprop(conn, SASL_AUTH_EXTERNAL,authorizationId.c_str());
    */
  }

  chosenMech = mechList = mechanisms;
  authComplete = false;
  clientStarted = false;
} 

sasl::SaslClient::~SaslClient() { dispose(); }

void sasl::SaslClient::dispose()
{
	if (conn != nullptr)
	{
		sasl_dispose(&conn);
		conn = nullptr;
	}
}

/* Evaluates the challenge data and generates a response. */
uint8_t* sasl::SaslClient::evaluateChallenge(uint8_t* challenge, uint32_t& len) {
  sasl_interact_t *client_interact=NULL;
  uint8_t *out=NULL;
  uint32_t outlen=0;
  uint32_t result;
  char *mechusing;

  if (!clientStarted) {
    result=sasl_client_start(conn,
          mechList.c_str(),
          &client_interact, /* filled in if an interaction is needed */
          (const char**)&out,      /* filled in on success */
          &outlen,   /* filled in on success */
          (const char**)&mechusing);
    clientStarted = true;
    chosenMech = mechusing;
  } else {
    if (len  > 0) {
      result=sasl_client_step(conn,  /* our context */
          (const char*)challenge,    /* the data from the server */
          len, /* it's length */
          &client_interact,  /* this should be unallocated and NULL */
          (const char**)&out,     /* filled in on success */
          &outlen); /* filled in on success */
    } else {
      result = SASL_CONTINUE;
    }
  }

  if (result == SASL_OK)
    authComplete = true;  
  else if (result != SASL_CONTINUE)
    throw SaslImplException(sasl_errstring(result, NULL, NULL));

  len = outlen;
  return (uint8_t*)out;
}

/* Returns the IANA-registered mechanism name of this SASL client. */
std::string sasl::SaslClient::getMechanismName() {
  return chosenMech;
}

/* Retrieves the negotiated property */
std::string	sasl::SaslClient::getNegotiatedProperty(std::string propName) {
  return NULL;
}

/* Determines whether this mechanism has an optional initial response. */
bool sasl::SaslClient::hasInitialResponse() {
  // TODO: need to check if its true for Kerberos
  return true;
}
    /* Determines whether the authentication exchange has completed. */
bool sasl::SaslClient::isComplete() {
  return authComplete;
}
   /* Unwraps a byte array received from the server. allocate new buffer for result */
uint8_t* sasl::SaslClient::unwrap(uint8_t* incoming, int offset, uint32_t & len) {
  uint32_t outputlen;
  uint8_t *output;
  int result;

  result = sasl_decode(conn, (const char*)incoming, len, (const char**)&output, &outputlen);
  if (result != SASL_OK)
    throw SaslImplException(sasl_errstring(result, NULL, NULL));

  len = outputlen;
  return output;
}

/* Wraps a byte array to be sent to the server. allocate new buffer for result */
uint8_t* sasl::SaslClient::wrap(uint8_t *outgoing, int offset, uint32_t & len) {
  uint32_t outputlen;
  uint8_t *output;
  int result;

  result = sasl_encode(conn, (const char*)outgoing+offset, len, (const char**)&output, &outputlen);
  if (result != SASL_OK)
    throw SaslImplException(sasl_errstring(result, NULL, NULL));

  len = outputlen;
  return output;
}

sasl::SaslImplException::SaslImplException(const char* errMsg) : SaslException(errMsg) { }

boost::shared_ptr<sasl::Tsasl> sasl::SaslClient::create_simple_client(const char* username, const char* password)
{
	auto ptrCallbackHandler = new sasl::SimpleSaslCallbackHandler(username, password);

	boost::shared_ptr<sasl::GenericSaslCallbackHandler> callbackHandler(ptrCallbackHandler);
	map<string, string> props;

	return boost::shared_ptr<sasl::Tsasl>(new SaslClient("PLAIN", "", "", "", props, callbackHandler));
}

boost::shared_ptr<sasl::Tsasl> sasl::SaslClient::create_password_based_gssapi_client(const std::string& realm,
																					 const std::string& fqdn,
																					 const std::string& username,
																					 const std::string& password,
																					 const std::string& service_name)
{
	auto auth_details_ptr = boost::shared_ptr<hs2client::krb::AuthenticationDetails>(new hs2client::krb::PasswordAuthenticationDetails(username, password));
	return create_gssapi_client(realm, fqdn, auth_details_ptr, service_name);
}

boost::shared_ptr<sasl::Tsasl> sasl::SaslClient::create_keytab_based_gssapi_client(const std::string& realm,
																				   const std::string& fqdn,
																				   const std::string& username,																				 
																				   const std::string& key_tab_file_path,
																				   const std::string& service_name)
{
	auto auth_details_ptr = boost::shared_ptr<hs2client::krb::AuthenticationDetails>(new hs2client::krb::KeytabAuthenticationDetails(username, key_tab_file_path));
	return create_gssapi_client(realm, fqdn, auth_details_ptr, service_name);
}

boost::shared_ptr<sasl::Tsasl> sasl::SaslClient::create_gssapi_client(const std::string& realm,
																	  const std::string& fqdn,
																	  boost::shared_ptr<hs2client::krb::AuthenticationDetails> auth_details, 
																	  const std::string& service_name)
{
	hs2client::krb::RenewalProcess::get_instance().start(auth_details->get_principal(), auth_details);

	auto ptrCallbackHandler = new sasl::GssapiSaslCallbackHandler(realm, fqdn, auth_details, service_name);
	boost::shared_ptr<sasl::GenericSaslCallbackHandler> callbackHandler(ptrCallbackHandler);

	map<string, string> props;
	return boost::shared_ptr<sasl::Tsasl>(new SaslClient("GSSAPI", "", service_name, fqdn, props, callbackHandler));
}
