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

#ifndef SASL_IMPL_H_
#define SASL_IMPL_H_

#include <map>
#include <string.h>

#include <boost/shared_ptr.hpp>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>
#include <thrift/transport/TTransport.h>

#include "hs2client/sasl/thrift/TSasl.h"
#include "hs2client/sasl/sasl-callbacks.h"

using namespace std;

namespace sasl 
{
   class SaslClient : public Tsasl
   {
      public:
		  SaslClient(string mechanisms, string authorizationId,
                     string protocol, string serverName,
                     map<string,string> props, 
			         boost::shared_ptr<sasl::GenericSaslCallbackHandler> callbackHandler) ;

         ~SaslClient();

         virtual void dispose();

         /* Evaluates the challenge data and generates a response. */
         virtual uint8_t* evaluateChallenge(uint8_t* challenge, uint32_t& len);

         /* Returns the IANA-registered mechanism name of this SASL client. */
         virtual string getMechanismName();

         /* Retrieves the negotiated property */
         virtual string	getNegotiatedProperty(string propName);
         
         /* Determines whether this mechanism has an optional initial response. */
         virtual bool hasInitialResponse();

         /* Determines whether the authentication exchange has completed. */
         virtual bool isComplete();

         /* Unwraps a byte array received from the server. allocate new buffer for result */
         virtual uint8_t* unwrap(uint8_t* incoming, int offset, uint32_t & len);

         /* Wraps a byte array to be sent to the server. allocate new buffer for result */
         virtual uint8_t* wrap(uint8_t *outgoing, int offset, uint32_t & len);

		 static boost::shared_ptr<sasl::Tsasl> create_simple_client(const char* username, const char* password);

		 static boost::shared_ptr<sasl::Tsasl> create_password_based_gssapi_client(const std::string& realm, 
																				   const std::string& fully_qualified_domain_name,
																				   const std::string& username,
																				   const std::string& password,
																				   const std::string& service_name = "impala");

		 static boost::shared_ptr<sasl::Tsasl> create_keytab_based_gssapi_client(const std::string& realm, 
																				 const std::string& fully_qualified_domain_name, 
																				 const std::string& username,																				 
																				 const std::string& key_tab_file_path,
																				 const std::string& service_name = "impala");

		 static boost::shared_ptr<sasl::Tsasl> create_gssapi_client(const std::string& realm, 
																	const std::string& fully_qualified_domain_name,
																	boost::shared_ptr<hs2client::krb::AuthenticationDetails> auth_details,
																	const std::string& service_name = "impala");

      private :
         string chosenMech;
         string mechList;
         bool authComplete;
         bool clientStarted;
         sasl_conn_t *conn;

		 boost::shared_ptr<sasl::GenericSaslCallbackHandler> _callbackHandler;
   };

   /* return the libsasl error string */
   class SaslImplException : public SaslException 
   {
      public:
         SaslImplException(const char *errMsg);
   };
};

#endif // SASL_IMPL_H_
