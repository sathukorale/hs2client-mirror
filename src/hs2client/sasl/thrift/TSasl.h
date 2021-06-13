/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _THRIFT_TRANSPORT_TSSLWRAPPER_H_
#define _THRIFT_TRANSPORT_TSSLWRAPPER_H_

#include <string>
#include <stdint.h>
#include <stdexcept>

namespace sasl {
  class SaslException : public std::runtime_error {
    public:
      SaslException(const char *msg) : runtime_error(msg) {
    }
  };

  class Tsasl {
    public:
    /* Disposes of any system resources or security-sensitive 
     * information the SaslClient might be using. 
     */
    virtual void dispose() =0;

    /* Evaluates the challenge data and generates a response. */
    virtual uint8_t* evaluateChallenge(uint8_t* challenge, uint32_t& len) =0;

    /* Returns the IANA-registered mechanism name of this SASL client. */
    virtual std::string getMechanismName() =0;

    /* Retrieves the negotiated property */
    virtual std::string	getNegotiatedProperty(std::string propName) =0;
     
    /* Determines whether this mechanism has an optional initial response. */
    virtual bool hasInitialResponse() =0;

    /* Determines whether the authentication exchange has completed. */
    virtual bool isComplete() =0;

   /* Unwraps a byte array received from the server. allocate new buffer for result */
   virtual uint8_t* unwrap(uint8_t* incoming, int offset, uint32_t & len) =0;

   /* Wraps a byte array to be sent to the server. allocate new buffer for result */
   virtual uint8_t* wrap(uint8_t *outgoing, int offset, uint32_t & len) =0;
  };

}
#endif /* _THRIFT_TRANSPORT_TSSLWRAPPER_H_ */
