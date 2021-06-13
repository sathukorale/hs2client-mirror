// Copyright 2016 Cloudera Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HS2CLIENT_SERVICE_H
#define HS2CLIENT_SERVICE_H

#include <map>
#include <memory>
#include <string>

#include <boost/shared_ptr.hpp>
#include <thrift/transport/TSSLSocket.h>

#include "hs2client/macros.h"
#include "hs2client/status.h"

namespace hs2client {

class Session;
struct ThriftRPC;

// Stores per-session or per-operation configuration parameters.
class HS2ClientConfig {
 public:
  void SetOption(const std::string& key, const std::string& value) {
    config_[key] = value;
  }

  bool GetOption(const std::string& key, std::string* value_out) {
    if (config_.find(key) != config_.end() && value_out) {
      *value_out = config_[key];
      return true;
    }
    return false;
  }

  const std::map<std::string, std::string>& GetConfig() const { return config_; }

 private:
  std::map<std::string, std::string> config_;
};

// Maps directly to TProtocolVersion in the HiveServer2 interface.
enum class ProtocolVersion {
  HS2CLIENT_PROTOCOL_V1, // not supported
  HS2CLIENT_PROTOCOL_V2, // not supported
  HS2CLIENT_PROTOCOL_V3, // not supported
  HS2CLIENT_PROTOCOL_V4, // not supported
  HS2CLIENT_PROTOCOL_V5, // not supported
  HS2CLIENT_PROTOCOL_V6, // supported
  HS2CLIENT_PROTOCOL_V7, // supported
};

// Manages a connection to a HiveServer2 server. Primarily used to create
// new sessions via OpenSession.
//
// Service objects are created using Service::Connect(). They must
// have Close called on them before they can be deleted.
//
// This class is not thread-safe.
//
// Example:
// unique_ptr<Service> service;
// if (Service::Connect(host, port, protocol_version, &service).ok()) {
//   // do some work
//   service->Close();
// }
class Service {
 public:
	 struct Params
	 {
		static constexpr const char* paramTlsVersion = "tls.version";
		static constexpr const char* paramSslEnable = "ssl.enabled";
		static constexpr const char* paramSslSelfSigned = "ssl.selfSigned";
		static constexpr const char* paramCertificateLocation = "ssl.certificate";
		static constexpr const char* paramDisablePeerValidation = "ssl.disablePeerValidation";
		static constexpr const char* paramAuthMechanism = "auth.mechanism";
		static constexpr const char* paramKerberosRealm = "sasl.kerberos.realm";
		static constexpr const char* paramKerberosFqdn = "sasl.kerberos.fqdn";
		static constexpr const char* paramKerberosServiceName = "sasl.kerberos.serviceName";
		static constexpr const char* paramKerberosKeytabPath = "sasl.kerberos.keytabPath";
		static constexpr const char* paramCommonUsername = "sasl.username";
		static constexpr const char* paramCommonPassword = "sasl.password";
	  };

	 // Creates a new connection to a HS2 service at the given host and port. If
  // conn_timeout > 0, connection attempts will timeout after conn_timeout ms, otherwise
  // no timeout is used. protocol_version is the HiveServer2 protocol to use, and
  // determines whether the results returned by operations from this service are row or
  // column oriented. Only column oriented protocols are currently supported.
  //
  // The client calling Connect has ownership of the new Service that is created.
  // Executing RPCs with an Session or Operation corresponding to a particular
  // Service after that Service has been closed or deleted in undefined.
  static Status Connect(const std::string& host, int port, int conn_timeout,
	  ProtocolVersion protocol_version, std::unique_ptr<Service>* service);

  static Status Connect(const std::string& host, int port, int conn_timeout,
	  ProtocolVersion protocol_version, std::shared_ptr<HS2ClientConfig> securityConfigs, std::unique_ptr<Service>* service);

  ~Service();

  // Closes the connection. Must be called before the service is deleted. May be
  // safely called on an invalid or already closed service - will only return an
  // error if the service is open but the close rpc fails.
  Status Close();

  // Returns true iff this service has an active connection to the HiveServer2 server.
  bool IsConnected() const;

  // Set the send and receive timeout for Thrift RPCs in ms. 0 indicates no timeout,
  // negative values are ignored.
  void SetRecvTimeout(int timeout);
  void SetSendTimeout(int timeout);

  // Opens a new HS2 session using this service.
  // The client calling OpenSession has ownership of the Session that is created.
  // Operations on the Session are undefined once it is closed.
  Status OpenSession(const std::string& user, const HS2ClientConfig& config, std::unique_ptr<Session>* session) const;

  void SetSecurityConfigurations(std::shared_ptr<HS2ClientConfig> security_configs) { security_configs_ = security_configs; }

 private:
  HS2CLIENT_DISALLOW_COPY_AND_ASSIGN(Service);

  // Hides Thrift objects from the header.
  struct ServiceImpl;

  Service(const std::string& host, int port, int conn_timeout, ProtocolVersion protocol_version);

  // Opens the connection to the server. Called by Connect before new service is returned
  // to the user. Must be called before OpenSession.
  Status Open();

  boost::shared_ptr<apache::thrift::transport::TSSLSocketFactory> CreateSslSocketFactory(HS2ClientConfig& config);

  boost::shared_ptr<apache::thrift::transport::TTransport> CreateAuthenticatedTransport(HS2ClientConfig& config, 
																						boost::shared_ptr<apache::thrift::transport::TTransport> underlyingTransport, 
																						bool& is_renewal_process_needed);

  std::string host_;
  int port_;
  int conn_timeout_;

  std::unique_ptr<ServiceImpl> impl_;
  std::shared_ptr<ThriftRPC> rpc_;
  std::shared_ptr<HS2ClientConfig> security_configs_;

  boost::shared_ptr<apache::thrift::transport::TSSLSocketFactory> _ssl_socket_factory = nullptr;
};

}

#endif // HS2CLIENT_SERVICE_H
