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

#include "hs2client/service.h"

#include <sstream>
#include <fstream>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TSSLSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include "hs2client/session.h"
#include "hs2client/logging.h"
#include "hs2client/thrift-internal.h"
#include "hs2client/sasl/sasl-client.h"
#include "hs2client/sasl/thrift/TSaslTransport.h"
#include "hs2client/sasl/krb/renewal-process.h"

#include "gen-cpp/ImpalaHiveServer2Service.h"
#include "gen-cpp/TCLIService.h"

namespace thrift_transport = apache::thrift::transport;
namespace hs2 = apache::hive::service::cli::thrift;

using apache::thrift::TException;
using apache::thrift::protocol::TBinaryProtocol;
using apache::thrift::protocol::TProtocol;
using apache::thrift::transport::TBufferedTransport;
using apache::thrift::transport::TSocket;
using apache::thrift::transport::TTransport;
using std::string;
using std::unique_ptr;

namespace hs2client
{
	bool FileExists(const std::string& filePath)
	{
		std::ifstream fileStream(filePath);
		return fileStream.good();
	}

	boost::shared_ptr<thrift_transport::TSSLSocketFactory> Service::CreateSslSocketFactory(HS2ClientConfig& config)
	{
		std::vector<std::string> supportedTlsVersions = { "1", "1.0", "1.1", "1.2" };
		std::vector<std::string> trueStrings = { "1", "true", "yes" };

		bool isAuthenticationEnabled = false;
		bool isSelfSignedCertificate = false;
		bool isSslEnabled = false;
		int tlsVersion = 0;
		std::string tmpValue = "";
		std::string certificateFileLocation = "";

		if (config.GetOption(Service::Params::paramDisablePeerValidation, &tmpValue))
			isAuthenticationEnabled = std::binary_search(trueStrings.begin(), trueStrings.end(), tmpValue);
		else
			isAuthenticationEnabled = false;

		if (config.GetOption(Service::Params::paramSslEnable, &tmpValue) && std::binary_search(trueStrings.begin(), trueStrings.end(), tmpValue))
			isSslEnabled = true;

		if (config.GetOption(Service::Params::paramTlsVersion, &tmpValue) && std::binary_search(supportedTlsVersions.begin(), supportedTlsVersions.end(), tmpValue))
		{
			isSslEnabled = true;
			tlsVersion = 1 + (static_cast<int>(atof(tmpValue.c_str()) * 10) - 10);
		}

		if (isSslEnabled)
		{
			if (config.GetOption(Service::Params::paramSslSelfSigned, &tmpValue) && std::binary_search(trueStrings.begin(), trueStrings.end(), tmpValue))
				isSelfSignedCertificate = true;

			if (config.GetOption(Service::Params::paramCertificateLocation, &certificateFileLocation) == false)
				throw std::runtime_error("Cannot create an SSL connection if no certificate file is set.");

			if (FileExists(certificateFileLocation) == false)
			{
				std::stringstream strError;
				strError << "The certificate file expected at '" << certificateFileLocation << "' does not exist.";

				throw std::runtime_error(strError.str());
			}
		}
		else return nullptr;

		auto sslVersion = static_cast<apache::thrift::transport::SSLProtocol>(tlsVersion + 2);
		auto sslSocketFactory = boost::shared_ptr<thrift_transport::TSSLSocketFactory>(new thrift_transport::TSSLSocketFactory(sslVersion));

		sslSocketFactory->server(false);
		sslSocketFactory->authenticate(isAuthenticationEnabled);

		if (isSslEnabled)
		{
			if (isSelfSignedCertificate)
			{
				sslSocketFactory->loadCertificate(certificateFileLocation.c_str());
				sslSocketFactory->loadTrustedCertificates(certificateFileLocation.c_str());
			}
			else
				sslSocketFactory->loadTrustedCertificates(certificateFileLocation.c_str());

			return sslSocketFactory;
		}

		return nullptr;
	}

	boost::shared_ptr<thrift_transport::TTransport> Service::CreateAuthenticatedTransport(HS2ClientConfig& config, boost::shared_ptr<thrift_transport::TTransport> underlyingTransport, bool& is_renewal_process_needed)
	{
		is_renewal_process_needed = false;

		std::vector<std::string> supportedAuthMechanisms = { "kerberos", "simple" };

		std::string authMech;

		std::string commonUsername = "";
		std::string commonPassword = "";

		std::string kerberosKeytabFilePath = "";
		std::string kerberosRealm = "";
		std::string kerberosFullyQualifiedDomainName = "";
		std::string kerberosServiceName = "";

		if (config.GetOption(Service::Params::paramAuthMechanism, &authMech) == false ||
			std::binary_search(supportedAuthMechanisms.begin(), supportedAuthMechanisms.end(), authMech) == false)
			return nullptr;

		if (authMech == "kerberos")
		{
			if (config.GetOption(Service::Params::paramKerberosRealm, &kerberosRealm) == false)
				throw new std::runtime_error("The Kerberos Realm parameter is required.");

			if (config.GetOption(Service::Params::paramKerberosFqdn, &kerberosFullyQualifiedDomainName) == false)
				throw new std::runtime_error("The Kerberos Fully Qualified Domain Name parameter is required.");

			if (config.GetOption(Service::Params::paramKerberosServiceName, &kerberosServiceName) == false)
				kerberosServiceName = "impala";

			if (config.GetOption(Service::Params::paramCommonUsername, &commonUsername) == false)
				throw new std::runtime_error("The Kerberos Username/Principal parameter is required.");

			if (config.GetOption(Service::Params::paramKerberosKeytabPath, &kerberosKeytabFilePath) && FileExists(kerberosKeytabFilePath) == false)
			{
				std::stringstream strError;
				strError << "The key-tab file expected at '" << kerberosKeytabFilePath << "' does not exist.";

				throw new std::runtime_error(strError.str());
			}

			if (config.GetOption(Service::Params::paramCommonPassword, &commonPassword) == false)
				commonPassword = "";

			if (commonPassword.empty() && kerberosKeytabFilePath.empty())
				throw new std::runtime_error("Both the key-tab file path, and the password cannot be empty.");

			boost::shared_ptr<sasl::Tsasl> saslClient(nullptr);

			if (commonPassword.empty() == false)
				saslClient = sasl::SaslClient::create_password_based_gssapi_client(kerberosRealm, kerberosFullyQualifiedDomainName, commonUsername, commonPassword, kerberosServiceName);
			else if (kerberosKeytabFilePath.empty() == false)
				saslClient = sasl::SaslClient::create_keytab_based_gssapi_client(kerberosRealm, kerberosFullyQualifiedDomainName, commonUsername, kerberosKeytabFilePath, kerberosServiceName);

			is_renewal_process_needed = true;

			return boost::shared_ptr<thrift_transport::TTransport>(new thrift_transport::TSaslTransport(saslClient, underlyingTransport));
		}
		else if (authMech == "simple")
		{
			std::string username;
			std::string password;

			if (config.GetOption(Service::Params::paramCommonUsername, &username) == false)
				throw new std::runtime_error("The SASL username parameter is required.");

			if (config.GetOption(Service::Params::paramCommonPassword, &password) == false)
				throw new std::runtime_error("The SASL password parameter is required.");

			boost::shared_ptr<sasl::Tsasl> saslClient = sasl::SaslClient::create_simple_client(username.c_str(), password.c_str());
			return boost::shared_ptr<thrift_transport::TTransport>(new thrift_transport::TSaslTransport(saslClient, underlyingTransport));
		}

		return nullptr;
	}

struct Service::ServiceImpl {
  hs2::TProtocolVersion::type protocol_version;
  // The use of boost here is required for Thrift compatibility.
  boost::shared_ptr<TSocket> socket;
  boost::shared_ptr<TTransport> transport;
  boost::shared_ptr<TProtocol> protocol;
};

Status Service::Connect(const string& host, int port, int conn_timeout,
    ProtocolVersion protocol_version, unique_ptr<Service>* service) {
  service->reset(new Service(host, port, conn_timeout, protocol_version));
  return (*service)->Open();
}

Status Service::Connect(const string& host, int port, int conn_timeout,
	ProtocolVersion protocol_version, std::shared_ptr<HS2ClientConfig> securityConfigs,
	unique_ptr<Service>* service) {
	service->reset(new Service(host, port, conn_timeout, protocol_version));
	(*service)->SetSecurityConfigurations(securityConfigs);

	return (*service)->Open();
}

Service::~Service() {
  DCHECK(!IsConnected());
}

Status Service::Close() {
  if (!IsConnected()) return Status::OK();
  TRY_RPC_OR_RETURN(impl_->transport->close());
  return Status::OK();
}

bool Service::IsConnected() const {
  return impl_->transport && impl_->transport->isOpen();
}

void Service::SetRecvTimeout(int timeout) {
  impl_->socket->setRecvTimeout(timeout);
}

void Service::SetSendTimeout(int timeout) {
  impl_->socket->setSendTimeout(timeout);
}

Status Service::OpenSession(const string& user, const HS2ClientConfig& config,
    unique_ptr<Session>* session) const {
  session->reset(new Session(rpc_));
  return (*session)->Open(config, user);
}

Service::Service(const string& host, int port, int conn_timeout, ProtocolVersion protocol_version) 
  : host_(host), port_(port), conn_timeout_(conn_timeout), impl_(new ServiceImpl()),
    rpc_(new ThriftRPC()), security_configs_(nullptr){
  impl_->protocol_version = ProtocolVersionToTProtocolVersion(protocol_version);
}

Status Service::Open() 
{
	if (impl_->protocol_version < hs2::TProtocolVersion::HIVE_CLI_SERVICE_PROTOCOL_V6) 
	{
		std::stringstream ss;
		ss << "Unsupported protocol: " << impl_->protocol_version;

		return Status::Error(ss.str());
	}

	_ssl_socket_factory.reset();
	impl_->socket.reset();

	if (security_configs_.get() != nullptr)
	{
		_ssl_socket_factory = CreateSslSocketFactory(*security_configs_);		
		if (_ssl_socket_factory.get() != nullptr)
		{
			auto socket = _ssl_socket_factory->createSocket(host_, port_);
			if (socket.get() != nullptr)
				impl_->socket = socket;
		}
	}

	if (impl_->socket.get() == nullptr)
		impl_->socket.reset(new TSocket(host_, port_));

	impl_->socket->setConnTimeout(conn_timeout_);
	impl_->transport.reset(new TBufferedTransport(impl_->socket));

	boost::shared_ptr<thrift_transport::TTransport> transport_to_use = impl_->transport;
	bool requires_renewal_process = false;

	if (security_configs_.get() != nullptr)
	{
		boost::shared_ptr<thrift_transport::TTransport> transport = CreateAuthenticatedTransport(*security_configs_, impl_->transport, requires_renewal_process);
		if (transport.get() != nullptr) 
			transport_to_use = transport;
	}

	impl_->protocol.reset(new TBinaryProtocol(transport_to_use));

	rpc_->client.reset(new impala::ImpalaHiveServer2ServiceClient(impl_->protocol));

	if (requires_renewal_process)
	{
		std::lock_guard<std::mutex> l(hs2client::krb::RenewalProcess::get_instance().get_lock());
		TRY_RPC_OR_RETURN(transport_to_use->open());
	}
	else
	{
		TRY_RPC_OR_RETURN(transport_to_use->open());
	}

	return Status::OK();
}

} // namespace hs2client
