//*************************************************************************
// Copyright(C) 2021 Millennium Information Technologies.
// All rights reserved.
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF
// MILLENNIUM INFORMATION TECHNOLOGIES LIMITED.
//
// This copy of the source code is intended for Millennium IT's internal
// use only and is intended for viewing by persons duly authorized by the
// management of Millennium IT. No part of this file may be reproduced or
// distributed in any form or by any means without the written approval of
// the management of Millennium IT.
//*************************************************************************

#ifndef AUTHENTICATION_DETAILS_H
#define AUTHENTICATION_DETAILS_H

#include <iostream>

#include <krb5/krb5.h>
#include <netdb.h>
#include <netinet/in.h>

#include "hs2client/status.h"

namespace hs2client
{
	namespace krb
	{
		class AuthenticationDetails
		{
			friend class RenewalProcess;
			friend class KinitContext;

			private:
				std::string _principal;

				virtual Status pre_kinit(krb5_context context) { (void)context; return Status::OK(); }

				virtual Status kinit(krb5_context& context,
									 krb5_creds& creds,
									 krb5_principal& client,
									 const char* in_tkt_service,
									 krb5_get_init_creds_opt* k5_gic_options)
				{
					throw new std::runtime_error("AuthenticationDetails::kinit method should be overriden");
				}

				virtual void cleanup(krb5_context context) { (void)context; }

			public:
				AuthenticationDetails(const std::string& principal) : _principal(principal) {}
				virtual ~AuthenticationDetails() {}

				inline const std::string& get_principal() const { return _principal; }
		};

		class KeytabAuthenticationDetails : public AuthenticationDetails
		{
			private:
				std::string _keytab_location;
				krb5_keytab _keytab;

			public:
				KeytabAuthenticationDetails(const std::string& principal, const std::string& keytab_location);

				Status pre_kinit(krb5_context context) override;

				Status kinit(krb5_context& context,
							 krb5_creds& creds,
							 krb5_principal& principal,
							 const char* in_tkt_service,
							 krb5_get_init_creds_opt* options) override;

				void cleanup(krb5_context context) override;
		};

		class PasswordAuthenticationDetails : public AuthenticationDetails
		{
			private:
				std::string _password;

			public:
				PasswordAuthenticationDetails(const std::string& principal, const std::string& password);

				Status kinit(krb5_context& context,
							 krb5_creds& creds,
							 krb5_principal& principal,
							 const char* in_tkt_service,
							 krb5_get_init_creds_opt* options) override;

				inline const std::string& get_password() const { return _password; }
		};
	}
}

#endif /*AUTHENTICATION_DETAILS_H*/