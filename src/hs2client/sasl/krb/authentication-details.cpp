#include "authentication-details.h"

#include "hs2client/sasl/krb/kinit-context.h"
#include "hs2client/sasl/krb/status.h"

using namespace std;
using namespace hs2client;

#define KRB5_RETURN_NOT_OK_PREPEND_EXT(context, call, prepend) \
        RETURN_NOT_OK_PREPEND(hs2client::krb::KinitContext::Krb5CallToStatus(context, (call)), (prepend))

hs2client::krb::KeytabAuthenticationDetails::KeytabAuthenticationDetails(const std::string& principal, const std::string& keytab_location) :
hs2client::krb::AuthenticationDetails(principal),
_keytab_location(keytab_location),
_keytab(nullptr)
{
}

hs2client::krb::PasswordAuthenticationDetails::PasswordAuthenticationDetails(const std::string& principal, const std::string& password) :
hs2client::krb::AuthenticationDetails(principal),
_password(password)
{
}

Status krb::KeytabAuthenticationDetails::pre_kinit(krb5_context context)
{
	setenv("KRB5_KTNAME", _keytab_location.c_str(), 1);

	if (_keytab == nullptr)
	{
		KRB5_RETURN_NOT_OK_PREPEND_EXT(context, krb5_kt_resolve(context, _keytab_location.c_str(), &_keytab), "unable to resolve key-tab");
	}

	return Status::OK();
}

Status hs2client::krb::KeytabAuthenticationDetails::kinit(krb5_context& context, krb5_creds& creds, krb5_principal& principal, const char* in_tkt_service, krb5_get_init_creds_opt* options)
{
	KRB5_RETURN_NOT_OK_PREPEND_EXT(context, krb5_get_init_creds_keytab(context, &creds, principal, _keytab, 0, nullptr, options), "unable to login from keytab");
	return Status::OK();
}

Status hs2client::krb::PasswordAuthenticationDetails::kinit(krb5_context& context, krb5_creds& creds, krb5_principal& principal, const char* in_tkt_service, krb5_get_init_creds_opt* options)
{
	KRB5_RETURN_NOT_OK_PREPEND_EXT(context, krb5_get_init_creds_password(context, &creds, principal, _password.c_str(), nullptr, nullptr, 0, nullptr, options), "unable to login from password");
	return Status::OK();
}

void hs2client::krb::KeytabAuthenticationDetails::cleanup(krb5_context context)
{
	if (_keytab != nullptr) krb5_kt_close(context, _keytab);
}