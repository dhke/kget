
#include <cassert>

#include <iostream>
#include <memory>
#include <string>
#include <system_error>

extern "C" {
#include <sys/types.h>

#include <gssapi/gssapi.h>
#include <krb5.h>
#include <pwd.h>
}

#include "krb5_err.hpp"
#include "krb5_ctx.hpp"
#include "krb5_princ.hpp"
#include "krb5_creds.hpp"
#include "krb5_cc.hpp"


static void usage()
{
	fprintf(stderr, "Usage: kget <init_principal> <service_principal>\n");
}



int
main(int argc, char *argv[])
{
	if (argc < 3) {
		usage();
		return 1;
	}

	const char *init_princ_name = argv[1];
	const char *service_princ_name = argv[2];

	try {
		Krb5Context kctx;
		Krb5Principal princ(kctx, init_princ_name);
		Krb5Principal server(kctx, service_princ_name);

		Krb5Cc cc(kctx);
		if (! cc.has_principal()) {
			Krb5InitCredOpt cred_opts(kctx);
			char *password = getpass("Enter password: ");
			Krb5Creds init_creds = cred_opts.password(princ, password);
			cc.initialize(princ);
			cc.store(init_creds);
		}	

		Krb5Creds get_creds(kctx);
		get_creds.client(princ);
		get_creds.server(server);

		Krb5Creds service_creds = cc.get_credentials(get_creds);
		std::cout << service_creds.client() << std::endl;
		std::cout << service_creds.server() << std::endl;

	} catch (std::system_error &err) {
		std::cerr << err.what() << std::endl;
		return 1;
	}

	return 0;
}
