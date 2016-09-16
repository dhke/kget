#ifndef KRB5_CREDS_HPP
#define KRB5_CREDS_HPP

extern "C" {
#include "krb5.h"
}

#include "krb5_err.hpp"
#include "krb5_ctx.hpp"
#include "krb5_princ.hpp"

class Krb5Creds
	: public Krb5ContextHolder
{
private:
	krb5_creds _creds;
	bool _no_delete;

public:
	Krb5Creds(const Krb5Context &ctx, krb5_creds creds, bool no_delete=false);
	Krb5Creds(const Krb5Context &ctx);
	Krb5Creds(const Krb5Creds &creds);
	Krb5Creds(Krb5Creds &&creds);
	~Krb5Creds();

	Krb5Creds &operator=(const Krb5Creds &creds);
	Krb5Creds &operator=(Krb5Creds &&creds);

	Krb5Principal client() const;
	Krb5Principal server() const;
	void client(const Krb5Principal &client);
	void server(const Krb5Principal &server);

	operator krb5_creds &();
	operator krb5_creds() const;

	krb5_creds get() const;
	krb5_creds &get();

	static Krb5Creds copy_from(const Krb5Context &ctx, krb5_creds *creds);
};

class Krb5InitCredOpt
	: public Krb5ContextHolder
{ 
private:
	krb5_get_init_creds_opt *_opt;

public:
	Krb5InitCredOpt(Krb5Context &ctx);
	~Krb5InitCredOpt();

	krb5_get_init_creds_opt *get() const;


	Krb5Creds password(const Krb5Principal &princ, const std::string &password, krb5_prompter_fct prompter=nullptr, krb5_deltat start_time=0) const;
	Krb5Creds password(const Krb5Principal &princ, const std::string &password, krb5_prompter_fct prompter, krb5_deltat start_time, const std::string in_tkt_service) const;
};


#endif /* KRB5_CREDS_HPP */
