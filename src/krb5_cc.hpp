#ifndef KRB5_CC_H
#define KRB5_CC_H

#include <memory>

#include "krb5_err.hpp"
#include "krb5_ctx.hpp"
#include "krb5_princ.hpp"
#include "krb5_creds.hpp"

class Krb5Cc
	: public Krb5ContextHolder
{
private:
	std::shared_ptr<krb5_ccache> _cache;

public:
	Krb5Cc(const Krb5Context &ctx);
	~Krb5Cc();

	krb5_ccache &get();
	krb5_ccache get() const;

	operator krb5_ccache &();
	operator krb5_ccache() const;

	void store(const Krb5Creds &creds);

	bool has_principal() const;
	void initialize(const Krb5Principal &princ);
	void destroy();

	Krb5Creds get_credentials(const Krb5Creds &in_creds, krb5_flags options=0);
};

#endif /* KRB5_CC_H */
