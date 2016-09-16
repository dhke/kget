#ifndef KRB5_PRINC_HPP
#define KRB5_PRINC_HPP

#include <iostream>

#include "krb5_ctx.hpp"

class Krb5Principal 
	: public Krb5ContextHolder
{
private:
	krb5_principal _princ;

	static void free_principal(krb5_principal *princ);

public:
	Krb5Principal(const Krb5Context &ctx, const char *name);
	Krb5Principal(const Krb5Principal &princ);
	Krb5Principal(Krb5Principal &&princ);
	Krb5Principal(const Krb5Context &ctx, const krb5_principal princ);
	~Krb5Principal();

	Krb5Principal &operator=(const Krb5Principal &princ);
	Krb5Principal &operator=(Krb5Principal &&princ);

	operator krb5_principal &();
	operator krb5_principal() const;

	krb5_principal &get();
	krb5_principal get() const;
};

std::ostream &operator<<(std::ostream &os, const Krb5Principal &princ);
#endif /* KRB5_PRINC_HPP */
