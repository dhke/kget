#include <cstdlib>
#include <iostream>
#include <string>

extern "C" {
#include "krb5.h"
}

#include "krb5_err.hpp"
#include "krb5_princ.hpp"

Krb5Principal::Krb5Principal(const Krb5Context &ctx, const char *name)
	: Krb5ContextHolder(ctx)
{
	const krb5_error_code result = krb5_parse_name(ctx, name, &_princ);
	Krb5Category::raise_on_error(result);
}

Krb5Principal::Krb5Principal(const Krb5Principal &princ)
	: Krb5Principal(this->context(), princ)
{
}

Krb5Principal::Krb5Principal(Krb5Principal &&princ)
	: Krb5ContextHolder(princ), _princ(std::move(princ._princ))
{
}

Krb5Principal::Krb5Principal(const Krb5Context &ctx, const krb5_principal princ)
	: Krb5ContextHolder(ctx)
{
	const krb5_error_code result = krb5_copy_principal(context(), princ, &_princ);
	Krb5Category::raise_on_error(result);
}

Krb5Principal::~Krb5Principal()
{
	krb5_free_principal(context(), _princ);
}

Krb5Principal &
Krb5Principal::operator=(const Krb5Principal &princ)
{
	krb5_principal new_princ;
	const krb5_error_code result = krb5_copy_principal(context(), princ, &new_princ);
	Krb5Category::raise_on_error(result);
	krb5_free_principal(context(), _princ);
	_princ = new_princ;

	Krb5ContextHolder::operator=(princ.context());
	return *this;
}


Krb5Principal &
Krb5Principal::operator=(Krb5Principal &&princ)
{
	Krb5ContextHolder::operator=(princ.context());
	std::swap(_princ, princ._princ);
	return *this;
}


Krb5Principal::operator krb5_principal &()
{
	return get();
}


Krb5Principal::operator krb5_principal() const
{
	return get();
}


krb5_principal &
Krb5Principal::get()
{
	return _princ;
}

krb5_principal
Krb5Principal::get() const
{
	return _princ;
}

std::ostream &
operator<<(std::ostream &os, const Krb5Principal &princ)
{
	char *name = nullptr;
	try {
		krb5_error_code result = krb5_unparse_name(princ.context(), princ, &name);
		Krb5Category::raise_on_error(result);
		return os << name;
	} catch (...) {
		free(name);
		throw;
	}
}
