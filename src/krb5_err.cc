#include <string>
#include <system_error>

#include "krb5_err.hpp"

extern "C" {
#include <com_err.h>
}

Krb5Category::Krb5Category()
	: _error_table_initialized(false)
{
	if (! _error_table_initialized) {
		initialize_krb5_error_table();
	}	
	_error_table_initialized = true;
}

const char *
Krb5Category::name() const _NOEXCEPT
{
	return "krb5";
}

std::error_condition
Krb5Category::default_error_condition(int ev) const _NOEXCEPT
{
	return std::error_condition(ev, *this);
}

std::string
Krb5Category::message(int ev) const
{
	return error_message(ev);
}

void
Krb5Category::raise_on_error(krb5_error_code errcode)
{
	if (errcode != 0) {
		throw std::system_error(errcode, Krb5Category());
	}
}

const Krb5Category krb5_category;
