#ifndef KRB5_ERR_HPP
#define KRB5_ERR_HPP

#include <system_error>

extern "C" {
#include <krb5.h>
#include <krb5_err.h>
}

class Krb5Category
	: public std::error_category
{
private:
	bool _error_table_initialized;

public:
	Krb5Category();
	Krb5Category(Krb5Category &&) = delete;
	Krb5Category(const Krb5Category &) = delete;

	Krb5Category &operator=(const Krb5Category &) = delete;
public:
	virtual const char *name() const _NOEXCEPT;
	virtual std::error_condition default_error_condition(int ev) const _NOEXCEPT;
	virtual std::string message(int ev) const;

	static void raise_on_error(krb5_error_code errcode);
};

extern const Krb5Category krb5_category;

#endif /* KRB5_ERR_HPP */
