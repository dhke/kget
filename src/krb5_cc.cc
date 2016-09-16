#include "krb5_cc.hpp"
#include "krb5_err.hpp"
#include "krb5_princ.hpp"

class Krb5CCDeleter {
private:
	Krb5Context _ctx;

public:
	Krb5CCDeleter(const Krb5Context &ctx)
		: _ctx(ctx)
	{
	}

	void
	operator()(krb5_ccache *cache)
	{
		if (cache != nullptr) {
			krb5_cc_close(_ctx, *cache);
		}	
	}	
};

Krb5Cc::Krb5Cc(const Krb5Context &ctx)
	: Krb5ContextHolder(ctx), _cache(nullptr)
{
	krb5_ccache new_cache;
	krb5_error_code result = krb5_cc_default(ctx, &new_cache);
	Krb5Category::raise_on_error(result);
	_cache = std::shared_ptr<krb5_ccache>(new krb5_ccache(new_cache), Krb5CCDeleter(ctx));
}


Krb5Cc::~Krb5Cc()
{
}

bool
Krb5Cc::has_principal() const
{
	krb5_principal princ;
	krb5_error_code result = krb5_cc_get_principal(context(), *_cache, &princ);
	if (result == 0) {
		krb5_free_principal(context(), princ);
		return true;
	} else {
		return false;
	}	
}


void
Krb5Cc::initialize(const Krb5Principal &princ)
{
	krb5_error_code result = krb5_cc_initialize(context(), *_cache, princ);
	Krb5Category::raise_on_error(result);
}


void
Krb5Cc::destroy()
{
	krb5_error_code result = krb5_cc_destroy(context(), *_cache);
	Krb5Category::raise_on_error(result);
}


void
Krb5Cc::store(const Krb5Creds &creds)
{
	krb5_creds kcreds = creds;
	krb5_error_code result = krb5_cc_store_cred(context(), *_cache, &kcreds);
	Krb5Category::raise_on_error(result);
}


krb5_ccache 
Krb5Cc::get() const
{
	return *_cache;
}


krb5_ccache &
Krb5Cc::get()
{
	return *_cache;
}


Krb5Cc::operator krb5_ccache &()
{
	return get();
}


Krb5Cc::operator krb5_ccache() const
{
	return get();
}


Krb5Creds
Krb5Cc::get_credentials(const Krb5Creds &in_creds, krb5_flags options)
{
	krb5_creds raw_in_creds = in_creds;
	krb5_creds *out_creds;
	krb5_error_code result = krb5_get_credentials(
		context(),
		options,
		get(),
		&raw_in_creds,
		&out_creds
	);
	Krb5Category::raise_on_error(result);
	try {
		Krb5Creds creds = Krb5Creds::copy_from(context(), out_creds);
		krb5_free_creds(context(), out_creds);
		return creds;
	} catch (...) {
		krb5_free_creds(context(), out_creds);
		throw;
	}
}
