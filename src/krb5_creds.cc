#include "krb5_creds.hpp"

Krb5Creds::Krb5Creds(const Krb5Context &ctx, krb5_creds creds, bool no_delete)
	: Krb5ContextHolder(ctx), _creds(creds), _no_delete(no_delete)
{
}

Krb5Creds::Krb5Creds(const Krb5Creds &creds)
	: Krb5ContextHolder(creds), _creds(), _no_delete(true)
{
	krb5_creds new_creds;
	krb5_error_code result = krb5_copy_creds_contents(context(), &creds._creds, &new_creds);
	Krb5Category::raise_on_error(result);
	_creds = new_creds;
	_no_delete = false;
}

Krb5Creds::Krb5Creds(Krb5Creds &&creds)
	: Krb5ContextHolder(std::move(creds)), _creds(), _no_delete(true)
{
	std::swap(_creds, creds._creds);
	std::swap(_no_delete, creds._no_delete);
}

Krb5Creds::Krb5Creds(const Krb5Context &ctx)
	: Krb5ContextHolder(ctx), _creds(), _no_delete(false)
{
}

Krb5Creds::~Krb5Creds()
{
	if (! _no_delete) {
		krb5_free_cred_contents(context(), &_creds);
	}	
}

Krb5Creds &
Krb5Creds::operator=(const Krb5Creds &creds)
{
	krb5_creds new_creds;
	krb5_error_code result = krb5_copy_creds_contents(context(), &creds._creds, &new_creds);
	Krb5Category::raise_on_error(result);
	std::swap(_creds, new_creds);
	krb5_free_cred_contents(context(), &new_creds);
	_no_delete = false;
	Krb5ContextHolder::operator=(creds);
	return *this;
}

Krb5Creds &
Krb5Creds::operator=(Krb5Creds &&creds)
{
	Krb5ContextHolder::operator=(creds);
	std::swap(_creds, creds._creds);
	std::swap(_no_delete, creds._no_delete);
	return *this;
}


Krb5Principal
Krb5Creds::client() const
{
	return Krb5Principal(context(), _creds.client);
}


void
Krb5Creds::client(const Krb5Principal &client)
{
	/* XXX - use class */
	krb5_principal new_princ;
	const krb5_error_code result = krb5_copy_principal(context(), client, &new_princ);
	Krb5Category::raise_on_error(result);
	std::swap(_creds.client, new_princ);
	krb5_free_principal(context(), new_princ);
}

void
Krb5Creds::server(const Krb5Principal &server)
{
	/* XXX - use class */
	krb5_principal new_princ;
	const krb5_error_code result = krb5_copy_principal(context(), server, &new_princ);
	Krb5Category::raise_on_error(result);
	std::swap(_creds.server, new_princ);
	krb5_free_principal(context(), new_princ);
}


Krb5Principal
Krb5Creds::server() const
{
	return Krb5Principal(context(), _creds.server);
}


Krb5InitCredOpt::Krb5InitCredOpt(Krb5Context &ctx)
	: Krb5ContextHolder(ctx), _opt(nullptr)
{
	krb5_error_code result = krb5_get_init_creds_opt_alloc(context(), &_opt);
	Krb5Category::raise_on_error(result);
}


Krb5InitCredOpt::~Krb5InitCredOpt()
{
	krb5_get_init_creds_opt_free(context(), _opt);
}


krb5_get_init_creds_opt *
Krb5InitCredOpt::get() const
{
	return _opt;
}


Krb5Creds
Krb5InitCredOpt::password(const Krb5Principal &princ, const std::string &password, krb5_prompter_fct prompter, krb5_deltat start_time) const
{
	krb5_creds creds;
	krb5_error_code result = krb5_get_init_creds_password(
		princ.context(), 
		&creds,
		princ,
		password.c_str(),
		prompter,
		nullptr,
		start_time,
		nullptr,
		get()
	);
	Krb5Category::raise_on_error(result);
	return Krb5Creds(princ.context(), creds);
}


Krb5Creds
Krb5InitCredOpt::password(const Krb5Principal &princ, const std::string &password, krb5_prompter_fct prompter, krb5_deltat start_time, const std::string in_tkt_service) const
{
	krb5_creds creds;
	krb5_error_code result = krb5_get_init_creds_password(
		princ.context(), 
		&creds,
		princ,
		password.c_str(),
		prompter,
		nullptr,
		start_time,
		in_tkt_service.c_str(),
		get()
	);
	Krb5Category::raise_on_error(result);
	return Krb5Creds(princ.context(), creds);
}


Krb5Creds::operator krb5_creds &()
{
	return get();
}


Krb5Creds::operator krb5_creds() const
{
	return get();
}


krb5_creds
Krb5Creds::get() const
{
	return _creds;
}


krb5_creds &
Krb5Creds::get()
{
	return _creds;
}


Krb5Creds 
Krb5Creds::copy_from(const Krb5Context &ctx, krb5_creds *creds)
{
	krb5_creds new_creds;
	const krb5_error_code result = krb5_copy_creds_contents(ctx, creds, &new_creds);
	Krb5Category::raise_on_error(result);
	return Krb5Creds(ctx, new_creds);
}
