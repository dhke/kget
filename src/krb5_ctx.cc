#include <memory>

extern "C" {
#include <krb5.h>

}

#include "krb5_err.hpp"
#include "krb5_ctx.hpp"

Krb5Context::Krb5Context()
	: _ctx(nullptr)
{
	krb5_context new_ctx;
	const krb5_error_code result = krb5_init_context(&new_ctx);
	Krb5Category::raise_on_error(result);
	_ctx = std::shared_ptr<krb5_context>(new krb5_context(new_ctx), free_context);
}

Krb5Context::Krb5Context(const Krb5Context &ctx)
	: _ctx(ctx._ctx)
{
}

Krb5Context::Krb5Context(Krb5Context &&ctx)
	: _ctx(std::move(ctx._ctx))
{
}

Krb5Context &
Krb5Context::operator=(const Krb5Context &ctx)
{
	this->_ctx = ctx._ctx;
	return *this;
}

Krb5Context &
Krb5Context::operator=(Krb5Context &&ctx)
{
	std::swap(_ctx, ctx._ctx);
	return *this;
}

Krb5Context::operator krb5_context &()
{
	return get();
}


Krb5Context::operator krb5_context() const
{
	return get();
}


krb5_context &
Krb5Context::get()
{
	return *_ctx;
}

krb5_context
Krb5Context::get() const
{
	return *_ctx;
}

void
Krb5Context::free_context(krb5_context *ctx)
{
	if (ctx != nullptr) {
		krb5_free_context(*ctx);
	}	
}

Krb5ContextHolder::Krb5ContextHolder(const Krb5Context &ctx)
	: _ctx(ctx)
{
}


Krb5ContextHolder::Krb5ContextHolder(Krb5Context &&ctx)
	: _ctx(std::move(ctx))
{
}

Krb5ContextHolder::Krb5ContextHolder(const Krb5ContextHolder &holder)
	: _ctx(holder._ctx)
{
}


Krb5ContextHolder::Krb5ContextHolder(Krb5ContextHolder &&holder)
	: _ctx(std::move(holder._ctx))
{
}

Krb5ContextHolder &
Krb5ContextHolder::operator=(const Krb5ContextHolder &holder)
{
	_ctx = holder._ctx;
	return *this;
}

Krb5ContextHolder &
Krb5ContextHolder::operator=(Krb5ContextHolder &&holder)
{
	std::swap(_ctx, holder._ctx);
	return *this;
}

Krb5Context &
Krb5ContextHolder::context()
{
	return _ctx;
}

Krb5Context
Krb5ContextHolder::context() const
{
	return _ctx;
}
