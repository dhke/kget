#ifndef KRB5_CTX_HPP
#define KRB5_CTX_HPP

#include <memory>

extern "C" {
#include <krb5.h>
}

class Krb5Context {
private:
	std::shared_ptr<krb5_context> _ctx;

private:
	static void free_context(krb5_context *ctx);

public:
	Krb5Context();
	Krb5Context(const Krb5Context &ctx);
	Krb5Context(Krb5Context &&ctx);

	Krb5Context &operator=(const Krb5Context &ctx);
	Krb5Context &operator=(Krb5Context &&ctx);

	operator krb5_context &();
	operator krb5_context() const;

	krb5_context &get();
	krb5_context get() const;
};

class Krb5ContextHolder {
private:
	Krb5Context _ctx;

public:
	Krb5ContextHolder(const Krb5Context &ctx);
	Krb5ContextHolder(Krb5Context &&ctx);
	Krb5ContextHolder(const Krb5ContextHolder &holder);
	Krb5ContextHolder(Krb5ContextHolder &&holder);

	Krb5ContextHolder &operator=(const Krb5ContextHolder &holder);
	Krb5ContextHolder &operator=(Krb5ContextHolder &&holder);

	Krb5Context &context();
	Krb5Context context() const;
};

#endif /* KRB5_CTX_HPP */
