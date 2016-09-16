import os

kget_SOURCE = (
	'src/kget.cc', 
	'src/krb5_err.cc',
	'src/krb5_ctx.cc', 
	'src/krb5_princ.cc', 
	'src/krb5_creds.cc', 
	'src/krb5_cc.cc', 
)

env = Environment(environ=os.environ)
env.ParseConfig('krb5-config --cflags --libs')

env['CXX'] = 'c++'
env['CXXFLAGS'] = '-std=c++11 -g -W'
env['CPPPATH'] = 'include'

env.Program('kget', source=kget_SOURCE)
