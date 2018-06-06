PIP=pip

install:
	${PIP} install cherrypy
	${PIP} install pyotp
	${PIP} install pycrypto
	${PIP} install bcrypt
	${PIP} install scrypt