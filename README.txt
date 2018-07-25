The overall goal of this project is to design a simple peer-to-peer social media network:
	1. Allowing a user to log into the system.
	2. The system can automatically find other users on other computers.
	3. User can create and maintain a simple profile page.
	4. Users can send messages, images, audio, and PDFfiles to each other.

To install we must install the external library.
run following command on the terminal
	$ make install
or to download them seperately
	$ pip install cherrypy	# for cherrypy
	$ pip install pyotp	# for pyotp
	$ pip install pycrypto	# for pycrypto	
	$ pip install bcrypt	# for bcrypt	
	$ pip install scrypt	# for scrypt
Also external lib is inside lib folder.
move to C:\Python27\Lib\site-packages or lib folder of your python2.7 directory
This will download cherrypy pyotp pycrypto bcrypt and scrypt external lib which is required for the server to run

run by opening the terminal on main project directory, type:
	$ python main.py
This will run the server, access by going on the localhost : portnumber
where port number is 10002 by default.

If you want to change the portnumber, w=you will need to change the variable listen_port on main.py to desired number

This server uses python 2.7.
Please refer to
	https://www.python.org/downloads/ to download python 2.7.

To download Pip please refer to
	https://pip.pypa.io/en/stable/installing/


Testing:

The supported UPI for the server is:
ktam069
dlee906
ilee471
ylee778