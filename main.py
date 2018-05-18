#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: In Ha Ryu (iryu815@auckland.ac.nz)

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10004
my_location = '2'

central_server= "http://cs302.pythonanywhere.com"

import cherrypy

import json
import urllib2
import pickle
import time
import socket

import security

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        print("def default(self, *args, **kwargs):")
        """The default page, given when we don't recognise where the request is for."""
        Page = "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    # User nodes
    @cherrypy.expose
    def index(self):
        print("def index(self):")
        print self
        Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        last = ""
        try:
            Page += "Hello " + cherrypy.session['id'] + "!<br/><br/>"

            Page = '<form action="/send" method="post" enctype="multipart/form-data">'
            Page += 'To: <input type="text" name="destination"/><br/>'
            Page += 'Message: <input type="text" name="message"/><br/>'
            Page += '<input type="submit" value="Send"/></form>'
        
            Page += "Click here to list who is <a href='online'>online</a>.<br/>"
            last = "Click here to <a href='logoff'>log off</a>.<br/>"
        except KeyError, e: #There is no username
            if str(e) == "'id'":
                Page += "Click here to <a href='login'>login</a>.<br/>"
                
        Page += "Click here to list <a href='API'>API</a>.<br/>"
        Page += "Click here to list <a href='users'>Users</a>.<br/>"
        Page += last
        return Page

    @cherrypy.expose
    def API(self):
        Page = "Here is the of external API that we can use from cs302.pythonanywhere.com <br/><br/>"
        api = self.getAPI()
        print api
        return Page + api.read() + "<br/>Click here to go <a href='index'>home</a>.<br/>"

    def getAPI(self):
        return urllib2.urlopen(central_server + "/listAPI")
    
    @cherrypy.expose
    def users(self):
        Page = "Here is the of username listed in cs302.pythonanywhere.com <br/><br/>"
        user = self.getUser()
        print user
        return Page + user.read() + "<br/>Click here to go <a href='index'>home</a>.<br/>"

    def getUser(self):
        return urllib2.urlopen(central_server + "/listUsers")

    @cherrypy.expose
    def online(self):
        try:
            username = cherrypy.session['username']
            password = cherrypy.session['password']
            location = cherrypy.session['location']
            ip = cherrypy.session['ip']
            port = cherrypy.session['port']
            key = cherrypy.session['key']
        except KeyError:
            raise cherrypy.HTTPRedirect('/login?function=online')

        login = self.doReport(username, password, location, ip, port, key)
        l = login.read()
        if (l[0] == '0') :
            
            result = self.getOnline(username, password)
            Page = "Here is the list who is online:<br/><br/>"
            
            r = result.read()
            data = json.loads(r)
            cherrypy.session['online'] = data
            for i in data:
                for key, value in data[i].items():
                    Page += key + ': ' + value + ', '
                Page += '<br/><br/>'
            return Page + "<br/>Click here to go <a href='index'>home</a>.<br/>"
        else :
            raise cherrypy.HTTPRedirect('/login?function=online')

    def getOnline(self, username, password):
        req = urllib2.Request(
                central_server + "/getList" +
                "?username=" + username +
                "&password=" + password +
                "&enc=" + '1'+
                "&json=" + security.AES256encrypt('1', '150ecd12d550d05ad83f18328e536f53')
                )
        return urllib2.urlopen(req)

    def doReport(self, username, password, location, ip, port, key):
        req = urllib2.Request(
            central_server + "/report" +
            "?username=" + username +
            "&password=" + password +
            "&location=" + location +
            "&ip=" + ip +
            "&port=" + port +
            "&pubkey=" + key +
            "&enc=" + '1'
            )
        return urllib2.urlopen(req)
        
    
    @cherrypy.expose
    def login(self, function='index'):
        Page = '<form action="/signin?function='+ str(function) +'" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page + "<br/>Click here to go <a href='index'>home</a>.<br/>"

    @cherrypy.expose
    def send(self, destination, message):
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        location = cherrypy.session['location']
        ip = cherrypy.session['ip']
        port = cherrypy.session['port']
        key = cherrypy.session['key']
        address = self.getUserAddress(destination ,username, password, location, ip, port, key)
        if address == '3':
            return 3
        print address
        req = urllib2.Request(address + '/ping?sender=' + username)
        result = urllib2.urlopen(req)
        if result.read() != '0':
            return 3
        
        dict = {
                   "sender" : cherrypy.session['id'],
                   "destination" : destination,
                   "message" : message,
                   "stamp" : time.time()
               }
        req = urllib2.Request(address + '/receiveMessage', dict, {'Content-Type':'application/json'})
        result = urllib2.urlopen(req)

        return result.read()
        
    # back node login server
    @cherrypy.expose
    def logoff(self):

        username = cherrypy.session['username']
        password = cherrypy.session['password']
        req = urllib2.Request(
            central_server + "/logoff" +
            "?username=" + username +
            "&password=" + password +
            "&enc=" + '1'
            )
        try :
            cherrypy.lib.sessions.expire()
        except KeyError, e:
            if str(e) != "'online'" :            
                raise cherrypy.HTTPRedirect('/')
        
        result = urllib2.urlopen(req).read()
        if result[0] == '0' :
            raise cherrypy.HTTPRedirect('/')
        else :
            return result
    
    @cherrypy.expose
    def signin(self, username, password, function='index'):

        user_id = username

        login_pubkey = '150ecd12d550d05ad83f18328e536f53'
        RSA1024_public, RSA1024_private = security.RSAkeygen(1024)
        
        hashed = security.SHA256hash(password, username)
        username = security.AES256encrypt(username, login_pubkey)
        hashed = security.AES256encrypt(hashed, login_pubkey)
        location = security.AES256encrypt(my_location, login_pubkey)
        ipnum = ''
        if my_location == '1':
            ipnum = socket.gethostbyname(socket.gethostname())
        elif my_location == '2':
            ipnum = urllib2.urlopen('http://ip.42.pl/raw').read()
        ip = security.AES256encrypt(ipnum, login_pubkey)
        port = security.AES256encrypt("10004", login_pubkey)
        key = security.AES256encrypt(RSA1024_public ,login_pubkey)
        
        
        result = self.doReport(username, hashed, location, ip, port, key)

        r = result.read()
        if (r[0] == '0') :
            cherrypy.session['id'] = user_id
            cherrypy.session['username'] = username
            cherrypy.session['password'] = hashed
            cherrypy.session['location'] = location
            cherrypy.session['ip'] = ip
            cherrypy.session['port'] = port
            cherrypy.session['key'] = key
            raise cherrypy.HTTPRedirect('/' + str(function))
        else :
            return "failed to logic due to " + r

    # back node p2p server
    @cherrypy.expose
    def ping(self, sender):
        return '0'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        input_data = cherrypy.request.json
        try:
           log = {
                   "sender" : input_data["sender"],
                   "destination" : input_data["destination"],
                   "message" : input_data["message"],
                   "stamp" : input_data["stamp"]
                }
        except:
           return '1'

        try:
            username = cherrypy.session['username']
            password = cherrypy.session['password']
            location = cherrypy.session['location']
            ip = cherrypy.session['ip']
            port = cherrypy.session['port']
            key = cherrypy.session['key']
        except KeyError:
            raise cherrypy.HTTPRedirect('/login?function=online')

        try :
            loader = open('message.log', 'rb')
            input_log = pickle.load(loader)
            loader.close()
            log_id = input_log['id'] + 1
        except :
            log_id = '0'

        input_log[log_id] = log
        updater = open('message.log', 'wb')
        pickle.dump(input_log, updater)
        updater.close()
        return '0'

    def getUserAddress(self, User, username, password, location, ip, port, key):
        userip = None
        userport = None
        login = self.doReport(username, password, location, ip, port, key)
        l = login.read()
        if (l[0] == '0') :
            result = self.getOnline(username, password)            
            r = result.read()
            data = json.loads(r)
            cherrypy.session['online'] = data
            for i in data:
                if data[i]['username'] == User:
                    userip = data[i]['ip']
                    userport = data[i]['port']
                        
        if userip == None or userport == None:
            return '3'

        return 'http://' + userip + ':' + userport
    
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/")

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                           })

    print "========================="
    print "University of Auckland"
    print "COMPSYS302 - Software Design Application"
    print "========================================"                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
