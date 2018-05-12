#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2018

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10004

central_server= "http://cs302.pythonanywhere.com"

import cherrypy

import json
import urllib2
import hashlib
import socket

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
    @cherrypy.expose
    def index(self):
        print("def index(self):")
        print self
        Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/><br/>"

            Page += "Click here to list who is <a href='online'>online</a>.<br/>"
            
        except KeyError, e: #There is no username
            if str(e) == "'username'" or str(e) == "'password'":
                Page += "Click here to <a href='login'>login</a>.<br/>"
                
        Page += "Click here to list <a href='API'>API</a>.<br/>"
        Page += "Click here to list <a href='users'>Users</a>."
        
        return Page

    @cherrypy.expose
    def API(self):
        Page = "Here is the of external API that we can use from cs302.pythonanywhere.com <br/><br/>"
        api = urllib2.urlopen(central_server + "/listAPI")
        print api
        return Page + api.read()

    @cherrypy.expose
    def users(self):
        Page = "Here is the of username listed in cs302.pythonanywhere.com <br/><br/>"
        user = urllib2.urlopen(central_server + "/listUsers")
        print user
        return Page + user.read()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def online(self):
        try:
            username = cherrypy.session['username']
            password = cherrypy.session['password']
        except KeyError:
            raise cherrypy.HTTPRedirect('/login?function=online')

        login = urllib2.urlopen(
            central_server + "/report" +
            "?username=" + username +
            "&password=" + password +
            "&location=" + '2' +
            "&ip=" + socket.gethostbyname(socket.gethostname()) +
            "&port=" + "10004"
            )
        l = login.read()
        if (l[0] == '0') :
            req = urllib2.Request(
                central_server + "/getList" +
                "?username=" + username +
                "&password=" + password +
                "&enc=" + '0'+
                "&json=" + '1'
                )
            result = urllib2.urlopen(req)
            Page = "Here is the list who is online:<br/>"
            
            r = result.read()
            data = json.loads(r)

            for i in data:
                for key, value in data[i].items():
                    Page += key + ': ' + value + ', '
                Page += '<br/>'
            return Page
        else :
            raise cherrypy.HTTPRedirect('/login?function=online')
    
    @cherrypy.expose
    def login(self, function='index'):
        Page = '<form action="/signin?function='+ str(function) +'" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page
    
    @cherrypy.expose
    def signin(self, username, password, function='index'):
        salted = password + username
        hashed = hashlib.sha256(salted.encode()).hexdigest()
        result = urllib2.urlopen(
            central_server + "/report" +
            "?username=" + username +
            "&password=" + hashed +
            "&location=" + '2' +
            "&ip=" + socket.gethostbyname(socket.gethostname()) +
            "&port=" + "10004"
            )
        r = result.read()
        #pubkey and encoding required.
        if (r[0] == '0') :
            cherrypy.session['username'] = username
            cherrypy.session['password'] = hashed
            raise cherrypy.HTTPRedirect('/' + str(function))
        else :
            return "failed to logic due to " + r
          
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
