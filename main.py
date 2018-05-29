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
listen_port = 10002
my_location = '1'

central_server= "http://cs302.pythonanywhere.com"

import cherrypy
import sqlite3
import json
import urllib2
import pickle
import time
import socket
import Queue
import threading
from os.path import abspath
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
        last2 = ""
        try:
            Page += "Hello " + cherrypy.session['id'] + "!<br/><br/>"

            Page = '<form action="/send" method="post" enctype="multipart/form-data">'
            Page += 'To: <input type="text" name="destination"/><br/>'
            Page += 'Message: <input type="text" name="message"/><br/>'
            Page += '<input type="submit" value="Send"/></form>'

            last2 = '<form action="/onlineIndividual" method="post" enctype="multipart/form-data">'
            last2 += 'online: <input type="text" name="username"/><br/>'
            last2 += '<input type="submit" value="check"/></form>'
        
            Page += "Click here to list who is <a href='online'>online</a>.<br/>"
            last = "Click here to <a href='logoff'>log off</a>.<br/>"
        except KeyError, e: #There is no username
            if str(e) == "'id'":
                Page += "Click here to <a href='login'>login</a>.<br/>"
                
        Page += "Click here to list <a href='API'>API</a>.<br/>"
        Page += "Click here to list <a href='users'>Users</a>.<br/>"
        Page += last + last2
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
    def onlineIndividual(self, username):
        myname = cherrypy.session['username']
        password = cherrypy.session['password']
        location = cherrypy.session['location']
        ip = cherrypy.session['ip']
        port = cherrypy.session['port']
        key = cherrypy.session['key']
        address = self.getUserAddress(username ,myname, password, location, ip, port, key)
        if address == '3':
            return 3
        result = self.getUserAlive(address, myname)
        return result
        
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
        if (login[0] == '0') :
            
            result = self.getOnline(username, password)
            Page = "Here is the list who is online:<br/><br/>"
            
            connection = sqlite3.connect('data/online.db')
            c = connection.cursor()
            try :
                c.execute('''CREATE TABLE tasks
                     (username text, ip text, publicKey text, location real, LastLogin real, port real)''')
            except :
                c.execute('DELETE FROM tasks')
            connection.commit()
            r = result.read()
            data = json.loads(r)
            for i in data:
                for key, value in data[i].items():
                    Page += key + ': ' + value + ', '
                Page += '<br/><br/>'
                sql = '''INSERT INTO tasks(username, ip, publicKey, location, LastLogin, port)
                            VALUES(?,?,?,?,?,?)'''
                task = (
                    data[i].get('username',''),
                    data[i].get('ip',''),
                    data[i].get('publicKey',''),
                    data[i].get('location',''),
                    data[i].get('LastLogin',''),
                    data[i].get('port','')
                    )
                c.execute(sql,task)
                connection.commit()
                
            connection.close()
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
    
    reportTimer = None
    def doReport(self, username, password, location, ip, port, key):
        print 'reporting'
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
        result = urllib2.urlopen(req).read()
        if result[0] == '0':
            self.reportTimer = threading.Timer(60, self.doReport, [username, password, location, ip, port, key])
            self.reportTimer.setDaemon(True)
            self.reportTimer.start()
        return result
    
    
    @cherrypy.expose
    def login(self, function='index'):
        return file("media/LoginPage.html")

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
        
        Dict = {
                   "sender" : cherrypy.session['id'],
                   "destination" : destination,
                   "message" : message,
                   "stamp" : time.time()
               }
        json_Data = json.dumps(Dict)
        req = urllib2.Request(address + '/receiveMessage', json_Data, {'Content-Type': 'application/json'})
        result = urllib2.urlopen(req).read()
        
        if result == '0':
            if str(username) != str(destination):
                self.storeMessage(Dict)
                
            raise cherrypy.HTTPRedirect('/read')
        else :
            return result

    @cherrypy.expose
    def read(self):
        Page = ""
        connection = sqlite3.connect('data/message.db')
        c = connection.cursor()
        for row in c.execute('SELECT * FROM tasks ORDER BY stamp DESC LIMIT 10'):
            value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[4]))
            Page += "sender: " + row[1] + "<br/>"
            Page += "destination: " + row[2] + "<br/>"
            Page += "message: " + row[3] + "<br/>"
            Page += "time: " + str(value) + "<br/>"
            Page += "<br/>"
            print row
        connection.close()
        return Page
    
    # back node login server
    @cherrypy.expose
    def logoff(self):
        try:
            self.reportTimer.cancel()
        except:
            raise cherrypy.HTTPRedirect('/')
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
        if my_location == '1' or my_location == '0':
            ipnum = socket.gethostbyname(socket.gethostname())
        elif my_location == '2':
            ipnum = urllib2.urlopen('http://ip.42.pl/raw').read()
        ip = security.AES256encrypt(ipnum, login_pubkey)
        port = security.AES256encrypt(str(listen_port), login_pubkey)
        key = security.AES256encrypt(RSA1024_public ,login_pubkey)
        
        
        result = self.doReport(username, hashed, location, ip, port, key)
        if (result[0] == '0') :
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
        print input_data
        log = {}
        try:
           log = {
                   "sender" : input_data["sender"],
                   "destination" : input_data["destination"],
                   "message" : input_data["message"],
                   "stamp" : input_data["stamp"]
                }
        except:
           return '1'
        
        self.storeMessage(log);
        
        return '0'

    def storeMessage(self, log):
        connection = sqlite3.connect('data/message.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE tasks
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, destination text, message text, stamp real)''')
        except:
            pass
            
        task = (
            log.get("sender",''),
            log.get("destination",''),
            log.get("message",''),
            log.get("stamp",'')
            )
        
        sql = '''INSERT INTO tasks(sender, destination, message, stamp)
            VALUES(?,?,?,?)'''
                
        c.execute(sql,task)
        connection.commit()
        connection.close()

    def getUserAddress(self, User, username, password, location, ip, port, key):
        userip = None
        userport = None
        login = self.doReport(username, password, location, ip, port, key)
        if (login[0] == '0') :
            result = self.getOnline(username, password)            
            r = result.read()
            data = json.loads(r)
            for i in data:
                if data[i]['username'] == User:
                    userip = data[i]['ip']
                    userport = data[i]['port']
        if userip == None or userport == None:
            return '3'

        return 'http://' + userip + ':' + userport

    def getUserAlive(self, address, sender):
        req = urllib2.Request(address + '/ping?sender=' + sender)
        result = urllib2.urlopen(req)
        return result.read()
    
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/",
                        {'/media': {
                            'tools.staticdir.on': True,
                            'tools.staticdir.dir': abspath('./media')
                            }
                        }
                        )

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True
                            }
                            )

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
