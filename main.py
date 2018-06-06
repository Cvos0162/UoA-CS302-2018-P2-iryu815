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

central_server= "http://cs302.pythonanywhere.com"
data_key = 'f920f9a760c6f8142de9d57502c8d9ed'

import cherrypy
import sqlite3
import json
import urllib2
import urllib
import pickle
import time
import socket
import Queue
import threading
from os.path import abspath
import security
import text
import pyotp

class MainApp(object):

    totp = pyotp.TOTP("7BFIOWJ4CTPI6N4M")
    session = []
    session_keydic = { 'public':'',
               'private':''}
    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }
    #subscribe to log off when cherrypy stops
    def __init__(self):
        cherrypy.engine.subscribe('stop', self.logoff)
        
    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    # User nodes
    @cherrypy.expose
    def index(self):
        #header
        Page = '''<html>
  <head>
    <link rel="stylesheet" type="text/css" href="media/style.css"/>
  </head>
  <body>
'''
        #declare variable
        frame = ""
        buttons = ''
        
        try:
            name = cherrypy.session['id']

            buttons += '<div class="empty">'
            buttons += '<div class="buttons" >'
            buttons += '<form action="/logoff" method="post" enctype="multipart/form-data" align="top">'
            buttons += '<input type="submit" value="Log Off"/></form>'
            buttons += '</div>'
            
            buttons += '<div class="buttons" >'
            buttons += '<form action="/editProfile" method="post" enctype="multipart/form-data" align="top">'
            buttons += '<input type="submit" value="Edit Profile"/></form>'
            buttons += '</div>'
            
            frame = '''<div class="frame">
    <iframe src="/readFile"  align="left" width="40%" height="70%"></iframe>
    <iframe src="/read"  align="left" width="40%" height="70%"></iframe>
    <iframe src="/online" align="left" width="20%" height="70%"></iframe>
</div>
'''
            buttons += '<div class="buttons" >'
            buttons += '<form action="/send" method="post" enctype="multipart/form-data">'
            buttons += 'To: <input type="text" name="destination" required/><br/>'
            buttons += 'Message: <input type="text" name="message" required/><br/>'
            buttons += '<input type="submit" value="Send"/></form>'
            buttons += '</div>'
            
            buttons += '<div class="buttons" >'
            buttons += '<form action="/sendFile" method="post" enctype="multipart/form-data">'
            buttons += 'To: <input type="text" name = "destination" required/><br/>'
            buttons += '<input type="file" value="Select file" name="myfile" required/>'
            buttons += '<input type="submit" value="Send"/></form>'
            buttons += '</div>'
            buttons += '</div>'
            
            username = cherrypy.session['username']
            password = cherrypy.session['password']
            location = cherrypy.session['location']
            ip = cherrypy.session['ip']
            port = cherrypy.session['port']
            key = cherrypy.session['key']
            self.doReport(username, password, location, ip, port, key)
            
        except KeyError, e: #There is no username
            raise cherrypy.HTTPRedirect('/login')
        Page += frame + buttons+ '''</body>    
</html>
'''
        return Page

    @cherrypy.expose
    def API(self):
        Page = "Here is the of external API that we can use from cs302.pythonanywhere.com <br/><br/>"
        api = self.getAPI()
        return Page + api.read() + "<br/>Click here to go <a href='index'>home</a>.<br/>"

    def getAPI(self):
        return urllib2.urlopen(central_server + "/listAPI")
    
    @cherrypy.expose
    def users(self):
        Page = "Here is the of username listed in cs302.pythonanywhere.com <br/><br/>"
        user = self.getUser()
        return Page + user.read() + "<br/>Click here to go <a href='index'>home</a>.<br/>"

    def getUser(self):
        return urllib2.urlopen(central_server + "/listUsers")

    @cherrypy.expose
    def onlineIndividual(self, username):
        myname = cherrypy.session['username']
        address = self.getUserAddress(username)
        if address == '3':
            return 3
        result = self.getUserAlive(address, myname)
        return result
        
    @cherrypy.expose
    def online(self):
        print "getting online"
        username = ''
        password = ''
        Page = '''<head>
    <link rel="stylesheet" type="text/css" href="media/embedded.css"/>
    <base target="_parent" />
    <meta http-equiv="refresh" content="10">
</head>
<body>
'''
        try:
            username = cherrypy.session['username']
            password = cherrypy.session['password']
        except KeyError:
            pass
        result = self.getOnline(username, password)
        try:
            r = result.read()
            data = json.loads(r)
        except:
            return Page + 'login server is down'
        Page += "Here is the list who is online:<br/><br/>"

        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try :
            c.execute('''CREATE TABLE online
                 (username text PRIMARY KEY, ip text, publicKey text, location text, lastLogin text, port text)''')
        except :
            c.execute('DELETE FROM online')
        connection.commit()
        
        for i in data:
            sql = '''INSERT INTO online(username, ip, publicKey, location, lastLogin, port)
                    VALUES(?,?,?,?,?,?)'''
            task = (
                security.AES256encrypt(str(data[i].get('username','')), data_key),
                security.AES256encrypt(str(data[i].get('ip','')), data_key),
                security.AES256encrypt(str(data[i].get('publicKey','')), data_key),
                security.AES256encrypt(str(data[i].get('location','')), data_key),
                security.AES256encrypt(str(data[i].get('lastLogin','')), data_key),
                security.AES256encrypt(str(data[i].get('port','')), data_key)
                )
            c.execute(sql,task)
            connection.commit()

        for row in c.execute('SELECT * FROM online ORDER BY username ASC'):
            value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(security.AES256decrypt(row[4], data_key))))
            Page += "<div class='message'>username: <a href='/readProfile?username="+ text.html_escape(security.AES256decrypt(row[0], data_key))+"'>" + text.html_escape(security.AES256decrypt(row[0], data_key)) + "</a><br/>"
            Page += "lastLogin: " + text.html_escape(str(value)) + "<br/>"
            Page += "<br/></div>"
        
            
        connection.close()
        
        return Page

    def getOnline(self, username, password):
        try:
            req = urllib2.Request(
                    central_server + "/getList" +
                    "?username=" + username +
                    "&password=" + password +
                    "&enc=" + '1'+
                    "&json=" + security.AES256encrypt('1', '150ecd12d550d05ad83f18328e536f53')
                    )
            result = urllib2.urlopen(req)
        except:
            result = 0
        return result
    
    reportTimer = None
    def doReport(self, username, password, location, ip, port, key):
        print 'reporting'
        try:
            self.reportTimer.cancel()
        except:
            pass
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
    def enclogin(self, username, password, function='index'):
        user = security.AES256encrypt(username, data_key)
        pas = security.AES256encrypt(password, data_key)
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE loggedin
                    (username TEXT PRIMARY KEY)''')
            connection.commit()
        except:
            pass
        data = 0
        try:
            data = c.execute('''SELECT COUNT(*) FROM loggedin
                            WHERE username = ?''', (username, )).fetchone()[0]
            print data
            print username
        except:
            pass
        
        show = '1'
        if data != 0:
            show = '0'
        connection.close()
        raise cherrypy.HTTPRedirect('/login2FA?username='+user+'&password='+pas+'&show='+show)
    
    @cherrypy.expose
    def login2FA(self, username, password, show, function='index'):
        Page = '''<head>
    <link rel="stylesheet" type="text/css" href="media/style.css"/>
    </head>
    <body>
'''
        add = ('https://chart.googleapis.com/chart?'
            + 'cht='
            + 'qr'
            + '&chs=' 
            + str(400)
            + '&chl='
            + security.percentEncode(pyotp.totp.TOTP('7BFIOWJ4CTPI6N4M').provisioning_uri("@COMPSYS302", issuer_name="Secure App"))
               )
            
        Page += '<div class="MFA" align = "center">'
        if str(show) == '1':
            Page += '<img src="'+add+'"/>'
        else:
            Page += '<img src="https://media.giphy.com/media/GR81UZYyhN3Ww/giphy.gif">'
        Page += '<form action="/login2FAsignin">'
        Page += '<h2 align = "left">2FA Code</h2>'
        Page += '<input name="username" type="hidden" value="'+username+'">'
        Page += '<input name="password" type="hidden" value="'+password+'">'
        Page += '''
        <input type="text" name="code" placeholder="code" required>
        <hr>
        <input type="submit" value="Submit">
      </form></div>
'''
        
        return Page

    @cherrypy.expose
    def login2FAsignin(self, username, password, code):
        print self.totp.now()
        print code
        if self.totp.now() == code:
            user = security.AES256decrypt(username, data_key)
            pas = security.AES256decrypt(password, data_key)
            raise cherrypy.HTTPRedirect('/signin?username='+user+'&password='+pas)
        else:
            return '''<head>
<meta http-equiv="refresh" content="5; URL=/login">
</head>
<body>
'''+'falied!'

    @cherrypy.expose
    def send(self, destination, message):
        address = self.getUserAddress(destination)
        Dict = {
                   "sender" : cherrypy.session['id'],
                   "destination" : destination,
                   "message" : text.emojify(message),
                   "stamp" : time.time()
               }
        json_Data = json.dumps(Dict)
        result = ''
        try:
            req = urllib2.Request(address + '/receiveMessage', json_Data, {'Content-Type': 'application/json'})
            result = urllib2.urlopen(req).read()
        except:
            return 'cannot reach the target'
        if result[0] == '0':
            if cherrypy.session['id'] !=  destination :
                self.storeMessage(Dict)
                
            raise cherrypy.HTTPRedirect('/')
        else :
            return result

    @cherrypy.expose
    def sendFile(self, destination, myfile):
        data = myfile.file.read()
        if len(data) > 5242880:
            return 'file size is too large'

        address = self.getUserAddress(destination)

        dic = {
            'sender' : cherrypy.session['id'],
            'destination' : destination,
            'file' : security.base64Encode(data),
            'filename' : str(myfile.filename),
            'content_type' : str(myfile.content_type),
            'stamp' : time.time()
            }
        json_Data = json.dumps(dic)
        try:
            req = urllib2.Request(address + '/receiveFile', json_Data, {'Content-Type': 'application/json'})
            result = urllib2.urlopen(req).read()
        except:
            return 'cannot reach the target'
        if result[0] == '0':
            raise cherrypy.HTTPRedirect('/')
        else :
            return result

    @cherrypy.expose
    def read(self):
        print 'reading message'
        Page = '''<head>
    <link rel="stylesheet" type="text/css" href="media/embedded.css"/>
    <meta http-equiv="refresh" content="10">
</head>
<body>
'''
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE message
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, destination text, message text, stamp text)''')
        except:
            pass
        
        for row in c.execute('SELECT * FROM message ORDER BY id DESC LIMIT 10'):
            stamp = security.AES256decrypt(row[4], data_key)
            value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(stamp)))
            user = security.AES256decrypt(row[1], data_key)
            dest = security.AES256decrypt(row[2], data_key)
            message = security.AES256decrypt(row[3], data_key).decode('utf-8')
            Page += "<div class='message'>sender: " + text.html_escape(user) + "<br/>"
            Page += "destination: " + text.html_escape(dest) + "<br/>"
            Page += "message: " + text.html_escape(message) + "<br/>"
            Page += "time: " + text.html_escape(str(value)) + "<br/>"
            Page += '<a href="/requestDelete?sender='+text.html_escape(user)+'&destination='+text.html_escape(dest)+'&message='+ text.html_escape(message) + '&stamp='+ text.html_escape(stamp) +'">delete</a><br/>'
            Page += '<a href="/requestAcknowledge?sender='+text.html_escape(cherrypy.session['id'])+'&destination='+text.html_escape(user) + '&stamp=' + text.html_escape(stamp) + '&message=' + text.html_escape(message)+ '">acknowledge</a><br/>'
            Page += "<br/></div>"
        connection.close()
        
        return Page

    @cherrypy.expose
    def readFile(self):
        print 'reading file'
        Page = '''<head>
  <link rel="stylesheet" type="text/css" href="media/embedded.css"/>
  <base target="_parent" />
  <meta http-equiv="refresh" content="30">
</head>
<body>'''
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE file
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, destination text, filename text, content_type text, stamp real)''')
        except:
            pass
        
        for row in c.execute('SELECT * FROM file ORDER BY id DESC LIMIT 10'):
            value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(security.AES256decrypt(row[5], data_key))))
            Page += "<div class='message'>sender: " + text.html_escape(security.AES256decrypt(row[1],data_key)) + "<br/>"
            Page += "destination: " + text.html_escape(security.AES256decrypt(row[2], data_key)) + "<br/>"
            Page += "time: " + text.html_escape(str(value)) + "<br/>"
            Page += 'filename: <a href="download/'+text.html_escape(security.AES256decrypt(row[3], data_key))+'">' + text.html_escape(security.AES256decrypt(row[3], data_key)) + '</a><br/>'
            Page += '<object data="' + 'download/' + text.html_escape(security.AES256decrypt(row[3],data_key)) + '" type="' + text.html_escape(security.AES256decrypt(row[4], data_key)) + '" max-width="400px" height="auto">'
            Page += '</object>'
            Page += "</div><br/>"
        connection.close()
        
        return Page
    @cherrypy.expose
    def editProfile(self):
        Page = '''<head>
  <link rel="stylesheet" type="text/css" href="media/embedded.css"/>
  <base target="_parent" />
</head>
<body>'''
        Page += '<form action="/saveProfile" method="post" enctype="multipart/form-data">'
        Page += 'Name: <input type="text" name = "name"/><br/>'
        Page += 'Position: <input type="text" name="position"/><br/>'
        Page += 'description: <input type="text" name="description"/><br/>'
        Page += 'location: <input type="text" name="location"/><br/>'
        Page += 'picture: <input type="file" name="f" value="picture" accept="image/*"/><br/>'
        Page += '<input type="submit" value="Done"/></form>'
        return Page

    @cherrypy.expose
    def saveProfile(self, name='', position='', description='', location='', f=None):
        log = {}
        arg = False
        if name != '':
            log['fullname'] = name
            arg = True
        if position != '':
            log['position'] = position
            arg = True
        if description != '':
            log['description'] = description
            arg = True
        if location != '':
            log['location'] = location
            arg = True
        try:
            pic = open("profile/" + cherrypy.session['id'] + "." + str(f.content_type).replace("image/",''), "wb")
            pic.write(f.file.read())
            pic.close()
            log['picture'] = "/profile/"+cherrypy.session['id']+"."+ str(f.content_type).replace("image/",'')
            arg = True
        except:
            pass
        if arg == True:
            log['username'] = cherrypy.session['id']
            log['lastUpdated'] = time.time()
            self.storeProfile(log)
        raise cherrypy.HTTPRedirect('/readProfile?username=' + cherrypy.session['id'])
            
    @cherrypy.expose
    def readProfile(self, username):
        Page = '''<head>
    <link rel="stylesheet" type="text/css" href="media/embedded.css"/>
</head>
<body>
'''
        try:
            cherrypy.session['id']
        except:
            raise cherrypy.HTTPRedirect('/login')
        if username != cherrypy.session['id']:
            try:
                print 'calling'
                address = self.getUserAddress(username)
                Dict = {
                   "profile_username" : username,
                   "sender" : cherrypy.session['id'],
               }
                json_Data = json.dumps(Dict)
                req = urllib2.Request(address + '/getProfile', json_Data, {'Content-Type': 'application/json'})
                result = urllib2.urlopen(req).read()
                log = json.loads(result)
                try:
                    file_name = log['picture'].split('/')[-1]
                    file_content = file_name.split('.')[-1]
                    direc = 'profile/'+username+'.'+file_content
                    result = urllib.urlretrieve(log['picture'],direc)
                    log['picture'] = direc
                except:
                    pass
                log['username'] = username
                self.storeProfile(log)
            except:
                pass
            

        try:
            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            row = c.execute('SELECT * FROM profile WHERE username = ?', (security.AES256encrypt(str(username), data_key),)).fetchone()
            value = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(security.AES256decrypt(row[6], data_key))))
            Page += "<div class='message'> Username: " + text.html_escape(security.AES256decrypt(row[0], data_key)) + "<br/>"
            try:
                Page += "Name: " + text.html_escape(security.AES256decrypt(row[1], data_key)) + "<br/>"
            except:
                pass
            try:
                Page += "Position: " + text.html_escape(security.AES256decrypt(row[2], data_key)) + "<br/>"
            except:
                pass
            try:
                Page += "Description: " + text.html_escape(security.AES256decrypt(row[3], data_key)) + "<br/>"
            except:
                pass
            try:
                Page += "Location: " + text.html_escape(security.AES256decrypt(row[4], data_key)) + "<br/>"
            except:
                pass
            try:
                Page += '<img class="profilepic" src="'+ text.html_escape(security.AES256decrypt(row[5], data_key)) + '" height="auto" alt="image unavailable">'
                Page += '</img><br/>'
            except:
                pass
            try:
                Page += "Last Update date: " + str(value) + "<br/>"
            except:
                pass
            Page += "</div><br/>"
            connection.close()
        except :
            Page += 'cannot find a profile of this username'
        return Page + '''<div class="buttons"><form action="/" method="GET" enctype="multipart/form-data">
<input type="submit" value="GO Home"/></form></div>'''

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getProfile(self):
        input_data = cherrypy.request.json
        try:
            profile_username = input_data['profile_username']
            sender = input_data['sender']
        except:
            return '1'
        log = {}
        try:
            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            row = c.execute('SELECT * FROM profile WHERE username = ?', (security.AES256encrypt(profile_username, data_key), )).fetchone()
            log['lastUpdated'] = security.AES256decrypt(row[6], data_key)
            log['fullname'] = security.AES256decrypt(row[1], data_key)
            log['position'] = security.AES256decrypt(row[2], data_key)
            log['description'] = security.AES256decrypt(row[3], data_key)
            log['location'] = security.AES256decrypt(row[4], data_key)
            ipnum = ''
            localip = socket.gethostbyname(socket.gethostname())
            publicip = urllib2.urlopen('http://ip.42.pl/raw').read()
            if localip.find('10.103',0 ,6) != -1:
                ipnum = localip
            elif localip.find('172.23',0 ,6) != -1:
                ipnum = localip
            else:
                ipnum = publicip

            log['picture'] = 'http://'+ ipnum+':'+ str(listen_port) +security.AES256decrypt(row[5], data_key)

            connection.close()
        except:
            log['lastUpdated'] = ''
            log['fullname'] = ''
            log['position'] = ''
            log['description'] = ''
            log['location'] = ''
            log['picture'] = ''

        return json.dumps(log)

    def storeProfile(self, log):
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE profile
                (username text primary key,
                fullname text,
                position text,
                description text,
                location text,
                picture text,
                lastUpdated text)''')
            connection.commit()
        except:
            pass

        print log
        username = security.AES256encrypt(log['username'], data_key)
        try:
            data = c.execute('''SELECT count(*) FROM profile
                            WHERE username = ?''', (username, )).fetchone()[0]
            if data==0:
                c.execute('''INSERT INTO profile(username, lastUpdated)
                            VALUES(?,?)''',
                      (
                          username,
                          security.AES256encrypt(str(log['lastUpdated']), data_key)
                          )
                      )
                connection.commit()
            else:
                c.execute('''UPDATE profile
                                SET lastUpdated = ? WHERE username = ?''',
                          (
                              security.AES256encrypt(str(log['lastUpdated']), data_key),
                              username
                              )
                          )
                connection.commit()
        except:
            pass
        
        try:
            c.execute('''UPDATE profile
                            SET fullname = ? WHERE username = ?''',
                      (
                          security.AES256encrypt(log['fullname'], data_key),
                          username
                          )
                      )
            connection.commit()
        except:
            pass
        
        try:
            c.execute('''UPDATE profile
                            SET position = ? WHERE username = ?''',
                      (
                          security.AES256encrypt(log['position'], data_key),
                          username
                          )
                      )
            connection.commit()
        except:
            pass
        try:
            c.execute('''UPDATE profile
                            SET description = ? WHERE username = ?''',
                      (
                          security.AES256encrypt(log['description'], data_key),
                          username
                          )
                      )
            connection.commit()
        except:
            pass
        
        try:
            c.execute('''UPDATE profile
                            SET location = ? WHERE username = ?''',
                      (
                          security.AES256encrypt(log['location'], data_key),
                          username
                          )
                      )
            connection.commit()
        except:
            pass

        try:
            c.execute('''UPDATE profile
                            SET picture = ? WHERE username = ?''',
                      (
                          security.AES256encrypt(log['picture'], data_key),
                          username
                          )
                      )
            connection.commit()
        except:
            pass

        connection.commit()
        connection.close()

    # back node login server
    @cherrypy.expose
    def logoff(self):
        print 'logging off!!'
        result = ''
        for tup in self.session:
            username = tup[0]
            password = tup[1]
            try:
                req = urllib2.Request(
                    central_server + "/logoff" +
                    "?username=" + username +
                    "&password=" + password +
                    "&enc=" + '1'
                    )
                result = urllib2.urlopen(req).read()
            except:
                pass
        try :
            cherrypy.lib.sessions.expire()
        except KeyError, e:
            if str(e) != "'online'" :            
                raise cherrypy.HTTPRedirect('/')
        try:
            self.reportTimer.cancel()
        except:
            raise cherrypy.HTTPRedirect('/login')
        raise cherrypy.HTTPRedirect('/')
    
    @cherrypy.expose
    def signin(self, username, password, function='index'):

        user_id = username

        login_pubkey = '150ecd12d550d05ad83f18328e536f53'
        keydic = security.RSAkeygen(1024)
        self.session_keydic['public'] = keydic['public']
        self.session_keydic['private'] = keydic['private']
        hashed = security.SHA256hash(password, username)
        username = security.AES256encrypt(username, login_pubkey)
        hashed = security.AES256encrypt(hashed, login_pubkey)
        ipnum = ''
        location = ''
        localip = socket.gethostbyname(socket.gethostname())
        publicip = urllib2.urlopen('http://ip.42.pl/raw').read()
        if localip.find('10.103',0 ,6) != -1:
            location = '0'
            ipnum = localip
        elif localip.find('172.23',0 ,6) != -1:
            location = '1'
            ipnum = localip
        else:
            location = '2'
            ipnum = publicip
        location = security.AES256encrypt(location, login_pubkey)
        
        ip = security.AES256encrypt(ipnum, login_pubkey)
        port = security.AES256encrypt(str(listen_port), login_pubkey)
        key = security.AES256encrypt(self.session_keydic['public'] ,login_pubkey)
        
        
        result = self.doReport(username, hashed, location, ip, port, key)
        if (result[0] == '0') :
            tup = (username, hashed)
            self.session.append(tup)
            cherrypy.session['id'] = user_id
            cherrypy.session['username'] = username
            cherrypy.session['password'] = hashed
            cherrypy.session['location'] = location
            cherrypy.session['ip'] = ip
            cherrypy.session['port'] = port
            cherrypy.session['key'] = key

            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            try:
                c.execute('''CREATE TABLE loggedin
                                            (username TEXT PRIMARY KEY)''')
                connection.commit()
            except:
                pass
            try:
                c.execute('''INSERT INTO loggedin(username)
                                            VALUES(?)''', (user_id,))
                connection.commit()
            except:
                pass
            connection.close()
        
            
            raise cherrypy.HTTPRedirect('/' + str(function))
        else :
            return "failed to logic due to " + result

    # back node p2p server
    @cherrypy.expose
    def ping(self, sender):
        return '0'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getPublicKey(self):
        input_data = cherrypy.request.json
        error = 0
        try:
            input_data['sender']
            input_data['username']
        except:
            error = 1
        pubkey = ''
        if error == 0:
            pubkey = self.session_keydic['public']
        dic = {'error': error, 'pubkey':pubkey}
        output = json.dumps(dic)
        return output

    @cherrypy.expose
    def requestAcknowledge(self, sender, stamp, destination, message):
        Page = '''<head>
<meta http-equiv="refresh" content="5; URL=/read">
</head>
<body>
'''
        dic ={
                'sender':sender,
                'stamp':stamp,
                'destination':destination,
                'hashing':3,
                'hash': security.SHA512hash(message, sender)
            }
        add = self.getUserAddress(destination)
        result = ''
        try:
            req = urllib2.Request(add + '/acknowledge', json.dumps(dic), {'Content-Type': 'application/json'})
            result = json.loads(urllib2.urlopen(req).read())
        except:
            return Page + 'not acknowledged'
        if str(result)[0] == '0':
            return Page + 'acknowledged'
        else:
            return Page + 'not acknowledged'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def acknowledge(self):
        input_data = cherrypy.request.json
        sender = ''
        stamp = ''
        destination = ''
        hashing = ''
        given_hash = ''
        try:
            sender = input_data['sender']
            stamp = input_data['stamp']
            destination = input_data['destination']
            hashing = input_data['hashing']
            given_hash = input_data['hash']
        except:
            return '1'
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        message = ''
        try:
            
            arg1 = security.AES256encrypt(destination, data_key)
            arg2 = security.AES256encrypt(sender, data_key)
            arg3 = security.AES256encrypt(str(stamp), data_key)
            result = c.execute('SELECT * FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                            (
                                arg1, arg2, arg3,
                                )
                            ).fetchone()
            message = security.AES256decrypt(result[3], data_key)
            connection.close()
        except:
            return '4'
        hashed = ''
        if hashing == 0:
            given_hash = ''
        elif hashing == 1:
            hashed = security.SHA256hash(message)
        elif hashing == 2:
            hashed = security.SHA256hash(message, sender)
        elif hashing == 3:
            hashed = security.SHA512hash(message, sender)
        elif hashing == 4:
            hashed = security.bcryptHash(message, sender)
        elif hashing == 5:
            hashed = security.scryptHash(message, sender)
        
        if hashed != given_hash:
            return '7'
        else:
            return '0'
        
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def handshake(self):
        input_data = cherrypy.request.json
        message = ''
        sender = ''
        destination = ''
        encryption = ''
        decryptionKey = ''
        error = 0
        try:
            message = input_data['message']
            sender = input_data['sender']
            destination = input_data['destination']
            encryption = input_data['encryption']
        except:
            error = 1
        try:
            if encryption == 1:
                message = security.XORdecrypt(message,'10010110')
            elif encryption == 2:
                message = security.AES256decrypt(message,'41fb5b5ae4d57c5ee528adb078ac3b2e')
            elif encryption == 3:
                key = security.RSAimportKey(self.session_keydic['private'])
                message = security.RSAdecrypt(message, key)
            elif encryption == 4 or encryption == 5:
                key = security.RSAimportKey(self.session_keydic['private'])
                decryptionKey = security.RSAdecrypt(input_data['decryptionKey'], key)
                message = security.AES256decrypt(message, decryptionKey)
        except:
            error = 1
        data = json.dumps({'error':error, 'message':message})
        return data

    @cherrypy.expose
    def requestDelete(self, sender, destination, message, stamp):
        Page = '''<head>
<meta http-equiv="refresh" content="5; URL=/read">
</head>
<body>
'''
        if cherrypy.session['id'] == sender and sender == destination:
            try:
                connection = sqlite3.connect('data/data.db')
                c = connection.cursor()
                arg1 = security.AES256encrypt(sender, data_key)
                arg2 = security.AES256encrypt(destination, data_key)
                arg3 = security.AES256encrypt(str(stamp), data_key)
                c.execute('DELETE FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                      (
                         arg1, arg2, arg3,
                          )
                      )
                connection.commit()
                connection.close()
            except:
                pass
            raise cherrypy.HTTPRedirect('/read')
        address = ''
        if cherrypy.session['id'] != destination :
            address = self.getUserAddress(destination)
        else:
            address = self.getUserAddress(sender)
        result1 = ''
        pubkey = ''
        try:
            print 'trying to get pubkey'
            if cherrypy.session['id'] != destination :
                req = urllib2.Request(address + '/getPublicKey', json.dumps({'sender':cherrypy.session['id'],'username':destination}), {'Content-Type': 'application/json'})
            else :
                req = urllib2.Request(address + '/getPublicKey', json.dumps({'sender':cherrypy.session['id'],'username':sender}), {'Content-Type': 'application/json'})
                
            result1 = json.loads(urllib2.urlopen(req).read())
            print result1
            if str(result1['error'])[0] == '0':
                print 'getPublicKey is safe'
                pubkey = result1['pubkey']
            else :
                if cherrypy.session['id'] != destination :
                    pubkey = self.getUserPubkey(destination)
                else :
                    pubkey = self.getUserPubkey(sender)
        except:
            print 'cannot reach the target'
            if cherrypy.session['id'] != destination :
                pubkey = self.getUserPubkey(destination)
            else :
                pubkey = self.getUserPubkey(sender)
        print pubkey
        if pubkey == '':
            return Page + 'pubkey is not available'
        key = security.RSAimportKey(pubkey)
        
        try:
            print 'trying to handshake'
            if cherrypy.session['id'] != destination :
                req = urllib2.Request(address + '/handshake',
                                   json.dumps({
                                      'message':security.RSAencrypt('this is message',key),
                                      'sender':cherrypy.session['id'],
                                      'destination':destination,
                                      'encryption':3
                                      }), {'Content-Type': 'application/json'})
            else:
                req = urllib2.Request(address + '/handshake',
                                   json.dumps({
                                      'message':security.RSAencrypt('this is message',key),
                                      'sender':cherrypy.session['id'],
                                      'destination':sender,
                                      'encryption':3
                                      }), {'Content-Type': 'application/json'})
            result3 = json.loads(urllib2.urlopen(req).read())
            print result3
            if str(result3['error'])[0] == '0':
                if result3['message'] != 'this is message':
                    return Page + 'this node does not support decryption, unsafe to request delete'
        except:
            return Page + 'this node does not support handshake'
        dic = {}
        if cherrypy.session['id'] == destination:
            dic = {
                'sender' : cherrypy.session['id'],
                'destination' : sender,
                'stamp' : security.RSAencrypt(str(stamp),key),
                'hashing' : 2,
                'hash' : security.RSAencrypt(security.SHA256hash(message, cherrypy.session['id']), key),
                'encryption' : 3
                }
        else :
            dic = {
                'sender' : cherrypy.session['id'],
                'destination' : destination,
                'stamp' : security.RSAencrypt(str(stamp),key),
                'hashing' : 2,
                'hash' : security.RSAencrypt(security.SHA256hash(message, cherrypy.session['id']), key),
                'encryption' : 3
                }
        print security.SHA256hash(message, sender)
        print str(stamp)
        print dic
        json_Data = json.dumps(dic)
        result2 = ''
        try:
            req = urllib2.Request(address + '/acknowledgeDelete', json_Data, {'Content-Type': 'application/json'})
            result2 = urllib2.urlopen(req).read()
        except:
            return Page + 'cannot reach the target'
        print result2
        if str(result2)[0] == '0':
            try:
                connection = sqlite3.connect('data/data.db')
                c = connection.cursor()
                arg1 = security.AES256encrypt(sender, data_key)
                arg2 = security.AES256encrypt(destination, data_key)
                arg3 = security.AES256encrypt(str(stamp), data_key)
                c.execute('DELETE FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                      (
                         arg1, arg2, arg3,
                          )
                      )
                connection.commit()
                connection.close()
            except:
                pass
            raise cherrypy.HTTPRedirect('/read')
        else:
            return Page + 'could not delete the message'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def acknowledgeDelete(self):
        input_data = cherrypy.request.json
        sender = ''
        destination = ''
        stamp = ''
        hashing = ''
        givenHash = ''
        encryption = ''
        dataMatching = False
        try:
            sender = input_data["sender"]
            destination = input_data["destination"]
            stamp = input_data["stamp"]
            hashing = input_data["hashing"]
            givenHash = input_data['hash']
            encryption = input_data['encryption']
        except:
            return '1'
        try:
            if encryption == 1 or encryption == 2:
                return '1'
            elif input_data['encryption'] == 3:
                key = security.RSAimportKey(self.session_keydic['private'])
                givenHash = security.RSAdecrypt(givenHash, key)
                stamp = security.RSAdecrypt(stamp, key)
            elif input_data['encryption'] == 4 or input_data['encryption'] == 5:
                key = security.RSAimportKey(self.session_keydic['private'])
                decryptionKey = security.RSAdecrypt(input_data['decryptionKey'], key)
                givenHash = security.AES256decrypt(givenHash, decryptionKey)
                stamp = security.AES256decrypt(stamp, decryptionKey)
        except:
            return '1'
        #find matching stamp sender destination
        message = ''
        arg1 = ''
        arg2 = ''
        arg3 = ''
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        error1 = ''
        error2 = ''
        print sender
        print destination
        print stamp
        print givenHash
        try:
            arg1 = security.AES256encrypt(sender, data_key)
            arg2 = security.AES256encrypt(destination, data_key)
            arg3 = security.AES256encrypt(str(stamp), data_key)
            result = c.execute('SELECT * FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                            (
                                arg1, arg2, arg3,
                                )
                            ).fetchone()
            message = security.AES256decrypt(result[3], data_key)
            connection.close()
        except:
            error1 = '4'
        try:
            arg1 = security.AES256encrypt(sender, data_key)
            arg2 = security.AES256encrypt(destination, data_key)
            arg3 = security.AES256encrypt(str(stamp), data_key)
            result = c.execute('SELECT * FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                            (
                                arg2, arg1, arg3,
                                )
                            ).fetchone()
            message = security.AES256decrypt(result[3], data_key)
            connection.close()
        except:
            error2 = '4'
        if error1 == '4' and error2 == '4':
            return '4'
        
        try:
            hashed = ''
            if hashing == 0:
                givenHash = ''
            elif hashing == 1:
                hashed = security.SHA256hash(message)
            elif hashing == 2:
                hashed = security.SHA256hash(message, sender)
            elif hashing == 3:
                hashed = security.SHA512hash(message, sender)
            elif hashing == 4:
                hashed = security.bcryptHash(message, sender)
            elif hashing == 5:
                hashed = security.scryptHash(message, sender)
            if hashed != givenHash:
                return '7'
            else :        
                dataMatching = True
        except:
            return '7'
        if dataMatching == True:
            print 'deleting from destination'
            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            try:
                c.execute('DELETE FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                      (
                          arg1, arg2, arg3,
                          )
                      )
            except:
                pass
            try:
                c.execute('DELETE FROM message WHERE sender = ? AND destination = ? AND stamp = ?',
                      (
                          arg2, arg1, arg3,
                          )
                      )
            except:
                pass
            connection.commit()
            connection.close()
            return '0'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        input_data = cherrypy.request.json
        sender = ''
        destination = ''
        message = ''
        stamp = ''
        givenHash = ''
        try:
            sender = input_data["sender"]
            destination = input_data["destination"]
            message = input_data["message"]
            stamp = input_data["stamp"]
        except:
            return '1'
        try:
            if input_data['encryption'] == 1:
                message = security.XORdecrypt(message,'10010110')
                stamp = security.XORdecrypt(stamp,'10010110')
                givenHash = security.XORdecrypt(input_data.get('hash',''),'10010110')
            elif input_data['encryption'] == 2:
                message = security.AES256decrypt(message,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                stamp = security.AES256decrypt(stamp,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                givenHash = security.AES256decrypt(input_data.get('hash',''),'41fb5b5ae4d57c5ee528adb078ac3b2e')
            elif input_data['encryption'] == 3:
                key = security.RSAimportKey(self.session_keydic['private'])
                message = security.RSAdecrypt(message, key)
                stamp = security.RSAdecrypt(stamp, key)
                givenHash = security.RSAdecrypt(input_data.get('hash',''), key)
            elif input_data['encryption'] == 4 or input_data['encryption'] == 5:
                key = security.RSAimportKey(self.session_keydic['private'])
                decryptionKey = security.RSAdecrypt(input_data['decryptionKey'], key)
                message = security.AES256decrypt(message, decryptionKey)
                stamp = security.AES256decrypt(stamp, decryptionKey)
                givenHash = security.AES256decrypt(input_data.get('hash',''), decryptionKey)
        except:
            pass
        try:
            hashed = ''
            if input_data['hashing'] == 0:
                givenHash = ''
            elif input_data['hashing'] == 1:
                hashed = security.SHA256hash(message)
            elif input_data['hashing'] == 2:
                hashed = security.SHA256hash(message, sender)
            elif input_data['hashing'] == 3:
                hashed = security.SHA512hash(message, sender)
            elif input_data['hashing'] == 4:
                hashed = security.bcryptHash(message, sender)
            elif input_data['hashing'] == 5:
                hashed = security.scryptHash(message, sender)
            if hashed != givenHash:
                return '7'
        except:
            pass
        log = {
                "sender" : sender,
                "destination" : destination,
                "message" : message,
                "stamp" : stamp
            }

        self.storeMessage(log)
        return '0'

    def storeMessage(self, log):
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE message
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, destination text, message text, stamp text)''')
        except:
            pass
            
        task = (
            security.AES256encrypt(log.get("sender",''), data_key),
            security.AES256encrypt(log.get("destination",''), data_key),
            security.AES256encrypt(log.get("message",'').encode('utf-8').strip(),data_key),
            security.AES256encrypt(str(log.get("stamp",'')), data_key)
            )
        
        sql = '''INSERT INTO message(sender, destination, message, stamp)
            VALUES(?,?,?,?)'''
                
        c.execute(sql,task)
        connection.commit()
        connection.close()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        input_data = cherrypy.request.json
        sender = ''
        destination = ''
        content = ''
        filename = ''
        content_type = ''
        stamp = ''
        givenHash = ''
        try:
            sender = input_data["sender"]
            destination = input_data["destination"]
            content = input_data["file"]
            filename = input_data["filename"]
            content_type = input_data["content_type"]
            stamp = input_data["stamp"]
        except:
            return '1'

        try:
            if input_data['encryption'] == 1:
                content = security.XORdecrypt(content,'10010110')
                filename = security.XORdecrypt(filename,'10010110')
                content_type = security.XORdecrypt(content_type,'10010110')
                stamp = security.XORdecrypt(stamp,'10010110')
                givenHash = security.XORdecrypt(input_data.get('hash',''),'10010110')
            elif input_data['encryption'] == 2:
                content = security.AES256decrypt(content,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                filename = security.AES256decrypt(filename,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                content_type = security.AES256decrypt(content_type,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                stamp = security.AES256decrypt(stamp,'41fb5b5ae4d57c5ee528adb078ac3b2e')
                givenHash = security.AES256decrypt(input_data.get('hash',''),'41fb5b5ae4d57c5ee528adb078ac3b2e')
            elif input_data['encryption'] == 3:
                key = security.RSAimportKey(self.session_keydic['private'])
                content = security.RSAdecrypt(content, key)
                filename = security.RSAdecrypt(filename, key)
                content_type = security.RSAdecrypt(content_type, key)
                stamp = security.RSAdecrypt(stamp, key)
                givenHash = security.RSAdecrypt(input_data.get('hash',''), key)
            elif input_data['encryption'] == 4 or input_data['encryption'] == 5:
                key = security.RSAimportKey(self.session_keydic['private'])
                decryptionKey = security.RSAdecrypt(input_data['decryptionKey'], key)
                content = security.AES256decrypt(content, decryptionKey)
                filename = security.AES256decrypt(filename, decryptionKey)
                content_type = security.AES256decrypt(content_type, decryptionKey)
                stamp = security.AES256decrypt(stamp, decryptionKey)
                givenHash = security.AES256decrypt(input_data.get('hash',''), decryptionKey)
        except:
            pass
        try:
            hashed = ''
            if input_data['hashing'] == 0:
                givenHash = ''
            elif input_data['hashing'] == 1:
                hashed = security.SHA256hash(message)
            elif input_data['hashing'] == 2:
                hashed = security.SHA256hash(message, sender)
            elif input_data['hashing'] == 3:
                hashed = security.SHA512hash(message, sender)
            elif input_data['hashing'] == 4:
                hashed = security.bcryptHash(message, sender)
            elif input_data['hashing'] == 5:
                hashed = security.scryptHash(message, sender)
            if hashed != givenHash:
                return '7'
        except:
            pass
        log = {}
        try:
           log = {
                   "sender" : input_data["sender"],
                   "destination" : input_data["destination"],
                   "filename" : input_data["filename"],
                   "content_type" : input_data["content_type"],
                   "stamp" : input_data["stamp"]
                }
        except:
           return '1'

        self.storeFilelog(log)

        f = open("download/"+log["filename"], "wb")
        f.write(security.base64Decode(security.percentDecode(content)))
        f.close()

        return '0'

    def storeFilelog(self, log):
        connection = sqlite3.connect('data/data.db')
        c = connection.cursor()
        try:
            c.execute('''CREATE TABLE file
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, sender text, destination text, filename text, content_type text, stamp text)''')
        except:
            pass
            
        task = (
            security.AES256encrypt(log.get("sender",''), data_key),
            security.AES256encrypt(log.get("destination",''), data_key),
            security.AES256encrypt(log.get("filename",''), data_key),
            security.AES256encrypt(log.get("content_type", ''), data_key),
            security.AES256encrypt(str(log.get("stamp",'')), data_key)
            )
        
        sql = '''INSERT INTO file(sender, destination, filename, content_type, stamp)
            VALUES(?,?,?,?,?)'''
                
        c.execute(sql,task)
        connection.commit()
        connection.close()

    def getUserAddress(self, user):
        userip = ''
        userport = ''
        try:
            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            row = c.execute('SELECT * FROM online WHERE username = ?', (security.AES256encrypt(user,data_key), )).fetchone()
            userip = security.AES256decrypt(row[1], data_key)
            userport = security.AES256decrypt(row[5], data_key)
            connection.close()
        except:
            return ''
        return 'http://' + userip + ':' + userport

    def getUserAlive(self, address, sender):
        req = urllib2.Request(address + '/ping?sender=' + sender)
        result = urllib2.urlopen(req)
        return result.read()

    def getUserPubkey(self, user):
        pubkey = ''
        try:
            connection = sqlite3.connect('data/data.db')
            c = connection.cursor()
            row = c.execute('SELECT * FROM online WHERE username = ?', (security.AES256encrypt(user,data_key),)).fetchone()
            pubkey = security.AES256decrypt(row[2], data_key)
            connection.close()
        except:
            pass
        return pubkey

    def getUserEncryption(self, user):
        add = getUserAddress(user)
        if add == '':
            return 0
        
        pass
    
    def getUserHashing(self, user):
        pass
    
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/",
                        {'/media': {
                            'tools.staticdir.on': True,
                            'tools.staticdir.dir': abspath('./media')
                            },
                         '/download': {
                            'tools.staticdir.on': True,
                            'tools.staticdir.dir': abspath('./download')
                            },
                         '/profile': {
                            'tools.staticdir.on': True,
                            'tools.staticdir.dir': abspath('./profile')
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
