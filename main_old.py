import webapp2
import cgi # for escaping
import re
import os
import jinja2
import hashlib, hmac
import random, string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

                              
                     
class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    posted = db.DateTimeProperty(auto_now_add = True)
   
 
 
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
        
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
        
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

 
        
class Asciichan(Handler):
    def get(self):
        #self.write("asciichan!")
        #self.render("front.html")
        self.render_front()

        
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            #self.write("Thanks!")
            a = Art(title = title, art = art)
            a.put()
            self.redirect("/asciichan")
        else:
            error = "We need both a title and some artwork!"
            #self.render("front.html", error = error)
            self.render_front(title=title, art=art, error=error)
            
            
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery("SELECT * from Art ORDER BY created DESC")
        self.render("front.html", title=title, art=art, arts=arts, error=error)
            
            
form = '''
<form method="post" name="form">
	What is your birthday?
	<br>
	<label>Month
		<input type="text" name="month" value="%(month)s">
	</label>
	<label>Day
		<input type="text" name="day" value="%(day)s">
	</label>
	<label>Year
        <input type="text" name="year" value="%(year)s">
	</label>
    <div style="color: red">%(error)s</div>
	<br><br>
	<input type="submit">
</form> '''

def escape_html(s):
    return cgi.escape(s, quote = True)


    
    
class CookieCounter(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        
        self.write("You've been here %s times!" % visits)
        #self.render("index.html")

# Unit 4 HASH validation code:
def make_salt():
    ''' Return string of 5 random letters '''
    return ''.join(random.choice(string.letters) for x in xrange(5))

    
def make_pw_hash(name, pw, salt=None):
    ''' Return HASH(name + pw + salt),salt using sha256 '''
    if not salt:
        salt = make_salt()
    hsh = hashlib.sha256('%s%s%s' % (name, pw, salt)).hexdigest()
    return '%s,%s' % (hsh, salt)
    
    
def valid_pw(name, pw, h):
    ''' Return true if valid password '''
    hsh = h.split(',')[0]
    salt = h.split(',')[1]
    return (make_pw_hash(name, pw, salt=salt) == h)

    
def hash_str(s):
    ''' Return HASH value of s'''
    return hmac.new("imsosecret", s).hexdigest()
    #return hashlib.md5(s).hexdigest()

    
def make_secure_val(s):
    ''' Returns "string,HASH" for string s.'''
    return "%s|%s" % (s, hash_str(s))

    
def check_secure_val(h):
    ''' Check "string,HASH" against h '''
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s
    else:
        return None

        

class Validation(webapp2.RequestHandler):
    def write_form(self, error="", month="", day="", year=""):
        self.response.out.write(form % {"error": error,
                                        "month": escape_html(month),
                                        "day": escape_html(day),
                                        "year": escape_html(year)})

    def valid_month(self, month):
        months = ['January',
            'February',
            'March',
            'April',
            'May',
            'June',
            'July',
            'August',
            'September',
            'October',
            'November',
            'December']
        month_abbvs = dict((m[:3].lower(), m) for m in months)
        if month:
            short_month = month[:3].lower()
            return month_abbvs.get(short_month)

            
    # Day validation
    def valid_day(self, day):
        if day and day.isdigit():
             day = int(day)
             if day > 0 and day <= 31:
                return day

    #Year validation
    def valid_year(self, year):
        if year and year.isdigit():
            year = int(year)
            if year > 1900 and year < 2020:
                return year

    def get(self):
        self.write_form()
        #self.response.out.write(form)

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')
        
        month = self.valid_month(user_month)
        day = self.valid_day(user_day)
        year = self.valid_year(user_year)

     
        if not (month and day and year):
            #self.response.out.write(month, day, year)
            self.write_form("doesn't work for me!",
                            user_month, user_day, user_year)
        else:
            self.redirect("/thanks")
            #self.response.out.write("Thanks! That's a totally valid day!")
            
            
class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Thanks!")
 
 
class ROT13(webapp2.RequestHandler):

    def write_form(self, text=""):
        form = '''
            <form method="post" name="form">
                Enter some text to scramble:
                <br>
                <textarea name="text" style="height: 100px; width: 400px;">%(text)s</textarea>
                <br>
                <input type="submit">
            </form> '''
        self.response.out.write(form % {"text": text})

    def get(self):
        #self.response.out.write(self.form)
        self.write_form()
 
 
    def post(self):
        text = self.request.get('text')
        self.write_form(text=self.rot13(text))
        
       
    def rot13(self, text):
        returnStr = ''
        for char in text:
            ascii = ord(char)
            if ascii in range(65, 91):
                newAscii = ascii + 13
                if newAscii > 90:
                    newAscii = newAscii - 26
                returnStr += chr(newAscii)
            elif ascii in range(97, 123):
                newAscii = ascii + 13
                if newAscii > 122:
                    newAscii = newAscii - 26
                returnStr += chr(newAscii)
            else:
                returnStr += char
        return cgi.es
 
        
class Signup2(webapp2.RequestHandler):
    def write_form(self, username="", email="", usernameError="", passwordError="", emailError=""):
        form = '''
            <form method="post" name="form">
                Signup:
                <br>
                <label>Username
                    <input type="text" name="username" value="%(username)s"><div style="color: red">%(usernameError)s</div>
                </label><br>
                <label>Password
                    <input type="password" name="password"><div style="color: red">%(passwordError)s</div>
                </label><br>
                <label>Verify Password
                    <input type="password" name="verify">
                </label><br>
                <label>Email (optional)
                    <input type="text" name="email" value="%(email)s"><div style="color: red">%(emailError)s</div>
                </label><br>           
           
                <br>
                <input type="submit">
            </form> ''' 
        #self.response.out.write(form)
        self.response.out.write(form % {"username": username, "email": email, "usernameError": usernameError,
                                        "passwordError": passwordError, "emailError": emailError})

        
    def get(self):
        #self.response.out.write(self.form)
        self.write_form()
 
 
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        error = False
        usernameError = ""
        passwordError = ""
        emailError = ""
        
        if password != verify:
            error = True
            passwordError = 'Passwords did not match.'

        if not self.valid_username(username):
            error = True
            usernameError = 'Not a valid username.'
            
        if not self.valid_email(email):
            error = True
            emailError = 'Not a valid email.'            

        if not self.valid_password(password):
            error = True
            passwordError = 'Not a valid password.'            
        
        if error:
            self.write_form(username,email, usernameError, passwordError, emailError)
        else:
            self.redirect('/welcome?username=%s' % username)
            
    def valid_username(self, username):
        ''' Returns none if illegal '''
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        ''' Returns none if illegal '''
        USER_RE = re.compile(r"^.{3,20}$")
        return USER_RE.match(password)
        
    def valid_email(self, email):
        ''' Returns none if illegal '''
        USER_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return USER_RE.match(email)        
        
            
class Welcome2(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        self.response.out.write("Welcome, %s!" % username)
 
 
app = webapp2.WSGIApplication([('/validation', Validation), 
                               ('/thanks', ThanksHandler), ('/ROT13', ROT13), ('/asciichan', Asciichan),
                               ('/cookiecounter', CookieCounter)],
                              debug=True)