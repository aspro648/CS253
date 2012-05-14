import webapp2
import re
import os
import jinja2
import hashlib, hmac
import random, string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# FUNCTIONS ======================                             
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

    
# CLASSES ======================              
class BlogEntries(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add=True)                               
    last_modified = db.DateTimeProperty(auto_now=True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('blog.html', p=self)

        
class Users(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)    
    email = db.StringProperty()     
 
 
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Blog(Handler):
    def get(self):
        blogEntries = BlogEntries.all().order('-created')
        # or blogEntries = db.GqlQuery("SELECT * from BlogEntries ORDER BY created DESC limit 10")
        self.render('blog.html', blogEntries=blogEntries)
        
    def get2(self, id='', post=''):
        try:
            id = int(self.request.path.split("/")[-1])
        except Exception:
            id = ""
        if id:
            key = db.Key.from_path('BlogEntries', id)
            post = db.get(key)       
        self.render_blog(post=post)
 
    def render_blog(self, post="", blogEntries="", error=""):
        if not post:
            blogEntries = db.GqlQuery("SELECT * from BlogEntries ORDER BY created DESC")
        self.render("blog.html", post=post, blogEntries=blogEntries, error=error)

        
class Post(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogEntries', int(post_id)) #, parent=blog_key()
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render('post.html', post=post)
        
        
class Newpost(Handler):
    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            a = BlogEntries(subject = subject, content = content)
            a.put()
            self.redirect("/blog")
        else:
            error = "We need both a subject and a post!"
            #self.render("front.html", error = error)
            self.render_front(subject=subject, conent=content, error=error)
        
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)        

 
class Logout(Handler):
    def get(self):
        self.redirect('/blog/signup')

        
class Login(Handler):
    def write_form(self, username="", usernameError="", passwordError=""):
        form = '''
            <form method="post" name="form">
                Login:
                <br>
                <label>Username
                    <input type="text" name="username" value="%(username)s"><div style="color: red">%(usernameError)s</div>
                </label><br>
                <label>Password
                    <input type="password" name="password"><div style="color: red">%(passwordError)s</div>
                </label><br>
                <br>
                <input type="submit">
            </form> ''' 
        #self.response.out.write(form % {"username": username, "usernameError": usernameError,
        #                                "passwordError": passwordError})
        self.render("login.html", username=username, usernameError=usernameError,
                     passwordError=passwordError)
                                        
    def get(self):
        #self.response.out.write(self.form)
        self.write_form()
 
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        error = False
        usernameError = ""
        passwordError = ""

        if not valid_username(username):
            error = True
            usernameError = 'Not a valid username.'
 
        if not valid_password(password):
            error = True
            passwordError = 'Not a valid password.'            
           
        if error:
            self.write_form(username, usernameError, passwordError)
        else:
            query = db.GqlQuery('SELECT * FROM Users WHERE username = :1', username)
            row = query.get()
            #self.response.out.write('<br>username ' + username)
            #self.response.out.write('<br>password ' + password)
            #self.response.out.write('<br>row.username ' + row.username)
            #self.response.out.write('<br>row.password ' + row.password)
            #self.response.out.write('<br>item ' + str(row.key().id()))
            
            if row:
                hash = '%s,%s' % (row.password, row.salt)
                #self.response.out.write('<br>hash ' + hash)
                valid = valid_pw(row.username, password, hash)
                #self.response.out.write('<br>valid_pw ' + str(valid))
                if valid:
                    new_cookie_val = make_secure_val(str(row.key().id()))
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
                    self.redirect('/blog/welcome') 
                else:
                    passwordError = 'Invalid login.'
                    self.write_form(username, passwordError=passwordError) 
            else:
                passwordError = 'Invalid login.'
                self.write_form(username, passwordError=passwordError)            

        
class Signup(Handler):
    ''' for section 4 '''
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
        #self.response.out.write(form % {"username": username, "email": email, "usernameError": usernameError,
        #                                "passwordError": passwordError, "emailError": emailError})
        self.render("signup.html", username=username, email=email, usernameError=usernameError,
                     passwordError=passwordError, emailError=emailError)
        
    def get(self):
        #self.response.out.write(self.form)
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.write_form()
        
    def post(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
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

        if not valid_username(username):
            error = True
            usernameError = 'Not a valid username.'
            
        if not valid_email(email):
            pass
            #error = True
            #emailError = 'Not a valid email.'            

        if not valid_password(password):
            error = True
            passwordError = 'Not a valid password.'            

        if error:
            self.write_form(username,email, usernameError, passwordError, emailError)
        else:
            
            salt = make_salt()
            hsh = hashlib.sha256('%s%s%s' % (username, password, salt)).hexdigest()
            
            query = db.GqlQuery('SELECT * FROM Users WHERE username = :1', username)
            row = query.get()
            if row:
                usernameError = 'That user already exists.'
                self.write_form(username, usernameError=usernameError)            
            else:
                user = Users(username=username, password=hsh, email=email, salt=salt)
                key = user.put()
                new_cookie_val = make_secure_val(str(key.id()))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
                self.redirect('/blog/welcome') 


class Welcome(Handler):
    def get(self):
        cookie_val = None
        #self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        cookie_str = self.request.cookies.get('user_id')
        #self.response.out.write(cookie_str + '\n')
        if cookie_str:
            cookie_val = check_secure_val(cookie_str)
            #self.response.out.write('cookie_val ' + cookie_val + '\n')
            if cookie_val:
                user = Users.get_by_id(int(cookie_val))
                if user:
                    self.write("Welcome, %s!\n" % user.username)
                    #self.render("welcome.html", username=user.username)
                else:
                    self.redirect('/blog/signup')
        if not cookie_val:
            self.redirect('/blog/signup')

 
app = webapp2.WSGIApplication([('/blog/logout', Logout), ('/blog/signup', Signup), ('/blog/welcome', Welcome), 
                               ('/blog/?', Blog), ('/blog/newpost', Newpost), ('/blog/(\d+)', Post),
                               ('/blog/login', Login)],
                              debug=True)