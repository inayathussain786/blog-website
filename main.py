import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

file = open('secret.txt', 'r')
secret = file.read()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        userid = str(user.key().id())
        self.set_secure_cookie('user_id', userid)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    username = db.StringProperty()
    likes = db.IntegerProperty()

    @classmethod
    def by_name(cls, subject):
        u = Post.all().filter('subject =', subject).get()
        return u

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def render1(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post1.html", p = self)

class Comment(db.Model):
    username = db.StringProperty()
    post_id = db.StringProperty()
    comments = db.TextProperty()

class Like(db.Model):
    username = db.StringProperty()
    post_id = db.StringProperty()
    status = db.StringProperty()

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.user:
            self.render("permalink.html", post = post, username = self.user.name)
        else:
            self.redirect('/login')

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        likes = "0"

        if subject and content:
            u = Post.by_name(subject)
            if u:
                msg = 'Already used. Choose another subject'
                self.render("newpost.html", error_subject = msg)
            else:
                #### inserting subject, content, username and no of likes
                p = Post(parent = blog_key(),
                        subject = subject,
                        content = content,
                        username = self.user.name,
                        likes = int(likes))
                p.put()
                post_id = str(p.key().id())
                self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class MyPosts(BlogHandler):
    def get(self):
        if self.user:
            posts = db.GqlQuery("select * from Post where username='%s' order by last_modified desc" % self.user.name)
            self.render("myposts.html", posts = posts)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.logout()
            self.redirect('/login')

class EditPosts(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            oldsubject = post.subject
            oldcontent = post.content
            if self.user.name == post.username:
                self.render('editposts.html', post = post,
                                              username = self.user.name,
                                              oldsubject = oldsubject,
                                              oldcontent = oldcontent)
            else:
                error = "You cannot edit this blog!!!"
                self.render('editposts.html', post = post,
                                              username = self.user.name,
                                              oldsubject = oldsubject,
                                              oldcontent = oldcontent,
                                              error = error)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            oldsubject = post.subject
            oldcontent = post.content
            if self.user.name == post.username:
                newsubject = self.request.get('subject')
                newcontent = self.request.get('content')
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                post.subject = newsubject
                post.content = newcontent
                post.put()
                self.redirect('/blog/%s' % str(post_id))
            else:
                error = "You cannot edit this blog!!!"
                self.render('editposts.html', post = post,
                                              username = self.user.name,
                                              oldsubject = oldsubject,
                                              oldcontent = oldcontent,
                                              error = error)
        else:
            self.redirect('/login')

class DeletePosts(BlogHandler):
    def get(self,post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if self.user.name == post.username:
                post.delete()
                self.redirect('/blog/myposts')
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')

class CommentHandler(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            self.render("cmmtpge.html", post = post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            comment = self.request.get('comment')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if comment:
                q = Comment(parent = blog_key(),
                                username = self.user.name,
                                post_id = str(post_id),
                                comments = comment)
                q.put()
                self.redirect('/blog/%s' % str(post_id))
            else:
                error = "Comments cannot be blank!!!"
                self.render("cmmtpge.html", post = post, error = error)
        else:
            self.redirect("/login")

# class ViewComments(BlogHandler):
#     def get(self, post_id):
#         if not self.user:
#             self.redirect('/blog')
#         key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
#         post = db.get(key)
#         if not post:
#             self.error(404)
#             return
#         self.render("allcmmts.html", post = post)

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', username = self.username, error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/error')

class ErrorHandler(BlogHandler):
    def get(self):
        self.render('error.html')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/myposts', MyPosts),
                               ('/blog/myposts/edit/([0-9]+)', EditPosts),
                               ('/blog/myposts/delete/([0-9]+)', DeletePosts),
                               ('/blog/([0-9]+)/comment', CommentHandler),
                               #('/blog/[0-9]+/allcomments', ViewComments),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/error', ErrorHandler)],
                              debug=True)