from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from sqlalchemy import create_engine, join, desc
from sqlalchemy.orm import sessionmaker
from library_database_setup import Base, User, Author, Book

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# Creates client id
CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

app = Flask(__name__)

engine = create_engine('sqlite:///librarydatabase.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/main/')
def frontPage():
    loggedin = False
    if 'username' in login_session:
        print login_session['username']
        loggedin = True
    authors = session.query(Author).order_by(Author.lastName).all()
    joinedBooks = session.query(Book, Author).join(Author)\
                         .filter(Book.author_id == Author.id)\
                         .order_by(desc(Book.create_date)).limit(4)\
                         .values(Book.title, Book.description,
                                 Author.firstName, Author.lastName,
                                 Book.author_id, Book.id, Book.create_date)
    result = []
    for j in joinedBooks:
        result.append({'title': j.title, 'description': j.description,
                       'author': (j.firstName + " " + j.lastName),
                       'author_id': j.author_id, 'id': j.id})
    return render_template('front.html', authors=authors, booklist=result,
                           loggedin=loggedin)


@app.route('/authors/')
def showAuthors():
    authors = session.query(Author).order_by(Author.lastName).all()
    if 'username' in login_session:
        return render_template('authors.html', authors=authors, loggedin=True)
    else:
        return render_template('publicauthors.html', authors=authors,
                               loggedin=False)


@app.route('/authors/new/', methods=['GET', 'POST'])
def addAuthor():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newAuthor = Author(lastName=request.form['lastname'],
                           firstName=request.form['firstname'],
                           user_id=login_session['user_id'])
        session.add(newAuthor)
        session.commit()
        flash("Author " + newAuthor.firstName + " " + newAuthor.lastName +
              " has been added")
        return redirect(url_for('showAuthors', loggedin=True))
    else:
        return render_template('addauthor.html', loggedin=True)


@app.route('/authors/<int:author_id>/')
def showOneAuthor(author_id):
    author = session.query(Author).filter_by(id=author_id).one()
    books = session.query(Book).filter_by(author_id=author.id).all()
    if 'username' in login_session:
        return render_template('oneauthor.html', author=author, books=books,
                               loggedin=True)
    else:
        return render_template('publicauthor.html', author=author, books=books,
                               loggedin=False)


@app.route('/authors/<int:author_id>/edit/', methods=['GET', 'POST'])
def editAuthor(author_id):
    if 'username' not in login_session:
        return redirect('/login')
    editAuthor = session.query(Author).filter_by(id=author_id).one()
    if editAuthor.user_id != login_session['user_id']:
        return "<script>function myFunction() \
                {alert('Only the creator can edit an entry.');}</script>\
                <body onload='myFunction()'>"
    if request.method == 'POST':
        editAuthor.lastName = request.form['lastname']
        editAuthor.firstName = request.form['firstname']
        session.add(editAuthor)
        session.commit()
        flash(editAuthor.firstName + " " + editAuthor.lastName +
              " was updated.")
        return redirect(url_for('showAuthors'))
    else:
        return render_template('editauthor.html', author=editAuthor)


@app.route('/authors/<int:author_id>/delete/',  methods=['GET', 'POST'])
def deleteAuthor(author_id):
    if 'username' not in login_session:
        return redirect('/login')
    deleteAuthor = session.query(Author).filter_by(id=author_id).one()
    if request.method == 'POST':
        session.delete(deleteAuthor)
        session.commit()
        flash(deleteAuthor.firstName + " " + deleteAuthor.lastName +
              " was deleted.")
        return redirect(url_for('showAuthors'))
    else:
        return render_template('deleteauthor.html', author=deleteAuthor)


@app.route('/authors/<int:author_id>/shelf/new/', methods=['GET', 'POST'])
def addBook(author_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['title'] == "":
            flash("Book must have title")
            return redirect(url_for('showOneAuthor', author_id=author_id))
        newBook = Book(title=request.form['title'],
                       description=request.form['descrip'],
                       genre=request.form['genre'],
                       page_count=request.form['pagecount'],
                       year=request.form['year'],
                       author_id=author_id,
                       user_id=login_session['user_id'])
        session.add(newBook)
        session.commit()
        flash("New book " + newBook.title + " was added.")
        return redirect(url_for('showOneAuthor', author_id=author_id,
                        loggedin=True))
    else:
        author = session.query(Author).filter_by(id=author_id).one()
        return render_template('addbook.html', author=author, loggedin=True)


@app.route('/authors/<int:author_id>/shelf/<int:book_id>')
def showBook(author_id, book_id):
    author = session.query(Author).filter_by(id=author_id).one()
    book = session.query(Book).filter_by(author_id=author_id, id=book_id).one()
    if 'username' in login_session:
        return render_template('onebook.html', author=author, book=book,
                               loggedin=True)
    else:
        return render_template('publicbook.html', author=author, book=book)


@app.route('/authors/<int:author_id>/shelf/<int:book_id>/edit',
           methods=['GET', 'POST'])
def editBook(author_id, book_id):
    if 'username' not in login_session:
        return redirect('/login')
    editBook = session.query(Book).filter_by(author_id=author_id, id=book_id)\
                      .one()
    if request.method == 'POST':
        editBook.title = request.form['title']
        editBook.description = request.form['descrip']
        editBook.genre = request.form['genre']
        editBook.page_count = request.form['pagecount']
        editBook.year = request.form['year']
        session.add(editBook)
        session.commit()
        flash(editBook.title + " was updated.")
        return redirect(url_for('showOneAuthor', author_id=author_id))
    else:
        return render_template('editbook.html', author_id=author_id,
                               book=editBook)
    return "This edits the book with id " + book_id


@app.route('/authors/<int:author_id>/shelf/<int:book_id>/delete',
           methods=['GET', 'POST'])
def deleteBook(author_id, book_id):
    if 'username' not in login_session:
        return redirect('/login')
    deleteBook = session.query(Book).filter_by(author_id=author_id,
                                               id=book_id).one()
    if request.method == 'POST':
        session.delete(deleteBook)
        session.commit()
        flash(deleteBook.title + " was deleted.")
        return redirect(url_for('showOneAuthor', author_id=author_id))
    else:
        return render_template('deletebook.html', author_id=author_id,
                               book=deleteBook)


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already \
                                connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    login_session['provider'] = 'google'

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesnt, make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius: 100px;\
               -webkit-border-radius: 100px;-moz-border-radius: 100px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == "google":
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('frontPage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('frontPage'))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('credentials')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session.get('credentials')
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for \
                                            given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=\
           fb_exchange_token&client_id=%s&client_secret=%s\
           &fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?%s&redirect\
           =0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
              -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
          % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out."


@app.route('/clearSession')
def clearSession():
    login_session.clear()
    return "session cleared."


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON API ENDPOINTS

@app.route('/authors/<int:author_id>/JSON')
def oneAuthorJSON(author_id):
    author = session.query(Author).filter_by(id=author_id).one()
    books = session.query(Book).filter_by(author_id=author_id).all()
    return jsonify(Books=[b.serialize for b in books])


@app.route('/authors/<int:author_id>/shelf/<int:book_id>/JSON')
def bookJSON(author_id, book_id):
    book = session.query(Book).filter_by(author_id=author_id, id=book_id).one()
    return jsonify(Book=[book.serialize])


@app.route('/authors/JSON')
def authorsJSON():
    authors = session.query(Author).all()
    return jsonify(Authors=[a.serialize for a in authors])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
