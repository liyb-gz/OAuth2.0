from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

# Add login session
from flask import session as login_session
import random, string

# Add gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# access_token verification
from google.oauth2 import id_token
from google.auth.transport import requests as g_requests

CLIENT_ID = json.loads(
  open('client_secret.json', 'r').read())['web']['client_id']

FB_APP = json.loads(open('fb_client_secret.json', 'r').read())['facebook app']

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenu_with_users.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))

  if 'username' not in login_session:
    return render_template('publicrestaurants.html', restaurants = restaurants)
  else:
    return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if 'username' not in login_session:
      return redirect(url_for('showLogin'))
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'],
                                 user_id = login_session['user_id'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  if 'username' not in login_session:
      return redirect(url_for('showLogin'))

  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  creator = session.query(User).filter_by(id = editedRestaurant.user_id).one()

  if login_session['email'] != creator.email:
    flash('You don\'t have the permission to edit this restaurant.')
    return redirect(url_for('showRestaurants'))


  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  if 'username' not in login_session:
      return redirect(url_for('showLogin'))

  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  creator = session.query(User).filter_by(id = restaurantToDelete.user_id).one()

  if login_session['email'] != creator.email:
    flash('You don\'t have the permission to delete this restaurant.')
    return redirect(url_for('showRestaurants'))

  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    creator = session.query(User).filter_by(id = restaurant.user_id).one()

    if ('username' not in login_session) or \
       (login_session['email'] != creator.email):
      return render_template('publicmenu.html',
                             items = items,
                             restaurant = restaurant,
                             creator = creator)
    else:
      return render_template('menu.html', items = items, restaurant = restaurant)


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  if 'username' not in login_session:
      return redirect(url_for('showLogin'))

  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  creator = session.query(User).filter_by(id = restaurant.user_id).one()

  if login_session['email'] != creator.email:
    flash('You don\'t have the permission to add new menu items to this restaurant.')
    return redirect(url_for('showRestaurants'))

  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'],
                         description = request.form['description'],
                         price = request.form['price'],
                         course = request.form['course'],
                         restaurant_id = restaurant_id,
                         user_id = login_session['user_id'])
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):

    if 'username' not in login_session:
      return redirect(url_for('showLogin'))

    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    creator = session.query(User).filter_by(id = restaurant.user_id).one()

    if login_session['email'] != creator.email:
      flash('You don\'t have the permission to edit this restaurant\'s menu items.')
      return redirect(url_for('showRestaurants'))

    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    if 'username' not in login_session:
      return redirect(url_for('showLogin'))

    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    creator = session.query(User).filter_by(id = restaurant.user_id).one()

    if login_session['email'] != creator.email:
      flash('You don\'t have the permission to delete this restaurant\'s menu items.')
      return redirect(url_for('showRestaurants'))

    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)


# Login
@app.route('/login')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                  for x in xrange(32))
  login_session['state'] = state
  return render_template('login.html',
                         STATE = state,
                         CLIENT_ID = CLIENT_ID,
                         FB_APP = FB_APP)

# Process Google login info
@app.route('/gconnect', methods=['POST'])
def gConnect():

  # Check session state
  if request.args.get('state') != login_session.get('state'):
    response = make_response(json.dumps('Invalid state.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Session state correct, process ajax json from frontend
  else:
    auth_response = request.json
    id_code = auth_response['id_token']
    access_token = auth_response['access_token']

    # Check if access token is valid
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    g_user_id = result.get('user_id')

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    try:
      id_info = id_token.verify_oauth2_token(id_code, g_requests.Request(), CLIENT_ID)

      if id_info['sub'] != g_user_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response


      if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
        raise ValueError('Wrong issuer.')

      # In case the user has already logged in
      stored_access_token = login_session.get('access_token')
      stored_g_user_id = login_session.get('g_user_id')
      if stored_access_token is not None and g_user_id == stored_g_user_id:
        # Update access token
        login_session['access_token'] = access_token
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

      # Store the access token in the session for later use.
      login_session['access_token'] = access_token
      login_session['g_user_id'] = g_user_id

      # Get user info
      userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
      params = {'access_token': access_token, 'alt': 'json'}
      answer = requests.get(userinfo_url, params=params)

      data = answer.json()

      login_session['provider'] = "google"
      login_session['username'] = data['name']
      login_session['picture'] = data['picture']
      login_session['email'] = data['email']

      user_id = getUserID(login_session['email'])

      if user_id is not None:
        login_session['user_id'] = user_id
      else:
        login_session['user_id'] = createUser(login_session)

      output = ''
      output += '<h1>Welcome, '
      output += login_session['username']
      output += '!</h1>'
      output += '<img src="'
      output += login_session['picture']
      output += ' " style = "width: 30px; height: 30px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
      flash("you are now logged in as %s" % login_session['username'])
      print "Access token: {}".format(login_session['access_token'])
      return output

    except ValueError, error:
      response = make_response(json.dumps(str(error)), 401)
      response.headers['Content-Type'] = 'application/json'
      return response

# User Google logout
@app.route('/gdisconnect', methods=['POST'])
def gDisonnect():
  access_token = login_session.get('access_token')

  # Check if the user is logged in
  if access_token is None:
    print 'Access Token is None'
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # User logged in, check him/her out.
  else:
    print 'In gdisconnect access token is {}'.format(access_token)
    print 'User name is: {}'.format(login_session['username'])

    # Send request to google to revoke access token
    # url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    print 'URL to revoke token: {}'.format(url)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    print 'HTTP Request to Google to revoke token: \n{}'.format(result)

    # Request to google successful
    print result['status']
    # if result['status'] == '200':
    if result.status == 200:
      del login_session['access_token']
      del login_session['g_user_id']
      del login_session['user_id']
      del login_session['username']
      del login_session['email']
      del login_session['picture']
      del login_session['provider']
      response = make_response(json.dumps('Successfully disconnected.'), 200)
      response.headers['Content-Type'] = 'application/json'
      return response
    else:
      response = make_response(json.dumps('Failed to revoke token for given user.', 400))
      response.headers['Content-Type'] = 'application/json'
      return response

# Process Facebook login info
@app.route('/fbconnect', methods=['POST'])
def fbConnect():

  # Check session state
  if request.args.get('state') != login_session.get('state'):
    response = make_response(json.dumps('Invalid state.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Session state correct, process ajax json from frontend
  else:
    auth_response = request.json
    print auth_response
    access_token = auth_response.get('accessToken')
    fb_user_id = auth_response.get('userID')

    # Exchange short term token for long term token
    url = ('https://graph.facebook.com/' \
           'oauth/access_token?' \
           'grant_type=fb_exchange_token&' \
           'client_id={}&' \
           'client_secret={}&' \
           'fb_exchange_token={}').format(FB_APP['id'], FB_APP['secret'], access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
      response = make_response(json.dumps(result.get('error')), 500)
      response.headers['Content-Type'] = 'application/json'
      return response

    access_token = result.get('access_token')

    url = ('https://graph.facebook.com/{}/me?' \
            'access_token={}&fields=name,id,email').format(FB_APP['version'], access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # Verify user
    if result.get('id') != fb_user_id:
      response = make_response(
        json.dumps("Token's user ID doesn't match given user ID."), 401)
      response.headers['Content-Type'] = 'application/json'
      return response

    name = result.get('name')
    email = result.get('email')

    # Get user picture
    url = ('https://graph.facebook.com/{}/me/picture?' \
            'access_token={}&height=200&width=200' \
            '&redirect=0').format(FB_APP['version'],access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    picture = result.get('data').get('url')

    # In case the user has already logged in
    stored_access_token = login_session.get('access_token')
    stored_g_user_id = login_session.get('g_user_id')
    if stored_access_token is not None and g_user_id == stored_g_user_id:
      # Update access token
      login_session['access_token'] = access_token
      response = make_response(json.dumps('Current user is already connected.'), 200)
      response.headers['Content-Type'] = 'application/json'
      return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['fb_user_id'] = fb_user_id

    login_session['username'] = name
    login_session['picture'] = picture
    login_session['email'] = email

    login_session['provider'] = "facebook"

    user_id = getUserID(login_session['email'])

    if user_id is not None:
      login_session['user_id'] = user_id
    else:
      login_session['user_id'] = createUser(login_session)

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 30px; height: 30px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "Access token: {}".format(login_session['access_token'])
    return output


# User logout
@app.route('/fbdisconnect', methods=['GET', 'POST'])
def fbDisonnect():
  access_token = login_session.get('access_token')

  # Check if the user is logged in
  if access_token is None:
    print 'Access Token is None'
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # User logged in, check him/her out.
  else:
    print 'In gdisconnect access token is {}'.format(access_token)
    print 'User name is: {}'.format(login_session['username'])

    # Send request to google to revoke access token
    # url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    print 'URL to revoke token: {}'.format(url)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    print 'HTTP Request to Google to revoke token: \n{}'.format(result)

    # Request to google successful
    print result['status']
    # if result['status'] == '200':
    if result.status == 200:
      del login_session['access_token']
      del login_session['fb_user_id']

      del login_session['user_id']
      del login_session['username']
      del login_session['email']
      del login_session['picture']
      
      del login_session['provider']

      response = make_response(json.dumps('Successfully disconnected.'), 200)
      response.headers['Content-Type'] = 'application/json'
      return response
    else:
      response = make_response(json.dumps('Failed to revoke token for given user.', 400))
      response.headers['Content-Type'] = 'application/json'
      return response


def getUserInfo(user_id):
  try:
    return session.query(User).filter_by(id = user_id).one()
  except:
    return None

def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.id
  except:
    return None

def createUser(login_session):
  newUser = User(name = login_session['username'],
                 email = login_session['email'],
                 picture = login_session['picture'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  return user.id

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
