# flask imports
from flask import Flask, request, jsonify, make_response, g, abort
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps


# creates Flask object
app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)

blacklist = set()

# Database ORMs
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(80))

    roles = db.relationship('Role', secondary='user_roles')

# Define Role model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50))

# Define UserRoles model
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

with app.app_context():
    db.create_all()
    
    admin_user = User.query.filter_by(name='admin').first()
    if not admin_user:
        admin_user = User(public_id = str(uuid.uuid4()), name='admin',password=generate_password_hash('admin'))
        admin_user.roles.append(Role(name='Admin'))
        db.session.add(admin_user)
        db.session.commit()

    admin_role = Role.query.filter_by(name='Admin').first()
    if not admin_role:
        admin_role = Role(name='Admin')
        db.session.add(admin_role)
        db.session.commit()

    member_role = Role.query.filter_by(name='Member').first()
    if not member_role:
        member_role = Role(name='Member')
        db.session.add(member_role)
        db.session.commit()


def roles_required(*role_required):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('x-access-token')
            if not token:
                return jsonify({'message': 'Token is missing!'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.filter_by(public_id=data['public_id']).first()
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Token is invalid!'}), 401
            # Get the role ids for the specified role names
            current_roles = UserRoles.query.filter_by(user_id=user.id).all()
            authorized = 0
            for current_role in current_roles:
                role_name = Role.query.filter_by(id=current_role.role_id).first()
                if role_name.name in role_required:
                    authorized += 1

            if not authorized > 0:
                return jsonify({'message': 'Unauthorized!'}), 403
            
            # Save the user object in the Flask application context
            g.user = user

            return f(*args, **kwargs)
        return wrapper
    return decorator

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS512', 'HS256'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
    return decorated

# User Database Route
# this route sends back list of users
@app.route('/user', methods =['GET'])
@token_required
@roles_required ('Admin', 'Member')
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'id' : user.id,
            'public_id': user.public_id,
            'name' : user.name
        })
  
    return jsonify({'users': output})

@app.route('/role', methods = ['POST', 'GET', 'DELETE'])
@token_required
def get_role(current_user):

    payload = request.form

    if request.method == 'GET':
        roles = Role.query.all()
        output = []
        for role in roles:

            output.append({
                'id' : role.id,
                'name': role.name
            })
        return jsonify({'roles': output})
    
    if request.method == 'POST':
        #required
        #user_name
        #role_name

        user = User.query.filter_by(name=payload.get('name')).first()
        role = Role.query.filter_by(name=payload.get('role')).first()
    
        if not UserRoles.query.filter_by(user_id=user.id, role_id=role.id).first():
            user_role = User.query.filter_by(name=user.name).first()
            user_role.roles.append(Role(name=role.name))
            db.session.commit()
            return make_response(jsonify({'Message' : 'Role was successfully added!'}), 200)
        else:
            return make_response(jsonify({'Error' : 'Invalid!'}), 400)

@app.route('/userroles', methods = ['POST', 'GET', 'DELETE'])
@token_required
def get_userroles(current_user):
    if request.method == 'GET':
        userroles = UserRoles.query.all()
        output = []
        for userrole in userroles:

            output.append({
                'id' : userrole.id,
                'user_id': userrole.user_id,
                'role_id' : userrole.role_id
            })
        return jsonify({'userroles': output})
    
# route for logging user in
@app.route('/login', methods = ['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('password'):
        # returns 401 if any name and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
    user = User.query\
        .filter_by(name = auth.get('name'))\
        .first()
    
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
        return make_response(jsonify({'token' : token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )
  
# signup route
@app.route('/user', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
  
    # gets name, email and password
    name = data.get('name')
    password = data.get('password')
  
    # checking for existing user
    user = User.query\
        .filter_by(name = name)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            password = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)

@app.route('/logout')
@token_required
def logout(current_user):
    jti = get_raw_jwt()['jti'] # get the unique identifier of the JWT
    blacklist.add(jti) # add the jti to the blacklist
    return jsonify({'message': 'Successfully logged out.'}), 200

if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debugger shell
    # if you hit an error while running the server
    app.run(host='0.0.0.0', port=80 ,debug = True)
