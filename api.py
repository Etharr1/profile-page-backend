from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt  
import urllib.parse
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,jwt_manager, get_jwt_identity

app = Flask(__name__)
@app.route('/')
def home():
    return "Server is running successfully! Use Postman to test the API "
SERVER_NAME = 'HAITHAM'  
DATABASE_NAME = 'Profile Page'

params = urllib.parse.quote_plus(
    f"DRIVER={{ODBC Driver 17 for SQL Server}};"
    f"SERVER={SERVER_NAME};"
    f"DATABASE={DATABASE_NAME};"
    f"Trusted_Connection=yes;"
)

app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'super-secret-key-that-should-be-changed'  
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'Users'

    user_id = db.Column('ID', db.Integer, primary_key=True)
    email = db.Column('Email', db.String(100), unique=True, nullable=False)
    password = db.Column('Password', db.String(250), nullable=False)
    created_at = db.Column('Created Date', db.Date)

    profile = db.relationship('PersonalInfo', backref='user', uselist=False)

class PersonalInfo(db.Model):
    __tablename__ = 'Personal_Information' 
    user_id = db.Column('UserID', db.Integer, db.ForeignKey('Users.ID'), primary_key=True)
    first_name = db.Column('FirstName', db.String(50))

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
         return jsonify({"message": "Missing data"}), 400

        hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        new_user = User(
            email=data['email'],
            password=hashed_pw, 
            created_at=datetime.now()
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        access_token = create_access_token(identity=user.user_id)
        return jsonify({"message": "Login Successful!", "id": user.user_id, "access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid email or password"}), 401
    
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    profile = PersonalInfo.query.filter_by(user_id=current_user_id).first()
    if profile:
        return jsonify({
            "user_id": profile.user_id,
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "bio": profile.bio}), 200
    else:
        return jsonify({
            "message": "Profile not found.please create your profile first",
        "user_id":current_user_id}), 404
@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    profile = PersonalInfo.query.filter_by(user_id=current_user_id).first()

    if not profile:
        profile = PersonalInfo(user_id=current_user_id)

    profile.first_name = data.get('first_name', profile.first_name)
    profile.last_name = data.get('last_name', profile.last_name)
    profile.bio = data.get('bio', profile.bio)

    db.session.add(profile)
    db.session.commit()

    return jsonify({"message": "Profile created successfully!"}), 201

if __name__ == '__main__':
 app.run(debug=True, host='0.0.0.0' , port=5000)