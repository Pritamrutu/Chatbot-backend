    
from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Pritam'
app.config['MYSQL_DB'] = 'chatbot'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['JWT_SECRET_KEY'] = 'secret'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

@app.route('/chatbot/register', methods=['POST'])
def register():
    cur = mysql.connection.cursor()
    PRN = request.get_json()['PRN']
    UserName = request.get_json()['UserName']
    Pass = bcrypt.generate_password_hash(request.get_json()['Pass'])
    Email = request.get_json()['Email'].decode('utf-8')
    
    cur.execute("INSERT INTO student (PRN, UserName, Pass, Email) VALUES ('" + 
		str(PRN) + "', '" + 
		str(UserName) + "', '" + 
		str(Pass) + "', '" + 
        str(Email) + "')")
    mysql.connection.commit()
    cur.close()
	
    result = {
		'PRN' : PRN,
		'UserName' : UserName,
        'Pass' : Pass,
		'Email' : Email,
	}

    return jsonify({'result' : result})
	

@app.route('/chatbot/login', methods=['POST'])
def login():
    cur = mysql.connection.cursor()
    Email = request.get_json()['Email']
    Pass = request.get_json()['Pass']
    result = ""
	
    cur.execute("SELECT * FROM Student where Email = '" + str(Email) + "'")
    rv = cur.fetchone()
    mysql.connection.commit()
    cur.close()
	
    if bcrypt.check_password_hash(rv['Pass'], Pass):
        access_token = create_access_token(identity = {'PRN': rv['PRN'],'UserName': rv['UserName'],'Email': rv['email']})
        result = jsonify({"token":access_token})
    else:
        result = jsonify({"error":"Invalid username and password"})
    
    return result

if __name__ == '__main__':
    app.run(debug=True)
