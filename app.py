from flask import Flask, jsonify, abort, request
from flask_swagger_ui import get_swaggerui_blueprint
from db import get_db
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, get_raw_jwt
)

app = Flask(__name__)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 120
app.config['JWT_HEADER_TYPE'] = ''
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_SECRET_KEY'] = 'extra'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'
jwt = JWTManager(app)
USERS = {'admin': {'password': 'admin', 'access': 'example', 'refresh': 'example'}}
blacklist = set()


SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Online-Market"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

conn = get_db()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


@app.route('/register/', methods=['POST'])
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('email', None)
    password = request.json.get('password', None)
    if username in USERS:
        return jsonify({'error': 'Email already used'}), 403
    USERS[username] = {'password': password, 'access': 'example', 'refresh': 'example'}
    return jsonify({'Register': 'Successfully registered new user.'}), 201


@app.route('/login/', methods=['POST'])
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('email', None)
    password = request.json.get('password', None)
    if username not in USERS or USERS[username]['password'] != password:
        return jsonify({'Login': False, 'error': 'No user found with this email and password'}), 401
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    USERS[username]['access'] = access_token
    USERS[username]['refresh'] = refresh_token
    return jsonify({'login': 'Success', 'access_token': access_token, 'refresh_token': refresh_token}), 200


@app.route('/refresh/', methods=['POST'])
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if auth_header != USERS[current_user]['refresh']:
        return jsonify({'Refresh': 'Wrong refresh token'}), 401
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(identity=current_user)
    USERS[current_user]['access'] = access_token
    USERS[current_user]['refresh'] = refresh_token
    return jsonify({'Refresh': 'Success', 'access_token': access_token, 'refresh_token': refresh_token}), 200


@app.route('/validate/', methods=['POST'])
@app.route('/validate', methods=['POST'])
@jwt_required
def validate():
    try:
        return jsonify({'valid_user_token': True}), 200
    except:
        return jsonify({'valid_user_token': False}), 201


@app.route('/logout/', methods=['DELETE'])
@app.route('/logout', methods=['DELETE'])
@jwt_refresh_token_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({'logout': True}), 200


@app.route('/')
@app.route('/index')
def index():
    return jsonify('Welcome to Online-market'), 200


@app.route('/items/<int:item_id>', methods=['GET'])
def get_curr_item(item_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM Item WHERE id = %s", (item_id, ))
    item = cur.fetchone()
    if not item:
        cur.close()
        abort(404)
    cur.close()
    return jsonify({'Item': item[1], 'Category': item[2]}), 200


@app.route('/items/', methods=['GET'])
@app.route('/items', methods=['GET'])
def get_items():
    cur = conn.cursor()
    cur.execute("SELECT COUNT(id) FROM Item")
    total = cur.fetchone()[0]
    page = request.args.get('page', type=int, default=1)
    per_page = request.args.get('limit', type=int, default=2)
    offset = (page - 1) * per_page
    cur.execute("SELECT name, category FROM Item ORDER BY id LIMIT %s OFFSET %s", (per_page, offset, ))
    items = cur.fetchall()
    results = []
    for item in items:
        results.append({'Item': item[0], 'Category': item[1]})
    return jsonify({'Items': results, 'Total_amount': total}), 200


@app.route('/items', methods=['POST'])
@jwt_required
def create_item():
    if not request.json:
        abort(400)
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if auth_header != USERS[current_user]['access']:
        return jsonify({'Error': 'Wrong access token'}), 401
    cur = conn.cursor()
    cur.execute("SELECT id FROM Item ORDER BY id DESC LIMIT 1")
    last_item = cur.fetchone()
    if not last_item:
        last_id = 1
    else:
        last_id = last_item[0] + 1
    cur.execute("INSERT INTO Item(id, name, category) VALUES (%s, %s, %s)", (last_id, request.json['name'], request.json['category']))
    cur.close()
    conn.commit()
    return jsonify({'Item': request.json['name'], 'Category': request.json['category']}), 201


@app.route('/items/<int:item_id>', methods=['PUT'])
@jwt_required
def change_item(item_id):
    if not request.json:
        abort(400)
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if auth_header != USERS[current_user]['access']:
        return jsonify({'Error': 'Wrong access token'}), 401
    cur = conn.cursor()
    cur.execute("SELECT * FROM Item WHERE id = %s", (item_id, ))
    item = cur.fetchone()
    if not item:
        cur.close()
        abort(404)
    if 'name' in request.json:
        cur.execute("UPDATE Item SET name = %s WHERE id = %s", (request.json['name'], item_id, ))
    if 'category' in request.json:
        cur.execute("UPDATE Item SET category = %s WHERE id = %s", (request.json['category'], item_id, ))
    cur.close()
    conn.commit()
    return get_curr_item(item_id)


@app.route('/items/<int:item_id>', methods=['DELETE'])
@jwt_required
def delete_item(item_id):
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if auth_header != USERS[current_user]['access']:
        return jsonify({'Error': 'Wrong access token'}), 401
    cur = conn.cursor()
    cur.execute("SELECT * FROM Item WHERE id = %s", (item_id, ))
    item = cur.fetchone()
    if not item:
        cur.close()
        abort(404)
    cur.execute("DELETE FROM Item WHERE id = %s", (item_id, ))
    cur.close()
    conn.commit()
    return jsonify({'Item': item[1], 'Category': item[2]}), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify('Item Not Found'), 404


@app.errorhandler(400)
def not_found(error):
    return jsonify('Bad request. You may have sent an empty request'), 400


@app.errorhandler(500)
def internal_error(error):
    return jsonify('An unexpected error has occurred'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')