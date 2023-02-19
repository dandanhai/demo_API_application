
from flask import Flask, jsonify, request, make_response
import jwt
import boto3
import datetime
import os
from functools import wraps


AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
SECRET_KEY = os.environ['SECRET_KEY']
auth_username = os.environ['auth_username']
auth_password = os.environ['auth_password']


dynamodb = boto3.resource(
    service_name='dynamodb',
    region_name='ap-southeast-1',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# deploy app
application = Flask(__name__)

"""
for EB to check health
"""


@application.route('/health')
def health_check():
    return "health check pass"


"""
function to login and get the token
"""


@application.route(f'/login')
def login():
    auth = request.authorization

    if auth and auth.password == auth_password:
        token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           SECRET_KEY, algorithm="HS256")
        return jsonify({'token': token})

    return make_response('can not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


"""
function to decode and check the token
"""


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:  # there is nothing
            return jsonify({'message': 'do not have token here, please attach token'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY,
                              algorithms=["HS256"])  # if it is able to decode by key, token is correct
            if data['user'] == auth_username:
                pass
            else:
                return jsonify({'message': 'cannot match the user, token is invalid!'}), 401
        except:
            return jsonify({'message': 'token is invalid! please type the correct one'}), 401

        return f(*args, **kwargs)

    return decorated


"""
route unprotected
"""


@application.route(f'/unprotected', methods=['GET'])
def demo():
    return jsonify({'message': 'Congrat! it is a unprotected route result'})


"""
route protected
"""


@application.route(f'/protected_demo', methods=['GET'])
@token_required
def protected_demo():
    return jsonify({'message': 'Congrat! U are reaching here and it is the demo protect route result.'})




if __name__ == '__main__':
    application.run(debug=True)
