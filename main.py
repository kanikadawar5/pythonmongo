from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from common_functions import create_user, view_user, view_users, update_user, delete_user, authenticate_user, \
    authenticate_token, logout_user, check_if_logged_out
from constants import JWT_ALGORITHM, JWT_EXP_DELTA_SECONDS, JWT_SECRET, HOST, PORT
from validations import validate_user_id
import json
import logging
import jwt

result = {}


class ServiceHandler(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        length = int(self.headers['Content-Length'])
        content = self.rfile.read(length)
        temp = str(content).strip('b\'')
        self.end_headers()
        return temp

    def do_GET(self):
        result = {
            'status_code': 400,
            'message': 'invalid user id',
            'data': {}
        }
        query_components = parse_qs(urlparse(self.path).query)
        jwt_token = self.headers['jwt_token']
        payload = authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM)
        check_logged_out = check_if_logged_out(jwt_token)
        if check_logged_out:
            result = {'status_code': 400, 'message': "User logged out, try logging in again", "data": {}}
        elif not payload:
            result = {'status_code': 400, 'message': "Authentication failed, try logging in again", "data": {}}
        else:
            payload = payload[0]
            logging.info("GET request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                         str(self.path), str(self.headers), query_components)
            if 'user_id' in query_components:
                user_id = query_components["user_id"][0]
                if not validate_user_id(user_id):
                    result = {
                        'status_code':400,
                        'message' : 'invalid user id',
                        'data' : {}
                    }
                    self.send_response(result['status_code'])
                    self.send_header('Content-type', 'text/json')
                    self.end_headers()
                    self.wfile.write(str(result).encode('utf-8'))
                if str(payload['_id']) == str(user_id):
                    if user_id is not None:
                        result = view_user(user_id)
            else:
                result = view_users()

        self.send_response(result['status_code'])
        self.send_header('Content-type', 'text/json')
        self.end_headers()
        self.wfile.write(str(result).encode('utf-8'))

    def do_POST(self):
        try:
            if self.path.endswith("/login"):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                logging.info("POST login request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                             str(self.path), str(self.headers), post_data)
                post_data = json.loads(post_data)

                if not 'username' in post_data or 'password' not in post_data:
                    result = {'status_code': 400, 'message': "Enter both username and password","data":{} }
                    self._set_response()
                    self.send_response(400, result['message'])
                    self.wfile.write(str(result).encode('utf-8'))
                username = post_data['username']
                password = post_data['password']
                authentic = authenticate_user(username, password)

                if authentic:
                    payload = {
                        'username': username,
                        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
                    }
                    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
                    result = {'status_code': 200, 'message': "Login Successful", "data": {'token':jwt_token}}
                    self._set_response()
                    self.send_response(400, result['message'])
                    self.wfile.write(str(result).encode('utf-8'))
                else:
                    result = {'status_code': 400, 'message': "Invalid username or password", "data": {}}
                    self._set_response()
                    self.send_response(400, result['message'])
                    self.wfile.write(str(result).encode('utf-8'))

            elif self.path.endswith("/logout"):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                logging.info("POST logout request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                             str(self.path), str(self.headers), post_data)
                result = {
                    'status_code': 400,
                    'message': 'invalid username',
                    'data': {}
                }
                jwt_token = self.headers['jwt_token']
                payload = authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM)

                if not payload:
                    result = {'status_code': 400, 'message': "Already logged out", "data": {}}
                else:
                    result = logout_user(jwt_token)
                self.send_response(result['status_code'])
                self.send_header('Content-type', 'text/json')
                self.end_headers()
                self.wfile.write(str(result).encode('utf-8'))

            elif self.path.endswith("/create"):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                logging.info("POST create request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                             str(self.path), str(self.headers), post_data)
                result = create_user(post_data)
                self._set_response()
                self.send_response(200, "Creating")
                self.wfile.write(str(result).encode('utf-8'))

            elif self.path.endswith("/update"):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                logging.info("POST update request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                             str(self.path), str(self.headers), post_data)
                result = {
                    'status_code': 400,
                    'message': 'invalid username',
                    'data': {}
                }
                jwt_token = self.headers['jwt_token']
                payload = authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM)

                check_logged_out = check_if_logged_out(jwt_token)
                if check_logged_out:
                    result = {'status_code': 400, 'message': "User logged out, try logging in again", "data": {}}
                elif not payload:
                    result = {'status_code': 400, 'message': "Authentication failed, try logging in again", "data": {}}
                else:
                    payload = payload[0]
                    username = json.loads(post_data)['username']
                    if str(username) == str(payload['username']):
                        result = update_user(post_data)
                    # self._set_response()
                    # self.send_response(200, "Updating")
                    # self.wfile.write(str(result).encode('utf-8'))

                self.send_response(result['status_code'])
                self.send_header('Content-type', 'text/json')
                self.end_headers()
                self.wfile.write(str(result).encode('utf-8'))
            else:
                raise ValueError()
        except ValueError:
            result = {}
            message = "Invalid url"
            logging.error(message)
            result['status_code'] = 400
            result['message'] = message
            self._set_response()
            self.send_response(400, message)
            self.wfile.write(str(result).encode('utf-8'))

    def do_DELETE(self):
        result = {
            'status_code': 400,
            'message': 'invalid username',
            'data': {}
        }
        jwt_token = self.headers['jwt_token']
        payload = authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM)

        check_logged_out = check_if_logged_out(jwt_token)
        if check_logged_out:
            result = {'status_code': 400, 'message': "User logged out, try logging in again", "data": {}}
        elif not payload:
            result = {'status_code': 400, 'message': "Authentication failed, try logging in again", "data": {}}
        else:
            payload = payload[0]
            query_components = parse_qs(urlparse(self.path).query)
            logging.info("DELETE request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                         str(self.path), str(self.headers), query_components)
            if 'user_id' in query_components:
                user_id = query_components['user_id'][0]
                if str(user_id) == str(payload['user_id']):
                    result = delete_user(user_id)
                    self._set_response()
                    self.send_response(400, result['message'])
                    self.wfile.write(str(result).encode('utf-8'))
        self.send_response(result['status_code'])
        self.send_header('Content-type', 'text/json')
        self.end_headers()
        self.wfile.write(str(result).encode('utf-8'))


# Server Initialization
server = HTTPServer((HOST, PORT), ServiceHandler)
server.serve_forever()
