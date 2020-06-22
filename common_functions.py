import _datetime
import json
from datetime import datetime

import jwt
from bson.objectid import ObjectId
from mongo_connect import connect_mongodb
from config import db_name
from validations import validate_name, validate_email, validate_contact, validate_dob, validate_user_id, validate_username
from constants import JWT_ALGORITHM, JWT_SECRET, JWT_EXP_DELTA_SECONDS

result = {
    "status_code" : 200,
    "message" : "Success",
    "data" : {}
}


def create_user(user_details):
    errors = []
    user_details = json.loads(user_details)

    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        if 'username' in user_details:
            if not validate_username(user_details['username']):
                errors.append("username is invalid")
            else:
                mycol = db.users
                username = user_details['username']
                x = list(mycol.find({'username': username}))
                if len(x) != 0:
                    result['status_code'] = 203
                    result['message'] = "This username is in use. Try another"
                    result['data'] = {}
                    return result

        if 'first_name' in user_details and 'last_name' in user_details:
            if validate_name(user_details['first_name']) and validate_name(user_details['last_name']):
                user_details['name'] = {
                    'first' : user_details['first_name'],
                    'last'  : user_details['last_name']
                }
                del user_details['first_name']
                del user_details['last_name']
            else:
                errors.append('name is invalid. Max size is 50 characters')
        else:
            errors.append('first_name and last_name are required.')
        if 'email_id' in user_details and not validate_email(user_details['email_id']):
            errors.append('email_id is invalid')
        if 'contact_number' in user_details:
            if not validate_contact(user_details['contact_number']):
                errors.append('contact_number is invalid')
        else:
            errors.append('contact number is required')
        if 'dob' in user_details and not validate_dob(user_details['dob']):
            errors.append("invalid dob format. use example - Nov 25, 1997")

        user_details['is_deleted'] = 0
        user_details['create_time'] = datetime.now()

        mycol = db.users
        x = mycol.insert_one(user_details)
        user_id = x.inserted_id
        if len(errors) > 0:
            result['status_code'] = 400
            result['message'] = errors
            result['data'] = {"errors":errors}
            return result
        result['status_code'] = 200
        result['message'] = "Signup Successful"
        result['data'] = {"user_id": user_id}
        return result


def view_user(user_id):
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        mycol = db.users
        x = list(mycol.find({'_id' : ObjectId(user_id)}))

        if len(x) == 0:
            result['status_code'] = 201
            result['message'] = "no data found"
            result['data'] = {}
            return result
        result['status_code'] = 200
        result['message'] = "Fetch Successful"
        result['data'] = x[0]
        return result


def view_users():
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        mycol = db.users
        x = list(mycol.find())
        result['status_code'] = 200
        result['message'] = "Fetch Successful"
        result['data'] = x
        return result


def update_user(user_details):
    errors = []
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        mycol = db.users
        user_details = json.loads(user_details)
        if 'user_id' in user_details:
            if not validate_user_id:
                errors.append("invalid user_id")
            else:
                x = list(mycol.find({'_id': ObjectId(user_details['user_id'])}))
                if len(x) == 0:
                    result['status_code'] = 201
                    result['message'] = "no data found"
                    result['data'] = {}
                    return result
                find_query = {"_id": ObjectId(user_details['user_id'])}
        else:
            errors.append("user_id is required for updation")

        if 'first_name' in user_details and 'last_name' in user_details:
            if validate_name(user_details['first_name']) and validate_name(user_details['last_name']):
                user_details['name'] = {
                    'first': user_details['first_name'],
                    'last': user_details['last_name']
                }
                del user_details['first_name']
                del user_details['last_name']
            else:
                errors.append('name is invalid. Max size is 50 characters')
        else:
            errors.append('first_name and last_name are required.')
        if 'email_id' in user_details and not validate_email(user_details['email_id']):
            errors.append('email_id is invalid')
        if 'contact_number' in user_details:
            if not validate_contact(user_details['contact_number']):
                errors.append('contact_number is invalid')
        if 'dob' in user_details and not validate_dob(user_details['dob']):
            errors.append("invalid dob format. use example - Nov 25, 1997")

        mycol.update(find_query, user_details)
        x = list(mycol.find({'_id': ObjectId(user_details['user_id'])}))[0]
        result['status_code'] = 200
        result['message'] = "Updation Successful"
        result['data'] = x
        return result


def delete_user(user_id):
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        mycol = db.users
        x = list(mycol.find({'_id': ObjectId(user_id)}))
        if len(x) == 0:
            result['status_code'] = 203
            result['message'] = "no data found"
            result['data'] = {}
            return result
        mycol.delete_one({"_id" : ObjectId(user_id)})
        x = list(mycol.find({'_id': ObjectId(user_id)}))
        if len(x) == 0:
            result['status_code'] = 200
            result['message'] = "Deleted successfully"
            result['data'] = {}
            return result


def authenticate_user(username, password):
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        mycol = db.users
        x = list(mycol.find({'username': username}, {'password' : password}))

        if len(x) == 0:
            return False
        return True


def authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM):
    if jwt_token:
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET,
                                 algorithms=[JWT_ALGORITHM])
            username = payload['username']
            db = connect_mongodb()
            if not db:
                result['status_code'] = 400
                result['message'] = "db connection failed"
                return result
            else:
                mycol = db.users
                x = list(mycol.find({'username': username}))

                if len(x) == 0:
                    return False
            x[0]['exp'] = payload['exp']
            return x
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return False


def logout_user(jwt_token):
    db = connect_mongodb()
    if not db:
        result['status_code'] = 400
        result['message'] = "db connection failed"
        return result
    else:
        errors = []
        user_details = {
            'jwt_token' : jwt_token,
            'create_timestamp' : datetime.now()
        }
        mycol = db.blacklisted_tokens
        x = mycol.insert_one(user_details)
        token_id = x.inserted_id
        if len(errors) > 0:
            result['status_code'] = 400
            result['message'] = "logout failed"
            result['data'] = {"errors": errors}
            return result
        result['status_code'] = 200
        result['message'] = "Logout Successful"
        result['data'] = {"token_id": token_id}
        return result


def check_if_logged_out(jwt_token):
    db = connect_mongodb()
    if not db:
        return True
    else:
        user_details = {
            'jwt_token': jwt_token,
            'create_timestamp': datetime.now()
        }
        mycol = db.blacklisted_tokens
        x = list(mycol.find({'jwt_token': jwt_token}))

        if len(x) != 0:
            x = x[0]
            create_time = x['create_timestamp']
            ct = utc_to_unix(create_time)
            if ct != 0:
                payload = authenticate_token(jwt_token, JWT_SECRET, JWT_ALGORITHM)

                if payload:
                    payload = payload[0]
                    jwt_token_create_time = payload['exp']
                    if ct < jwt_token_create_time:
                        return True
            return False


def utc_to_unix(utc_datetime):
    try:
        utc_datetime = str(utc_datetime)
        date_new = _datetime.datetime.timestamp(_datetime.datetime.strptime(utc_datetime, '%Y-%m-%d %H:%M:%S.%f'))
        return int(date_new)
    except:
        result['message'] = "Invalid datetime format"
        return 0

# print(utc_to_unix("2020-06-22 11:41:58.111000"))
# db_data = {
#     "name" : { "first" : "Kanika", "last": "Dawar" },
#     "dob" : new Date('Nov 25, 1997'),
#     "username" : "kanikadawar5",
#     "email_id" : "kanikadawar5@gmail.com",
#     "contact" : 9911112460,
#     "is_deleted" : 0,
#     "create_time" : new Date()
# }