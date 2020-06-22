import _datetime
import re


def validate_name(name):
    if len(name) > 50:
        return False
    else:
        return True


def validate_dob(dob):
    try:
        date_new = _datetime.datetime.strptime(dob, '%b %d, %Y')
        return True
    except:
        return False


def validate_email(email):
    if not re.match('^\S+@\S+$',str(email)):
        return False
    else:
        return True


def validate_contact(contact):
    if not re.match("^([0-9]{10})$", str(contact)):
        return False
    else:
        return True


def is_deleted(value):
    if value not in [0,1]:
        return False
    else:
        return True


def validate_user_id(user_id):
    if len(user_id)>24 or len(user_id)<1:
        return False
    else:
        return True


def validate_username(username):
    if len(username)>100:
        return False
    else:
        return True