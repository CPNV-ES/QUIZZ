'''
File for all security or authorization related methods

Author : Steven Avelino
'''
from passlib.context import CryptContext
from models.User import User
from .token_management import decrypt

'''
Function to check if the token sent is valid

Returns a boolean
'''
def check_token(token, require_admin, require_creator):
    decrypted_token = decrypt(token)
    if (User.objects(username=decrypted_token['username'])):
        user = User.objects.get(username=decrypted_token['username'])
        if (decrypted_token['password'] == user.password):
            if (require_admin):
                return True if user.admin == True else False
            elif (require_creator):
                return True if user.creator == True or user.admin == True else False
            else:
                return True
        else:
            return False
    else:
        return False

'''
Function that checks if an user is a guest
'''
def check_guest(token):
    decrypted_token = decrypt(token)
    if (User.objects(username=decrypted_token['username'])):
        user = User.objects.get(username=decrypted_token['username'])
        if (user.guest):
            return True
        else:
            return False
    else:
        return False

'''
Context object for password encryptions
'''
pwd_context = CryptContext(
    schemes=['pbkdf2_sha256'],
    default='pbkdf2_sha256',
    pbkdf2_sha256__default_rounds=20000
)