from passlib.context import CryptContext
from models.User import User
from .token_management import decrypt

'''
Function to check if the token sent is valid

Returns a boolean
'''
def check_token(token, require_admin):
    decrypted_token = decrypt(token)
    user = User.objects.get(username=decrypted_token['username'])
    if (user):
        if (decrypted_token['password'] == user.password):
            if (require_admin):
                return True if user.admin == True else False
            else:
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