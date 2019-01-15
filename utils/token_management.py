'''
File for JWT token related methods

Author : Steven Avelino
'''
import jwt

# Encrypt the username and password as well as a salt
def encrypt(username, password):
    return jwt.encode({'username': username, 'password': password}, 'secret', algorithm='HS256')

# Decrypt the token
def decrypt(token):
    return jwt.decode(token, 'secret', algorithms='HS256')