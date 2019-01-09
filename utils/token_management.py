import jwt

def encrypt(username, password):
    return jwt.encode({'username': username, 'password': password}, 'secret', algorithm='HS256')

def decrypt(token):
    return jwt.decode(token, 'secret', algorithms='HS256')