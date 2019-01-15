'''
User model for the MongoDB database

Author : Steven Avelino
'''

from mongoengine import *

'''
Main class for the model User
'''
class User(Document):
    username = StringField(required=True, max_length=30, unique=True)
    password = StringField(required=True, min_length=8)
    token = StringField(required=True)
    scores = ListField(DictField(defaultdict={}))
    admin = BooleanField(required=True, default=False)
    creator = BooleanField(required=True, default=False)
    guest = BooleanField(required=True, default=False)