from mongoengine import *

class User(Document):
    username = StringField(required=True, max_length=30, unique=True)
    password = StringField(required=True, min_length=8)
    token = StringField(required=True)
    scores = ListField(DictField(defaultdict={}))
    admin = BooleanField(required=True, default=False)