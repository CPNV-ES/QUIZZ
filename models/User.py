'''
User model for the MongoDB database

Author : Steven Avelino
'''

from mongoengine import *
from bson import json_util

'''
Custom queryset for the class

Created for the purpose to modify the to_json method
'''
class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

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

    # Change the queryset class to the custom one
    meta = {'queryset_class': CustomQuerySet}

    # Override to_json method
    def to_json(self):
         # Get the object to a mongo object
        data = self.to_mongo()
        # Remove the default _id key from the dict as it is badly formatted
        data.pop('_id')
        # Remove the password from the json
        data.pop('password')
        # Remove the token from the json
        data.pop('token')
        # Add a correctly formatted id key in the dict
        data['id'] = str(self.pk)
        # Return the dict as JSON
        return json_util.dumps(data)