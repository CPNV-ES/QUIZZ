'''
Question model for the MongoDB database

Author : Steven Avelino
'''
from mongoengine import *
from bson import json_util
from .User import User

'''
Custom queryset for the class

Created for the purpose to modify the to_json method
'''
class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

'''
Main class for the model Question
'''
class Question(Document):
    question = StringField(required=True, max_length=255)
    answers = ListField(DictField())
    image = StringField()
    created_by = ReferenceField(User)
    number_answered = IntField(default=0)
    number_right = IntField(default=0)

    # Change the queryset class to the custom one
    meta = {'queryset_class': CustomQuerySet}

    # Override to_json method
    def to_json(self):
        # Get the object to a mongo object
        data = self.to_mongo()
        # Remove the default _id key from the dict as it is badly formatted
        data.pop('_id')
        # Add a correctly formatted id key in the dict
        data['id'] = str(self.pk)
        # Add a created_by
        data['created_by'] = {"id": str(self.created_by.pk), "username": self.created_by.username}
        # Return the dict as JSON
        return json_util.dumps(data)