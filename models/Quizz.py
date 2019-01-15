'''
Quizz model for MongoDB database

Author : Steven Avelino
'''
from mongoengine import *
from .Question import Question
from .User import User
from bson import json_util

'''
Custom queryset for the class

Created for the purpose to modify the to_json method
'''
class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

'''
Main class for the model Quizz
'''
class Quizz(Document):
    title = StringField(required=True, max_length=255)
    image = StringField(required=True)
    description = StringField(required=True)
    questions = ListField(ReferenceField(Question))
    created_by = ReferenceField(User)
    number_participants = IntField(default=0)

    # Override the default queryset class
    meta = {'queryset_class': CustomQuerySet}

    # Override to_json method
    def to_json(self):
        # Get the object to a mongo object
        data = self.to_mongo()
        # Remove the badly formatted _id key in the dict
        data.pop('_id')
        # Pop the questions as we don't want to send them unless we specify it
        data.pop('questions')
        # Add a correctly formatted id
        data['id'] = str(self.pk)
        # Add a created_by
        data['created_by'] = {"id": str(self.created_by.pk), "username": self.created_by.username}
        # Send the JSON
        return json_util.dumps(data)