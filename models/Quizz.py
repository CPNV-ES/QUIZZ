from mongoengine import *
from .Question import Question
from .User import User
from bson import json_util

class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

class Quizz(Document):
    title = StringField(required=True, max_length=255)
    image = StringField(required=True)
    description = StringField(required=True)
    questions = ListField(ReferenceField(Question))
    created_by = ReferenceField(User)
    number_participants = IntField(default=0)

    meta = {'queryset_class': CustomQuerySet}

    def to_json(self):
        data = self.to_mongo()
        data.pop('_id')
        data.pop('questions')
        data['id'] = str(self.pk)
        data['created_by'] = {"id": str(self.created_by.pk), "username": self.created_by.username}
        return json_util.dumps(data)