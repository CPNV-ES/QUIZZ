from mongoengine import *
from bson import json_util

class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

class Question(Document):
    question = StringField(required=True, max_length=255)
    answers = ListField(DictField())
    image = StringField()
    number_answered = IntField(default=0)
    number_right = IntField(default=0)

    meta = {'queryset_class': CustomQuerySet}

    def to_json(self):
        data = self.to_mongo()
        data.pop('_id')
        data['id'] = str(self.pk)
        return json_util.dumps(data)