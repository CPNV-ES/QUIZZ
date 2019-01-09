from mongoengine import *
from .Question import Question
from .User import User
from bson import json_util

class CustomQuerySet(QuerySet):
    def to_json(self):
        return "[%s]" % (",".join([doc.to_json() for doc in self]))

class Quizz(Document):
    name = StringField(required=True, max_length=255)
    image = ImageField()
    description = StringField(required=True)
    questions = ListField(ReferenceField(Question))
    created_by = ReferenceField(User)
    number_participants = IntField(default=0)

    meta = {'queryset_class': CustomQuerySet}

    def to_json(self):
        data = self.to_mongo()
        questions = []
        for question in self.questions:
            questions.append({ "name": question.name, "answers": question.answers })
        data['questions'] = questions
        data.pop('_id')
        data['id'] = str(self.pk)
        data['created_by'] = {"id": str(self.created_by.pk), "username": self.created_by.username}
        return json_util.dumps(data)