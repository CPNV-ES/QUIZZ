'''
Main file for the API

author : Steven Avelino <steven.avelino@cpnv.ch
'''

import responder
import json
from mongoengine import *
from models.User import User
from models.Quizz import Quizz
from models.Question import Question
from utils.token_management import encrypt, decrypt
from utils.security import pwd_context, check_token, check_guest
import os

'''
Connect to the database

Connect to the mlab Database if the env variable IS_HEROKU is set to True

Else, just use a local database
'''
if os.environ.get('IS_HEROKU'):
    connect('awa_quizzes', host=f"mongodb://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@ds117209.mlab.com:17209/awa_quizzes")
else:
    connect('awa_quizzes')

# Create the responder API instance
api = responder.API()

'''
Register endpoint

Frontend should give a username and password.

Returns the token for the user
'''
@api.route('/api/register')
async def register(req, resp):
    try:
        data = await req.media()
        # Encrypt the password
        encrypted_password = pwd_context.encrypt(data['password'])
        # Create the JWT token from the username and the password
        token = encrypt(data['username'], encrypted_password)
        # Create the user in MongoDB
        new_user = User(username=data['username'], token=token, password=encrypted_password)
        new_user.save(validate=True)
        # Return the token to the frontend
        resp.status_code = api.status_codes.HTTP_200
        resp.media = {'token': str(token)}
    except ValidationError as validation_error:
        # Returns the error if the data sent wasn't compliant
        resp.status_code = api.status_codes.HTTP_401
        resp.media = {'message': validation_error}

'''
Login endpoint

Frontend should give a username and a password

Returns the token of the user
'''
@api.route('/api/login')
async def login(req, resp):
    data = await req.media()
    # Get the user from the db based on the username
    user = User.objects.get(username=data['username'])
    # Check if the user exists
    if (user):
        # Check the password
        if (pwd_context.verify(data['password'], user.password)):
            # Returns the token if password matches
            resp.status_code = api.status_codes.HTTP_200
            resp.media = {'token': user.token}
        else:
            # Returns an error if passwords don't match
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'The password is not correct'}
    else:
        # If user doesn't exist, notify the frontend
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'This username doesn\'t exist'}

'''
Route to give the admin role to user

The user calling this route must already be an admin

Parameters :
    - id : id of the user to give the admin role
'''
@api.route('/api/make-admin/{id}')
def make_admin(req, resp, *, id):
    if (req.method == 'put' or req.method == 'patch'):
        if (check_token(req.headers['quizz-token'], True, False)):
            user = User.objects.get(id=id)
            # Check if the user is a guest
            if user.guest == True:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'user is a guest'}
            else:
                user.admin = True
                user.save(validate=True)

                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'user': user}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}

'''
Route to give the creator role to user

The user calling this route must be an admin

Parameters :
    - id : id of the user to give the creator role
'''
@api.route('/api/make-creator/{id}')
def make_creator(req, resp, *, id):
    if (req.method == 'put' or req.method == 'patch'):
        if (check_token(req.headers['quizz-token'], True, False)):
            user = User.objects.get(id=id)
            if user.admin == True or user.guest == True:
                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'message': 'User already an admin or a guest'}
            else:
                user.creator = True
                user.save(validate=True)

                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'user': user}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}

'''
Route to give the guest role to user

The user calling this route must be an admin

Parameters :
    - id : id of the user to give the guest role
'''
@api.route('/api/make-guest/{id}')
def make_guest(req, resp, *, id):
    if (req.method == 'put' or req.method == 'patch'):
        if (check_token(req.headers['quizz-token'], True, False)):
            user = User.objects.get(id=id)
            if user.admin == True or user.creator == True:
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'User already an admin or a creator'}
            else:
                user.guest = True
                user.save(validate=True)

                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'user': user}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}

'''
POST and GET endpoints for Questions

Frontend needs to pass the token in the request header

Returns a list of questions in GET
Returns a success message on POST
'''

@api.route('/api/questions')
async def questions(req, resp):
    # Check the HTTP request method
    if (req.method == 'get'):
        # Check if user is authenticated
        if (check_token(req.headers['quizz-token'], False, True)):
            resp.status_code = api.status_codes.HTTP_200
            resp.media = {'questions': json.loads(Question.objects.all().to_json())}
        # If not, a message will notify the user
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated'}
    elif (req.method == 'post'):
        # Check if the user is authenticated and is admin
        if (check_token(req.headers['quizz-token'], False, True)):
            try:
                data = await req.media()
                # Check if the question has at least 2 answers and 4 or less answers
                if len(data['answers']) >= 2 and len(data['answers']) <= 4:
                    for answer in data['answers']:
                        # Check if the answers have the right attributes
                        if hasattr(answer, 'value') and hasattr(answer, 'correct'):
                            continue
                        else:
                            resp.status_code = api.status_codes.HTTP_401
                            resp.media = {'message': 'data sent isn\'t valid'}
                    if 'question' in data and 'image' in data:
                        # Create the question
                        new_question = Question(question=data['question'], image=data['image'], answers=data['answers'])
                        new_question.save(validate=True)
                        # Return a successful message to the frontend
                        resp.status_code = api.status_codes.HTTP_200
                        resp.media = {'message': f"Question : {data['question']} was created"}
                else:
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': 'A question must have between 2 and 4 answers'}
            # If data sent is not valid
            except ValidationError as validation_error:
                # Return an error message
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': validation_error}
        else:
            # Return an error message if user is not authenticated or admin
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not admin'}

'''
PUT and DELETE method for questions

Paramaters :
    id : id of question

return the question selected
'''

@api.route('/api/questions/{id}')
async def questions_id(req, resp, *, id):
    # Check if user is authenticated and admin if method is not get
    if check_token(req.headers['quizz-token'], False, True):
         # Get the question with the id in the request
        question = Question.objects.get(id=id)
        # Check if question exists
        if question:
            # Block for get method
            if req.method == 'get':
                # Return question
                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'question': json.loads(question.to_json())}
            # Block for delete method
            elif req.method == 'delete':
                try:
                    # Delete the question
                    question.delete()
                    # Return the deleted question
                    resp.status_code = api.status_codes.HTTP_200
                    resp.media = {'question': json.loads(question.to_json())}
                # Return an error if question can't be deleted
                except Exception as e:
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': e}
            # Block for put or patch method
            elif req.method == 'put' or req.method == 'patch':
                try:
                    # Get the data from the request
                    data = await req.media()
                    #Check if there's between 2 and 4 answers
                    if len(data['answers']) >= 2 and len(data['answers']) <= 4:
                        for answer in data['answers']:
                            # Check if the answers have the right attributes
                            if hasattr(answer, 'value') and hasattr(answer, 'correct'):
                                continue
                            else:
                                resp.status_code = api.status_codes.HTTP_401
                                resp.media = {'message': 'data sent isn\'t valid'}
                        # Assign the new values and save it
                        if 'question' in data and 'image' in data:
                            question.question = data['question']
                            question.image = data['image']
                            question.answers = data['answers']
                            question.save()
                            # Return the question if successful
                            resp.status_code = api.status_codes.HTTP_200
                            resp.media = {'question': json.loads(question.to_json())}
                    else:
                        # Return an error if the number answers is incorrect
                        resp.status_code = api.status_codes.HTTP_401
                        resp.media = {'message': 'A question must have between 2 and 4 answers'}
                # Throw an error if data wasn't valid
                except ValidationError as validation_error:
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': validation_error}
            else:
                # Return error if the HTTP Verb is wrong
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'Wrong HTTP Verb'}
        else:
            # Return an error if the question was not foun
            resp.status_code = api.status_codes.HTTP_401
            resp.media = {'message': 'Question was not found'}
    else:
        # Return an error if the user is not authenticated
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'Not authenticated'}

'''
POST and GET endpoints for quizzes

Frontend needs to pass the token in the request header

Returns the list of quizzes if method is get
Returns a successful message if quizz was created
'''
@api.route('/api/quizzes')
async def quizzes(req, resp):
    # Check if user is authenticated and admin if method is not get
    if check_token(req.headers['quizz-token'], False, False if req.method == 'get' else True):
        if req.method == 'get':
            # Return all quizzes
            resp.status_code = api.status_codes.HTTP_200
            resp.media = {'quizzes': json.loads(Quizz.objects.all().to_json())}
        elif req.method == 'post':
            try:
                questions = []
                # Get data from request
                data = await req.media()
                # Get all questions from array of id
                for question_id in data['questions']:
                    quizz_answer = Question.objects.get(id=question_id)
                    questions.append(quizz_answer)
                # Check if more than 2 questions
                if len(questions) >= 2:
                    # Check if data sent has all informations needed
                    if 'title' in data and 'description' in data and 'image' in data:
                        # Get the user to put in created_by
                        user = User.objects.get(token=req.headers['quizz-token'])
                        # Create quizz
                        new_quizz = Quizz(title=data['title'], description=data['description'], image=data['image'], questions=questions, created_by=user)
                        new_quizz.save(validate=True)
                        # Return the new quizz
                        resp.status_code = api.status_codes.HTTP_200
                        resp.media = {'quizz': json.loads(new_quizz.to_json())}
                    else:
                        resp.status_code = api.status_codes.HTTP_401
                        resp.media = {'type': 'error', 'message': 'Data sent not valid'}
                else:
                    # Return an error if not 2 questions or more
                    resp.status_codes = api.status_codes.HTTP_401
                    resp.media = {'type': 'error', 'message': 'Not enough questions'}
            except ValidationError as validation_error:
                # Return an error if data not valid
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'type': 'error', 'message': validation_error}
        else:
            # Return error if the HTTP Verb is wrong
            resp.status_code = api.status_codes.HTTP_401
            resp.media = {'type': 'error', 'message': 'Wrong HTTP Verb'}
    else:
        # Return an error if the user is not authenticated
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'type': 'error', 'message': 'Not authenticated'}

'''
PUT/PATCH and DELETE route for quizzes

Parameters:

id : id of the quizz

Returns the quizz that was edited or deleted
'''
@api.route('/api/quizzes/{id}')
async def quizzes_id(req, resp, *, id):
    # Check if user is authenticated and admin
    if check_token(req.headers['quizz-token'], False, False if req.method == 'get' else True):
        # Get the quizz from the id in the request
        quizz = Quizz.objects.get(id=id)
        # Check if the quizz exists
        if (quizz):
            if req.method == 'get':
                questions = []
                for question in quizz.questions:
                    questions.append({'question': question.question, 'image': question.image, 'answers': question.answers})
                # Returns question
                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'id': str(quizz.pk), 'title': quizz.title, 'description': quizz.description, 'created_by': quizz.created_by.username, 'questions': questions, 'number_participants': quizz.number_participants}
            # Put/Patch method block
            if (req.method == 'put' or req.method == 'patch'):
                try:
                    questions = []
                    # Get the data from the request
                    data = await req.media()
                    # Update the quizz
                    if 'title' in data and 'description' in data and 'image' in data:
                        quizz.title = data['title']
                        quizz.decription = data['decription']
                        quizz.image = data['image']
                    for question_id in data['questions']:
                        quizz_answer = Question.objects.get(id=question_id)
                        questions.append(quizz_answer)
                    if len(questions) >= 2:
                        quizz.questions = questions
                    else:
                        # Return an error if not 2 questions or more
                        resp.status_codes = api.status_codes.HTTP_401
                        resp.media = {'message': 'Not enough questions'}
                    quizz.save()
                    # Return the updated quizz
                    resp.status_code = api.status_codes.HTTP_200
                    resp.media = {'quizz': quizz}
                # Catch a validation error
                except ValidationError as validation_error:
                    # Throw an error
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': validation_error}
            elif (req.method is 'delete'):
                try:
                    # Delete the quizz
                    quizz.delete()
                    resp.status_code = api.status_codes.HTTP_200
                    resp.media = {'quizz': quizz}
                except Exception as e:
                    # Throw an error if something occured
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': e}
        # If quizz doesn't exist, throw an error
        else:
            resp.status_code = api.status_codes.HTTP_401
            resp.media = {'message': 'The quizz couldn\'t be found'}
    # Throw an error if user is not authenticated or an admin
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'Not authenticated or not admin'}


'''
Route to submit a user participation to a quizz

Parameters:
  - id : id of the quizz

Returns a successful message 
'''
@api.route('/api/participate/{id}')
async def submit_quizz(req, resp, *, id):
    # Anybody can use this route as long as authenticated
    if check_token(req.headers['quizz-token'], False, False):
        # Check if the quizz exists
        quizz = Quizz.objects.get(id=id)
        if quizz:
            data = await req.media()
            # Check if the user is not a guest
            if not check_guest(req.headers['quizz-token']):
                # If not, add the quizz score to the authenticated user
                user = User.objects.get(token=req.headers['quizz-token'])
                # Flag to check if the user already played this quizz
                found = False
                for index, score in enumerate(user.scores):
                    # If user already played, check if the score was better than before
                    if score['quizz_id'] == quizz.pk:
                        found = True
                        if score['score'] < data['score']:
                            user.scores[index]['score'] = data['score']
                # Add the quizz if not found and add a participant to the quizz
                if not found:
                    user.scores.append({ 'quizz_id': quizz.pk, 'score': data['score'] })
                    quizz.number_participants += 1
                    quizz.save(validate=True)
                user.save(validate=True)
            # Get the questions answered
            for question in data['questions']:
                db_question = Question.objects.get(id=question['id'])
                # Add an answered
                db_question.number_answered += 1
                # If the user got it right, add a correct answer to the question
                if question['right']:
                    db_question.number_right += 1
                db_question.save(validate=True)
            resp.status_code = api.status_codes.HTTP_200
            resp.media = {'message': 'quizz successfully answered'}
        else:
            resp.status_code = api.status_codes.HTTP_401
            resp.media = {'message': 'The quizz couldn\'t be found'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'Not authenticated'}

api.run()