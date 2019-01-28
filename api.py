'''
Main file for the API

Author : Steven Avelino <steven.avelino@cpnv.ch
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
api = responder.API(cors=True, cors_params={"allow_origins": ["*"], "allow_methods": ["*"], "allow_headers": ["*"]})

'''
Register endpoint

Frontend should give a username and password.

Returns the token for the user
'''
@api.route('/api/register')
async def register(req, resp):
    try:
        if req.method == 'post':
            data = await req.media()
            # Check if data sent is valid
            if 'username' in data and 'password' in data:
                # Encrypt the password
                encrypted_password = pwd_context.hash(data['password'])
                # Create the JWT token from the username and the password
                token = encrypt(data['username'], encrypted_password)
                # Create the user in MongoDB
                new_user = User(username=data['username'], token=token.decode('UTF-8'), password=encrypted_password)
                new_user.save(validate=True)
                # Return the token to the frontend
                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'token': token.decode('UTF-8')}
            else:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'Invalid data sent'}
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
    if req.method == 'post':
        data = await req.media()
        # Check if data sent is valid
        if 'username' in data and 'password' in data:
            # Check if the user exists
            if User.objects(username=data['username']):
                # Get the user from the db based on the username
                user = User.objects.get(username=data['username'])
                # Check the password
                if pwd_context.verify(data['password'], user.password):
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
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Invalid data sent'}

'''
Route to get the list of all users
'''
@api.route('/api/users')
def users(req, resp):
    if 'quizz-token' in req.headers:
        if check_token(req.headers['quizz-token'], True, False):
            if req.method == 'get':
                resp.status_code = api.status_codes.HTTP_200
                resp.media = {'users': json.loads(User.objects.all().to_json())}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
Route to get all informations from a user

Parameters:
    - id : id of the user
'''
@api.route('/api/users/{id}')
async def users_id(req, resp, *, id):
    # Check if the token is sent in the headers
    if 'quizz-token' in req.headers:
        # Check if user is logged in
        if check_token(req.headers['quizz-token'], False, False):
            # Check if user exists
            if User.objects(id=id):
                user = User.objects.get(id=id)
                # Returns the user if method is get
                if req.method == 'get':
                    resp.status_code = api.status_codes.HTTP_200
                    resp.media = {'user': json.loads(user.to_json())}
                elif req.method == 'put' or req.method == 'patch':
                    # Get the user making the request
                    auth_user = User.objects.get(token=req.headers['quizz-token'])
                    # Check if the user is trying to update his profile or is and admin
                    if True if str(auth_user.pk) == id else True if check_token(req.headers['quizz-token'], True, False) else False:
                        data = await req.media()
                        if 'username' in data:
                            user.username = data['username']
                            old_token = decrypt(user.token)
                            token = encrypt(data['username'], old_token['password'])
                            user.token = token.decode('UTF-8')
                            user.save(validate=True)

                            resp.status_code = api.status_codes.HTTP_200
                            resp.media = {'token': token.decode('UTF-8')}
                        else:
                            resp.status_code = api.status_codes.HTTP_401
                            resp.media = {'message': 'data sent not valid'}
                    else:
                        resp.status_code = api.status_codes.HTTP_403
                        resp.media = {'message': 'Not an admin'}

                elif req.method == 'delete':
                    # Must be an admin to delete an user
                    if check_token(req.headers['quizz-token'], True, False):
                        user.delete()

                        resp.status_code = api.status_codes.HTTP_200
                        resp.media = {'user': user}
                    else:
                        resp.status_code = api.status_codes.HTTP_403
                        resp.media = {'message': 'Not an admin'}
            else:
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'This user doesn\'t exist'}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
Route to change the password of a user

Parameters:
    - id : id of the user
'''
@api.route('/api/change-password/{id}')
async def change_password(req, resp, *, id):
    # check if token is sent in the request
    if 'quizz-token' in req.headers:
        # Check if the user is authenticated
        if check_token(req.headers['quizz-token'], False, False):
            if User.objects(id=id):
                if req.method == 'put' or req.method == 'patch':
                    data = await req.media()
                    user = User.objects.get(id=id)
                    auth_user = User.objects.get(token=req.headers['quizz-token'])
                    # Check if the user is trying to update his password or is an admin
                    if True if auth_user.id == id else True if check_token(req.headers['quizz-token'], True, False) else False:
                        # If the user is an admin, only check if new_password exists. If not, check for old_password and new_password
                        if True if auth_user.admin == True and 'new_password' in data else True if 'old_password' in data and 'new_password' in data else False:
                            # If user is an admin, just pass. If not, check if the password in db is the same as the one sent in the request
                            if auth_user.admin == True or pwd_context.verify(data['old_password'], user.password):
                                # Encrypt the password
                                encrypted_password = pwd_context.hash(data['new_password'])
                                # Create the JWT token from the username and the password
                                token = encrypt(user.username, encrypted_password)
                                user.password = encrypted_password
                                user.token = token.decode('UTF-8')
                                user.save(validate=True)
                                resp.status_code = api.status_codes.HTTP_200
                                resp.media = {'token': token.decode('UTF-8')}
                            else:
                                resp.status_code = api.status_codes.HTTP_401
                                resp.media = {'message': 'old password does not match'}
                        else:
                            resp.status_code = api.status_codes.HTTP_401
                            resp.media = {'message': 'data sent not valid'}
                    else:
                        resp.status_code = api.status_codes.HTTP_403
                        resp.media = {'message': 'Not an admin'}
            else:
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'This user doesn\'t exist'}
        else:
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
Route to give the admin role to user

The user calling this route must already be an admin

Parameters :
    - id : id of the user to give the admin role
'''
@api.route('/api/make-admin/{id}')
def make_admin(req, resp, *, id):
    if 'quizz-token' in req.headers:
        if req.method == 'put' or req.method == 'patch':
            if check_token(req.headers['quizz-token'], True, False):
                if User.objects(id=id):
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
                    resp.media = {'message': 'This user doesn\'t exist'}
            else:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
Route to give the creator role to user

The user calling this route must be an admin

Parameters :
    - id : id of the user to give the creator role
'''
@api.route('/api/make-creator/{id}')
def make_creator(req, resp, *, id):
    if 'quizz-token' in req.headers:
        if req.method == 'put' or req.method == 'patch':
            if check_token(req.headers['quizz-token'], True, False):
                if User.objects(id=id):
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
                    resp.media = {'message': 'This user doesn\'t exist'}
            else:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
Route to give the guest role to user

The user calling this route must be an admin

Parameters :
    - id : id of the user to give the guest role
'''
@api.route('/api/make-guest/{id}')
def make_guest(req, resp, *, id):
    if 'quizz-token' in req.headers:
        if req.method == 'put' or req.method == 'patch':
            if check_token(req.headers['quizz-token'], True, False):
                if User.objects(id=id):
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
                    resp.media = {'message': 'This user doesn\'t exist'}
            else:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'Not authenticated or not authorized'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
POST and GET endpoints for Questions

Frontend needs to pass the token in the request header

Returns a list of questions in GET
Returns a success message on POST
'''

@api.route('/api/questions')
async def questions(req, resp):
    if 'quizz-token' in req.headers:
        # Check the HTTP request method
        if req.method == 'get':
            # Check if user is authenticated
            if check_token(req.headers['quizz-token'], False, True):
                # Get the user
                user = User.objects.get(token=req.headers['quizz-token'])
                resp.status_code = api.status_codes.HTTP_200
                if user.admin == True:
                    resp.media = {'questions': json.loads(Question.objects.all().to_json())}
                else:
                    resp.media = {'questions': json.loads(Question.objects(created_by=user).to_json())}
            # If not, a message will notify the user
            else:
                resp.status_code = api.status_codes.HTTP_403
                resp.media = {'message': 'Not authenticated'}
        elif req.method == 'post':
            # Check if the user is authenticated and is admin
            if check_token(req.headers['quizz-token'], False, True):
                try:
                    data = await req.media()
                    # Check if the question has at least 2 answers and 4 or less answers
                    if len(data['answers']) >= 2 and len(data['answers']) <= 4:
                        if 'question' in data and 'image' in data:
                            answers_not_valid = False
                            for answer in data['answers']:
                                # Check if the answers have the right attributes
                                if 'name' not in answer or 'value' not in answer:
                                    answers_not_valid = True
                                else:
                                    if isinstance(answer['value'], bool) and isinstance(answer['name'], str):
                                        answers_not_valid = False
                                    else:
                                        answers_not_valid = True
                            if not answers_not_valid:
                                # Get the user to put in created_by
                                user = User.objects.get(token=req.headers['quizz-token'])
                                # Create the question
                                new_question = Question(question=data['question'], image=data['image'], answers=data['answers'], created_by=user)
                                new_question.save(validate=True)
                                # Return a successful message to the frontend
                                resp.status_code = api.status_codes.HTTP_200
                                resp.media = {'question': json.loads(new_question.to_json())}
                            else:
                                resp.status_code = api.status_codes.HTTP_401
                                resp.media = {'message': 'data sent is not valid'}
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
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
PUT and DELETE method for questions

Paramaters :
    id : id of question

return the question selected
'''

@api.route('/api/questions/{id}')
async def questions_id(req, resp, *, id):
    if 'quizz-token' in req.headers:
        # Check if user is authenticated and admin if method is not get
        if check_token(req.headers['quizz-token'], False, True):
            # Check if question exists
            if Question.objects(id=id):
                # Get the question with the id in the request
                question = Question.objects.get(id=id)
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
                        # Check if the question has at least 2 answers and 4 or less answers
                        if len(data['answers']) >= 2 and len(data['answers']) <= 4:
                            if 'question' in data and 'image' in data:
                                answers_not_valid = False
                                for answer in data['answers']:
                                    # Check if the answers have the right attributes
                                    if 'name' not in answer or 'value' not in answer:
                                        answers_not_valid = True
                                    else:
                                        if isinstance(answer['value'], bool) and isinstance(answer['name'], str):
                                            answers_not_valid = False
                                        else:
                                            answers_not_valid = True
                                if not answers_not_valid:
                                    question.question = data['question']
                                    question.image = data['image']
                                    question.answers = data['answers']
                                    question.save()
                                    # Return the question if successful
                                    resp.status_code = api.status_codes.HTTP_200
                                    resp.media = {'question': json.loads(question.to_json())}
                                else:
                                    resp.status_code = api.status_codes.HTTP_401
                                    resp.media = {'message': 'data sent is not valid'}
                        else:
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
                # Return an error if the question was not found
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'Question was not found'}
        else:
            # Return an error if the user is not authenticated
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
POST and GET endpoints for quizzes

Frontend needs to pass the token in the request header

Returns the list of quizzes if method is get
Returns a successful message if quizz was created
'''
@api.route('/api/quizzes')
async def quizzes(req, resp):
    if 'quizz-token' in req.headers:
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
                        if Question.objects(id=question_id):
                            quizz_answer = Question.objects.get(id=question_id)
                            questions.append(quizz_answer)
                        else:
                            resp.status_code = api.status_codes.HTTP_401
                            resp.media = {'message': f'Question with the id : {question_id} does not exist'}
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
                            resp.media = {'message': 'Data sent not valid'}
                    else:
                        # Return an error if not 2 questions or more
                        resp.status_code = api.status_codes.HTTP_401
                        resp.media = {'message': 'Not enough questions'}
                except ValidationError as validation_error:
                    # Return an error if data not valid
                    resp.status_code = api.status_codes.HTTP_401
                    resp.media = {'message': validation_error}
            else:
                # Return error if the HTTP Verb is wrong
                resp.status_code = api.status_codes.HTTP_401
                resp.media = {'message': 'Wrong HTTP Verb'}
        else:
            # Return an error if the user is not authenticated
            resp.status_code = api.status_codes.HTTP_403
            resp.media = {'message': 'Not authenticated'}
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

'''
PUT/PATCH and DELETE route for quizzes

Parameters:

id : id of the quizz

Returns the quizz that was edited or deleted
'''
@api.route('/api/quizzes/{id}')
async def quizzes_id(req, resp, *, id):
    if 'quizz-token' in req.headers:
        # Check if user is authenticated and admin
        if check_token(req.headers['quizz-token'], False, False if req.method == 'get' else True):
            # Check if the quizz exists
            if (Quizz.objects(id=id)):
                # Get the quizz from the id in the request
                quizz = Quizz.objects.get(id=id)
                if req.method == 'get':
                    questions = []
                    for question in quizz.questions:
                        questions.append({'id': str(question.pk), 'question': question.question, 'image': question.image, 'answers': question.answers})
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
                            if Question.objects(id=question_id):
                                quizz_answer = Question.objects.get(id=question_id)
                                questions.append(quizz_answer)
                            else:
                                resp.status_code = api.status_codes.HTTP_401
                                resp.media = {'message': f'Question with the id : {question_id} does not exist'}
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
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}


'''
Route to submit a user participation to a quizz

Parameters:
  - id : id of the quizz

Returns a successful message 
'''
@api.route('/api/participate/{id}')
async def submit_quizz(req, resp, *, id):
    if 'quizz-token' in req.headers:
        # Anybody can use this route as long as authenticated
        if check_token(req.headers['quizz-token'], False, False):
            if Quizz.objects(id=id):
                # Check if the quizz exists
                quizz = Quizz.objects.get(id=id)
                data = await req.media()
                # Check if the user is not a guest
                if not check_guest(req.headers['quizz-token']):
                    # If not, add the quizz score to the authenticated user
                    user = User.objects.get(token=req.headers['quizz-token'])
                    # Flag to check if the user already played this quizz
                    found = False
                    for index, score in enumerate(user.scores):
                        # If user already played, check if the score was better than before
                        if score['quizz'].id == quizz.pk:
                            found = True
                            if score['score'] < data['score']:
                                user.scores[index]['score'] = data['score']
                    # Add the quizz if not found and add a participant to the quizz
                    if not found:
                        user.scores.append({ 'quizz': { 'id': str(quizz.pk), 'title': quizz.title }, 'score': data['score'] })
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
    else:
        resp.status_code = api.status_codes.HTTP_403
        resp.media = {'message': 'auth token not sent in request'}

api.run()