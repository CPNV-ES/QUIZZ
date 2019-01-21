# Usage

## Routes that don't require auth

### POST - /api/register

Route to register an user

Example of payload :

```json
{
    "username": "stevenavelino",
    "password": "HelloWorld123"
}
```

Returns :

* Authentication token

### POST - /api/login

Route to login with an existing user

Example of payload :

```json
{
    "username": "stevenavelino",
    "password": "HelloWorld123"
}
```

Returns :

* Authentication token

## Routes that require basic auth

### PUT/PATCH - /api/users/{id}

Route to update an user profile

Can only update the user if user connected is the same or if the connected user is an admin

### PUT/PATCH - /api/change-password/{id}

Route to change the user password

#### Basic auth

A basic user will need to send the old_password to change it, example payload :

```json
{
    "old_password": "Hello123",
    "new_password": "World123"
}
```

#### Admin

The admin can change any user's password and only need to send the new password in the payload

### GET - /api/quizzes

Route to get the list of quizzes

Example of return value can be found [here](../example_quizzes.json)

### GET - /api/quizzes/{id}

Route to get the informations of a single quizz

Example of return value can be found [here](../example_single_quizz.json)

### POST - /api/participate/{quizz_id}

Route to submit results of a quizz answered by a player

Example of an expected payload can be found [here](../example_participation_payload.json)

## Routes that require Creator role

### GET - /api/questions

Route to get the list of questions

Example of return :

```json
{
    "questions": [
        {
            "question": "Test",
            "answers": [
                {
                    "name": "Hello2",
                    "value": "World2"
                },
                {
                    "name": "Pokemon",
                    "value": "Johto"
                }
            ],
            "image": "test.png",
            "number_answered": 3,
            "number_right": 3,
            "id": "5c35d6501b25c036310375bf"
        },
        {
            "question": "Test2",
            "answers": [
                {
                    "name": "Hello2",
                    "value": "World2"
                },
                {
                    "name": "Pokemon",
                    "value": "Johto"
                }
            ],
            "image": "test.png",
            "number_answered": 3,
            "number_right": 0,
            "id": "5c35d6731b25c037624dd9f8"
        }
    ]
}
```

### POST - /api/questions

Route to create a question

Example of expected payload :

```json
{
	"question": "Test2",
	"image": "test.png",
	"answers": [{
		"name": "Hello2",
		"value": "World2"
	},
	{
		"name": "Pokemon",
		"value": "Johto"
	}]
}
```

### GET - /api/questions/{question_id}

Route to display information about a specific question

### PUT/PATCH - /api/questions/{question_id}

Route to update an existing question

Payload similar to the POST method for questions

### DELETE - /api/questions/{question_id}

Route to delete a question

### POST - /api/quizzes

Route to create a quizz

Expected payload example :

```json
{
	"title": "Test",
	"description": "hello",
	"image": "image.png",
	"questions": ["5c1749811b25c04f05d263e8", "5c1a1cae1b25c0f05ecde1f7"]
}
```

The "questions" field is an array of questions id

### PUT/PATCH - /api/quizzes/{quizz_id}

Route to update a quizz

Payload similar to POST method

### DELETE - /api/quizzes/{quizz_id}

Route to delete a quizz

## Routes that require Admin role

### PUT/PATCH - /api/make-admin/{user_id}

Route to give admin role to an user

User can't be a guest

No additional payload needed

### PUT/PATCH - /api/make-creator/{user_id}

Route to give creator role to an user

Creator role won't be added if user is already an admin

No additional payload needed

### PUT/PATCH - /api/make-guest/{user_id}

Route to give guest role to an user

Guest role won't be added if user already a creator or an admin

No additional payload needed

### GET - /api/users

Route that returns all users

No payload needed