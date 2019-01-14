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

### GET - /api/quizzes

Route to get the list of quizzes

Example of return value can be found [here](../example_quizzes.json)