# Architecture

## DB Architecture

### Questions

```json
{
    "id": ID,
    "question": String,
    "answers": [
        {
            "value": String,
            "correct": Boolean
        }
    ],
    "image": String,
    "number_answered": Int,
    "number_right": Int
}
```

### Quizzes

```json
{
    "title": String,
    "image": String,
    "description": String,
    "question": Array<Reference<Question>>,
    "created_by": Reference<User>,
    "number_participants": Int
}
```

### Users

```json
{
    "username": String,
    "password": Hashed<String>,
    "token": String,
    "scores": [
        {
            "quizz_id": ID<Quizz>,
            "score": INT
        }
    ],
    "admin": Boolean,
    "creator": Boolean,
    "guest": Boolean
}
```

## API Architecture

Questions and Quizzes have complete CRUDs.

As for Users, we can login and register, as well as change the roles (if admin).

