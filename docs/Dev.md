# Development documentation

## File structure

### docs

Folder with all the documentation

### models

Folder with all the models

#### Question.py

File that contains the model for the questions

#### Quizz.py

File that contains the model for the quizzes

#### User.py

File that containes the model for the users

### utils

Folder that contains all the files that contains useful methods

#### security.py

File that contains every security related methods

#### token_managament.py

File that contains every JWT token related methods

### api.py

Main file for the project.

It's the entry point as well as containing all the routes

### Pipfile

List all dependencies for pipenv

### Procfile

File for Heroku deployment

### README.md

Simple README for the project

## Possible improvements

### Use class based views

The project initially puts all the logic in the routes declarations, while it works, it's not incredibly clean and Responder has class based views

### Tests

To make sure that the API works, tests are necessary.
As the time was limited during the development of the project, tests couldn't be done.
Testing every route with good parameters and bad parameters would be the best

### Make a validation class

In most framework, validations are part of the core. Since Responder is fairly new, validations are not done yet.
The project validates the data manually in each route depending on the need.

It would be best to create a Laravel-like validation system to reuse it easily.

### Make a deploy script

It is easy to deploy the project on Heroku, however having a script that will do every step of the process for us would be best.
It will also pass the tests before deploying so we're sure the release that we want to deploy is production ready