# QUIZZ

Backend for the quizz application

## How to install locally

### Tools required

* MongoDB Database
* Python 3.6 or later
* pipenv

### Installation

* Create a MongoDB Database
* run 'pipenv install' in the project folder
* Change the name of the DB in the 'api.py' file

#### Change the name of the DB

If the database is local, only the name of the DB needs to be changed.
You can do so by changing the string inside the method 'connect' in the file 'api.py' (Top of the file).

If the database isn't local, you need to specify the host as a second parameter and the port as the third, like so :

```python
connect('awa_quizzes', host='host.com', port=54321)
```

## Run the application

You can simply run this command inside the project folder :

```bash
pipenv run python3 api.py
```

## API routes documentation

[Link to the doc](./docs/Usage.md)

## API Architecture documentation

[Link to the doc](./docs/Architecture.md)

## Dev documentation

[Link to the doc](./docs/Dev.md)

## Links

* [Responder docs](https://python-responder.org/en/latest/quickstart.html)
* [Mongoengine docs](http://docs.mongoengine.org/index.html)
* [Pyjwt docs](https://pyjwt.readthedocs.io/en/latest/)
* [Passlib docs](https://passlib.readthedocs.io/en/stable/)
