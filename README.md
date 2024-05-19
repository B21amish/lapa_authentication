# lapa_authentication

## About

Authentication service

## Installation

> pip install lapa_authentication

## Env

- python>=3.12.0

## Changelog

### v0.0.10

- changes in register calls w.r.t new table Credential 

### v0.0.9

- fix missing dependencies in setup.py

### v0.0.8

- remove salt storing from register.
- implement login route.

### v0.0.7

- overhaul register logic.
- overhaul tablename import logic.

### v0.0.6

- syntax error fix in main.py.

### v0.0.5

- update database tables.
- move reading of database tables to configuration.py.

### v0.0.4

- bug fix - add "email_validator>=2.0.0" in dependencies.

### v0.0.3

- use lapa_commons to read config.

### v0.0.2

- move logger to configuration.py.
- remove unused dependencies.
- add lapa_database_helper.

### v0.0.1

1. /register endpoint added.
    1. Before adding user into the authentication server. It will first check if the user's email-id is already present
       in the database or not.
        1. If Yes -> Do not create entry in the database. Return message saying user already exists.
        2. If No -> Create entry in the database. Return message saying user created successfully.
