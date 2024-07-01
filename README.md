# lapa_authentication

## About

Authentication service

## Installation

> pip install lapa_authentication

## Env

- python>=3.12.0

## Changelog

### v0.0.20

- https support

### v0.0.19

- bugfix in login and register call (update column name).

### v0.0.18

- remove device entity.
- keep refresh token without hashing in database.

### v0.0.17

- changed jwt token creation timezone to utc.
- handled token expiry exception while decoding token.

### v0.0.16

- update repo link in setup.py
- keep version numbers for square_logger and lapa_database_structure as >= instead of ~=.
- add SQUARE_LOGGER and LAPA_DATABASE_HELPER sections in config and initialise their sdk as per those variables.

### v0.0.15

- add new call for /logout.

### v0.0.14

- add new call for /generate_access_token.

### v0.0.13

- add custom message and status code for duplicate username.
- delete session if already present on same device for same user.
- encrypt mac_address in login and register.
- keep seperate secret keys for access token refresh token and mac address encrpytion.

### v0.0.12

- create entry in device table and user_session_device table for login and register.

### v0.0.11

- changes in login and register calls as per database structure changes (naming convention)

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
