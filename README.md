# lapa_authentication

## About

Authentication service

## Installation

> pip install lapa_authentication

## Env

- python>=3.12.0

## Changelog

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
