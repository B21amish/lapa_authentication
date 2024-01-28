from enum import Enum


class User(Enum):
    user_email_id = "user_email_id"
    user_password_salt = "user_password_salt"
    user_password_hash = "user_password_hash"


class UserValidation(Enum):
    user_validation_status_id = "user_validation_status_id"
    status_description = "status_description"


class UserRegistration(Enum):
    user_registration_id = "user_registration_id"
    registration_description = "registration_description"


class HashingAlgorithm(Enum):
    hash_algorithm_id = "hash_algorithm_id"
    algorithm_name = "algorithm_name"
