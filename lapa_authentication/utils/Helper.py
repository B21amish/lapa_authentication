from lapa_database_helper.main import LAPADatabaseHelper


from lapa_authentication.utils.CommonEnums import (
    HashingAlgorithm,
    UserRegistration,
    UserValidation,
)
from lapa_authentication.configuration import (
    config_str_database_name,
    config_str_schema_name,
    config_str_user_validation_status_table_name,
    config_str_user_registration_table_name,
    config_str_hashing_algorithm_table_name,
)
local_object_lapa_database_helper = LAPADatabaseHelper()


def get_user_validation_status_id(pstr_status_description: str = "pending") -> int:
    """
    Description - This function is used to retrieve the status_id for the pending status when the user is created
    for the first time in the authentication system.
    :param pstr_status_description: pending
    :return: status_id
    """
    ldict_filter_condition = dict()
    try:
        ldict_filter_condition[
            UserValidation.status_description.value
        ] = pstr_status_description
        user_validation = local_object_lapa_database_helper.get_rows(
            database_name=config_str_database_name,
            schema_name=config_str_schema_name,
            table_name=config_str_user_validation_status_table_name,
            filters=ldict_filter_condition,
            ignore_filters_and_get_all=False,
        )
        return user_validation[0][UserValidation.user_validation_status_id.value]
    except Exception:
        raise
    finally:
        del ldict_filter_condition


def get_user_registration_id(pstr_registration_description: str) -> int:
    """
    Description - This function is used to retrieve the registration_id for the registration_description.
    :param pstr_registration_description: email
    :return: registration_id
    """
    ldict_filter_condition = dict()
    try:
        ldict_filter_condition[
            UserRegistration.registration_description.value
        ] = pstr_registration_description

        user_registration = local_object_lapa_database_helper.get_rows(
            database_name=config_str_database_name,
            schema_name=config_str_schema_name,
            table_name=config_str_user_registration_table_name,
            filters=ldict_filter_condition,
            ignore_filters_and_get_all=False,
        )
        return user_registration[0][UserRegistration.user_registration_id.value]
    except Exception:
        raise
    finally:
        del ldict_filter_condition


def get_hash_algorithm_id(pstr_algorithm_name: str = "bcrypt") -> int:
    """
    Description - This function is used to retrieve the hash_algorithm_id for the algorithm_name.
    :param pstr_algorithm_name: bcrypt
    :return: hash_algorithm_id
    """
    ldict_filter_condition = dict()
    try:
        ldict_filter_condition[
            HashingAlgorithm.algorithm_name.value
        ] = pstr_algorithm_name
        hashing_algorithm = local_object_lapa_database_helper.get_rows(
            database_name=config_str_database_name,
            schema_name=config_str_schema_name,
            table_name=config_str_hashing_algorithm_table_name,
            filters=ldict_filter_condition,
            ignore_filters_and_get_all=False,
        )
        return hashing_algorithm[0][HashingAlgorithm.hash_algorithm_id.value]
    except Exception:
        raise
    finally:
        del ldict_filter_condition
