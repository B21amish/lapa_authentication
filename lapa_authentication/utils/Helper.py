from http import HTTPStatus

import requests
from database_structure.main import DatabasesEnum, TablesEnum, SchemaEnum
from square_logger.main import SquareLogger

from lapa_authentication.configuration import config_str_log_file_name, database_api_url
from lapa_authentication.utils.CommonEnums import DatabaseEndpoint, UserRegistration, HashingAlgorithm, UserValidation

local_object_square_logger = SquareLogger(config_str_log_file_name)


def get_rows_wrapper(pstr_database_name: str,
                     pstr_table_name: str,
                     pstr_schema_name: str,
                     pdict_filter_condition: dict) -> list:
    """
    Description - This function is a wrapper for calling the database endpoint for get_rows.
    """
    ldict_get_rows_context = dict()
    try:
        ldict_get_rows_context['database_name'] = pstr_database_name
        ldict_get_rows_context['table_name'] = pstr_table_name
        ldict_get_rows_context['schema_name'] = pstr_schema_name
        ldict_get_rows_context['filters'] = pdict_filter_condition

        try:
            get_rows_response = requests.post(url=database_api_url + DatabaseEndpoint.get_rows.value,
                                              json=ldict_get_rows_context)

            if get_rows_response.status_code == HTTPStatus.OK:
                local_object_square_logger.logger.debug(f'{str(DatabaseEndpoint.get_rows.value)} call was successful.'
                                                        f' Input - {str(ldict_get_rows_context)}'
                                                        f', Output - {str(get_rows_response.json())}')
                local_object_square_logger.logger.info(f'{str(DatabaseEndpoint.get_rows.value)} call was successful')
                return get_rows_response.json()

        except requests.exceptions.RequestException as req_exc:
            local_object_square_logger.logger.error(f"API call failed with an exception: {req_exc}",
                                                    exc_info=True, extra=ldict_get_rows_context)
            raise

    except Exception as error:
        local_object_square_logger.logger.error(f'Exception - {str(error)}', exc_info=True,
                                                extra=ldict_get_rows_context)
        raise

    finally:
        del ldict_get_rows_context


def insert_rows_wrapper(pstr_database_name: str,
                        pstr_table_name: str,
                        pstr_schema_name: str,
                        pdict_insert_data: dict):
    """
    Description - This function is a wrapper for calling the database endpoint for insert_rows.
    """
    ldict_insert_rows = dict()
    try:
        ldict_insert_rows['database_name'] = pstr_database_name
        ldict_insert_rows['table_name'] = pstr_table_name
        ldict_insert_rows['schema_name'] = pstr_schema_name
        ldict_insert_rows['data'] = [pdict_insert_data]

        try:
            insert_rows_response = requests.post(url=database_api_url + DatabaseEndpoint.insert_rows.value,
                                                 json=ldict_insert_rows)

            if insert_rows_response.status_code == HTTPStatus.CREATED:
                local_object_square_logger.logger.debug(
                    f'{str(DatabaseEndpoint.insert_rows.value)} call was successful.'
                    f' Input - {str(ldict_insert_rows)}'
                    f', Output - {str(insert_rows_response.json())}')
                local_object_square_logger.logger.info(
                    f'{str(DatabaseEndpoint.insert_rows.value)} call was successful')
                return insert_rows_response.json()

        except requests.exceptions.RequestException as req_exc:
            local_object_square_logger.logger.error(f"API call failed with an exception: {req_exc}",
                                                    exc_info=True, extra=ldict_insert_rows)
            raise

    except Exception as error:
        local_object_square_logger.logger.error(f'Exception - {str(error)}', exc_info=True, extra=pdict_insert_data)
        raise


def get_user_validation_status_id(pstr_status_description: str = 'pending') -> int:
    """
    Description - This function is used to retrieve the status_id for the pending status when the user is created
    for the first time in the authentication system.
    :param pstr_status_description: pending
    :return: status_id
    """
    ldict_filter_condition = dict()
    try:
        ldict_filter_condition[UserValidation.status_description.value] = pstr_status_description
        user_validation = get_rows_wrapper(pstr_database_name=DatabasesEnum.authentication.value,
                                           pstr_table_name=TablesEnum.user_validation_status.value,
                                           pstr_schema_name=SchemaEnum.public.value,
                                           pdict_filter_condition=ldict_filter_condition)
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
        ldict_filter_condition[UserRegistration.registration_description.value] = pstr_registration_description
        user_registration = get_rows_wrapper(pstr_database_name=DatabasesEnum.authentication.value,
                                             pstr_table_name=TablesEnum.user_registration.value,
                                             pstr_schema_name=SchemaEnum.public.value,
                                             pdict_filter_condition=ldict_filter_condition)
        return user_registration[0][UserRegistration.user_registration_id.value]
    except Exception:
        raise
    finally:
        del ldict_filter_condition


def get_hash_algorithm_id(pstr_algorithm_name: str = 'bcrypt') -> int:
    """
    Description - This function is used to retrieve the hash_algorithm_id for the algorithm_name.
    :param pstr_algorithm_name: bcrypt
    :return: hash_algorithm_id
    """
    ldict_filter_condition = dict()
    try:
        ldict_filter_condition[HashingAlgorithm.algorithm_name.value] = pstr_algorithm_name
        hashing_algorithm = get_rows_wrapper(pstr_database_name=DatabasesEnum.authentication.value,
                                             pstr_table_name=TablesEnum.hashing_algorithm.value,
                                             pstr_schema_name=SchemaEnum.public.value,
                                             pdict_filter_condition=ldict_filter_condition)
        return hashing_algorithm[0][HashingAlgorithm.hash_algorithm_id.value]
    except Exception:
        raise
    finally:
        del ldict_filter_condition
