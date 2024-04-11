from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from lapa_database_helper.main import LAPADatabaseHelper
from lapa_database_structure.lapa.authentication.enums import UserLogEventEnum, AuthenticationTypeEnum

from lapa_authentication.configuration import global_object_square_logger, config_str_user_log_table_name, \
    config_str_database_name, config_str_user_table_name, config_str_schema_name, config_str_user_profile_table_name, \
    config_str_user_authentication_table_name, config_str_secret_key, config_int_access_token_valid_minutes, \
    config_int_refresh_token_valid_minutes, config_str_authentication_username_table_name

router = APIRouter(tags=["core"], )

global_object_lapa_database_helper = LAPADatabaseHelper()


@router.get("/register_username/")
@global_object_square_logger.async_auto_logger
async def register_username(username: str, password: str):
    try:
        # ======================================================================================
        # entry in user table
        local_list_response_user = global_object_lapa_database_helper.insert_rows(
            data=[{}], database_name=config_str_database_name, schema_name=config_str_schema_name,
            table_name=config_str_user_table_name)
        local_str_user_id = local_list_response_user[0]['user_id']
        # ======================================================================================

        # ======================================================================================
        # entry in user log
        local_list_response_user_log = global_object_lapa_database_helper.insert_rows(
            data=[{"user_id": local_str_user_id, "user_log_event": UserLogEventEnum.CREATED.value}],
            database_name=config_str_database_name, schema_name=config_str_schema_name,
            table_name=config_str_user_log_table_name)
        # ======================================================================================

        # ======================================================================================
        # entry in user profile
        local_list_response_user_profile = global_object_lapa_database_helper.insert_rows(
            data=[{"user_id": local_str_user_id}],
            database_name=config_str_database_name, schema_name=config_str_schema_name,
            table_name=config_str_user_profile_table_name)
        # ======================================================================================

        # ======================================================================================
        # entry in user authentication
        local_list_response_user_authentication = global_object_lapa_database_helper.insert_rows(
            data=[{"user_id": local_str_user_id,
                   "user_authentication_authentication_type": AuthenticationTypeEnum.USERNAME.value}],
            database_name=config_str_database_name, schema_name=config_str_schema_name,
            table_name=config_str_user_authentication_table_name)
        # ======================================================================================

        # ======================================================================================
        # entry in authentication username

        # hash password
        local_str_password_salt = bcrypt.gensalt()
        local_str_hashed_password = bcrypt.hashpw(password.encode("utf-8"), local_str_password_salt).decode('utf-8')

        # create access token
        local_dict_access_token_payload = {
            'user_id': local_str_user_id,
            'exp': datetime.now() + timedelta(minutes=config_int_access_token_valid_minutes)
        }
        local_str_access_token = jwt.encode(local_dict_access_token_payload, config_str_secret_key)

        # create refresh token
        local_dict_refresh_token_payload = {
            'user_id': local_str_user_id,
            'exp': datetime.now() + timedelta(minutes=config_int_refresh_token_valid_minutes)
        }
        local_str_refresh_token = jwt.encode(local_dict_refresh_token_payload, config_str_secret_key)

        # hash both
        local_str_hashed_access_token = bcrypt.hashpw(local_str_access_token.encode("utf-8"),
                                                      bcrypt.gensalt()).decode('utf-8')
        local_str_hashed_refresh_token = bcrypt.hashpw(local_str_refresh_token.encode("utf-8"),
                                                       bcrypt.gensalt()).decode('utf-8')

        local_list_response_authentication_username = global_object_lapa_database_helper.insert_rows(
            data=[{"user_id": local_str_user_id,
                   "authentication_username_username": username,
                   "authentication_username_hashed_password": local_str_hashed_password,
                   "authentication_username_password_salt": local_str_password_salt.decode('utf-8'),
                   "authentication_username_hashed_access_token": local_str_hashed_access_token,
                   "authentication_username_hashed_refresh_token": local_str_hashed_refresh_token,
                   }],
            database_name=config_str_database_name, schema_name=config_str_schema_name,
            table_name=config_str_authentication_username_table_name)
        # ======================================================================================

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"user_id": local_str_user_id, "access_token": local_str_access_token,
                     "refresh_token": local_str_refresh_token}
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e))
