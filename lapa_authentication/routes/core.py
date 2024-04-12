from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from lapa_database_helper.main import LAPADatabaseHelper
from lapa_database_structure.lapa.authentication.enums import UserLogEventEnum, AuthenticationTypeEnum
from lapa_database_structure.lapa.authentication.tables import local_string_database_name, local_string_schema_name, \
    User, UserLog, UserAuthentication, UserProfile, AuthenticationUsername

from lapa_authentication.configuration import global_object_square_logger, config_str_secret_key, \
    config_int_access_token_valid_minutes, config_int_refresh_token_valid_minutes

router = APIRouter(tags=["core"], )

global_object_lapa_database_helper = LAPADatabaseHelper()


@router.get("/register_username/")
@global_object_square_logger.async_auto_logger
async def register_username(username: str, password: str):
    local_str_user_id = None
    try:
        # ======================================================================================
        # entry in user table
        local_list_response_user = global_object_lapa_database_helper.insert_rows(
            data=[{}], database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=User.__tablename__)
        local_str_user_id = local_list_response_user[0][User.user_id.name]
        # ======================================================================================

        # ======================================================================================
        # entry in user log
        local_list_response_user_log = global_object_lapa_database_helper.insert_rows(
            data=[
                {UserLog.user_id.name: local_str_user_id, UserLog.user_log_event.name: UserLogEventEnum.CREATED.value}],
            database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=UserLog.__tablename__)
        # ======================================================================================

        # ======================================================================================
        # entry in user profile
        local_list_response_user_profile = global_object_lapa_database_helper.insert_rows(
            data=[{UserProfile.user_id.name: local_str_user_id}],
            database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=UserProfile.__tablename__)
        # ======================================================================================

        # ======================================================================================
        # entry in user authentication
        local_list_response_user_authentication = global_object_lapa_database_helper.insert_rows(
            data=[{UserAuthentication.user_id.name: local_str_user_id,
                   UserAuthentication.user_authentication_authentication_type.name:
                       AuthenticationTypeEnum.USERNAME.value}],
            database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=UserAuthentication.__tablename__)
        # ======================================================================================

        # ======================================================================================
        # entry in authentication username

        # hash password
        local_str_salt = bcrypt.gensalt()
        local_str_hashed_password = bcrypt.hashpw(password.encode("utf-8"), local_str_salt).decode('utf-8')

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
                                                      local_str_salt).decode('utf-8')
        local_str_hashed_refresh_token = bcrypt.hashpw(local_str_refresh_token.encode("utf-8"),
                                                       local_str_salt).decode('utf-8')

        local_list_response_authentication_username = global_object_lapa_database_helper.insert_rows(
            data=[{AuthenticationUsername.user_id.name: local_str_user_id,
                   AuthenticationUsername.authentication_username_username.name: username,
                   AuthenticationUsername.authentication_username_hashed_password.name: local_str_hashed_password,
                   AuthenticationUsername.authentication_username_salt.name: local_str_salt.decode('utf-8'),
                   AuthenticationUsername.authentication_username_hashed_access_token.name:
                       local_str_hashed_access_token,
                   AuthenticationUsername.authentication_username_hashed_refresh_token.name:
                       local_str_hashed_refresh_token,
                   }],
            database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=AuthenticationUsername.__tablename__)
        # ======================================================================================

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"user_id": local_str_user_id, "access_token": local_str_access_token,
                     "refresh_token": local_str_refresh_token}
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        if local_str_user_id:
            global_object_lapa_database_helper.delete_rows(
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=User.__tablename__,
                filters={User.user_id.name: local_str_user_id})
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e))
