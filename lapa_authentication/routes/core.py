from datetime import datetime, timedelta
from typing import Annotated, Union

import bcrypt
import jwt
from fastapi import APIRouter, status, Header
from fastapi.responses import JSONResponse
from lapa_database_helper.main import LAPADatabaseHelper
from lapa_database_structure.lapa.authentication.enums import UserLogEventEnum
from lapa_database_structure.lapa.authentication.tables import local_string_database_name, local_string_schema_name, \
    User, UserLog, UserCredential, UserProfile, Device, UserDeviceSession
from requests.exceptions import HTTPError

from lapa_authentication.configuration import global_object_square_logger, config_str_secret_key_for_access_token, \
    config_int_access_token_valid_minutes, config_int_refresh_token_valid_minutes, \
    config_str_secret_key_for_refresh_token, config_str_secret_key_for_mac_address_encryption
from lapa_authentication.utils.encryption import encrypt

router = APIRouter(tags=["core"], )

global_object_lapa_database_helper = LAPADatabaseHelper()


@router.get("/register_username/")
@global_object_square_logger.async_auto_logger
async def register_username(username: str, password: str, mac_address: Annotated[Union[str, None], Header()]):
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
        # entry in credential table

        # hash password
        local_str_hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode('utf-8')

        # create access token
        local_dict_access_token_payload = {
            'user_id': local_str_user_id,
            'exp': datetime.now() + timedelta(minutes=config_int_access_token_valid_minutes)
        }
        local_str_access_token = jwt.encode(local_dict_access_token_payload, config_str_secret_key_for_access_token)

        # create refresh token
        local_dict_refresh_token_payload = {
            'user_id': local_str_user_id,
            'exp': datetime.now() + timedelta(minutes=config_int_refresh_token_valid_minutes)
        }
        local_str_refresh_token = jwt.encode(local_dict_refresh_token_payload, config_str_secret_key_for_refresh_token)
        try:
            local_list_response_authentication_username = global_object_lapa_database_helper.insert_rows(
                data=[{UserCredential.user_id.name: local_str_user_id,
                       UserCredential.user_credential_username.name: username,
                       UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
                       }],
                database_name=local_string_database_name, schema_name=local_string_schema_name,
                table_name=UserCredential.__tablename__)
        except HTTPError as http_error:
            if http_error.response.status_code == 400:
                return JSONResponse(
                    status_code=status.HTTP_409_CONFLICT,
                    content=f"an account with the username {username} already exists."
                )
            else:
                raise http_error
        # ======================================================================================

        # ======================================================================================
        # entry in device table
        local_str_encrypted_mac_address = encrypt(plaintext=mac_address,
                                                  key=config_str_secret_key_for_mac_address_encryption)
        local_list_response_get_device = global_object_lapa_database_helper.get_rows(
            filters={
                Device.device_encrypted_mac_address.name: local_str_encrypted_mac_address
            },
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=Device.__tablename__
        )
        if len(local_list_response_get_device) == 1:
            local_device_id = local_list_response_get_device[0][Device.device_id.name]
        elif len(local_list_response_get_device) == 0:
            local_list_response_device = global_object_lapa_database_helper.insert_rows(
                data=[{Device.device_encrypted_mac_address.name: local_str_encrypted_mac_address}],
                database_name=local_string_database_name, schema_name=local_string_schema_name,
                table_name=Device.__tablename__)
            local_device_id = local_list_response_device[0][Device.device_id.name]
        else:
            global_object_square_logger.logger.error(
                f"multiple devices with same encrypted mac address: {local_str_encrypted_mac_address}.")
            raise Exception("Unexpected error.")
        # ======================================================================================
        # ======================================================================================
        # entry in user device session table
        local_str_hashed_refresh_token = bcrypt.hashpw(local_str_refresh_token.encode("utf-8"),
                                                       bcrypt.gensalt()).decode('utf-8')
        local_list_response_user_device_session = global_object_lapa_database_helper.insert_rows(
            data=[{UserDeviceSession.user_id.name: local_str_user_id,
                   UserDeviceSession.device_id.name: local_device_id,
                   UserDeviceSession.user_device_session_hashed_refresh_token.name: local_str_hashed_refresh_token}],
            database_name=local_string_database_name, schema_name=local_string_schema_name,
            table_name=UserDeviceSession.__tablename__)

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


@router.get("/login_username/")
@global_object_square_logger.async_auto_logger
async def login_username(username: str, password: str, mac_address: Annotated[Union[str, None], Header()]):
    try:
        # ======================================================================================
        # get entry from authentication_username table
        local_list_authentication_user_response = global_object_lapa_database_helper.get_rows(
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters={UserCredential.user_credential_username.name: username})
        # ======================================================================================
        # ======================================================================================
        # validate username
        # ======================================================================================
        if len(local_list_authentication_user_response) != 1:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content="incorrect username.")
        # ======================================================================================
        # validate password
        # ======================================================================================
        else:
            if not (bcrypt.checkpw(password.encode("utf-8"),
                                   local_list_authentication_user_response[0][
                                       UserCredential.user_credential_hashed_password.name].encode(
                                       "utf-8"))):
                return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content="incorrect password.")

            # ======================================================================================
            # return new access token and refresh token
            # ======================================================================================
            else:
                local_str_user_id = local_list_authentication_user_response[0][
                    UserCredential.user_id.name]
                # create access token
                local_dict_access_token_payload = {
                    'user_id': local_str_user_id,
                    'exp': datetime.now() + timedelta(minutes=config_int_access_token_valid_minutes)
                }
                local_str_access_token = jwt.encode(local_dict_access_token_payload,
                                                    config_str_secret_key_for_access_token)

                # create refresh token
                local_dict_refresh_token_payload = {
                    'user_id': local_str_user_id,
                    'exp': datetime.now() + timedelta(minutes=config_int_refresh_token_valid_minutes)
                }
                local_str_refresh_token = jwt.encode(local_dict_refresh_token_payload,
                                                     config_str_secret_key_for_refresh_token)
                # ======================================================================================
                # entry in device table
                local_str_encrypted_mac_address = encrypt(plaintext=mac_address,
                                                          key=config_str_secret_key_for_mac_address_encryption)
                local_list_response_get_device = global_object_lapa_database_helper.get_rows(
                    filters={
                        Device.device_encrypted_mac_address.name: local_str_encrypted_mac_address
                    },
                    database_name=local_string_database_name,
                    schema_name=local_string_schema_name,
                    table_name=Device.__tablename__
                )
                if len(local_list_response_get_device) == 1:
                    local_device_id = local_list_response_get_device[0][Device.device_id.name]
                elif len(local_list_response_get_device) == 0:
                    local_list_response_device = global_object_lapa_database_helper.insert_rows(
                        data=[{Device.device_encrypted_mac_address.name: local_str_encrypted_mac_address}],
                        database_name=local_string_database_name, schema_name=local_string_schema_name,
                        table_name=Device.__tablename__)
                    local_device_id = local_list_response_device[0][Device.device_id.name]
                else:
                    global_object_square_logger.logger.error("multiple devices with same encrypted mac address.")
                    raise Exception("Unexpected error.")
                # ======================================================================================
                # ======================================================================================
                # entry in user device session table
                local_str_hashed_refresh_token = bcrypt.hashpw(local_str_refresh_token.encode("utf-8"),
                                                               bcrypt.gensalt()).decode('utf-8')
                global_object_lapa_database_helper.delete_rows(
                    filters={UserDeviceSession.user_id.name: local_str_user_id,
                             UserDeviceSession.device_id.name: local_device_id},
                    database_name=local_string_database_name, schema_name=local_string_schema_name,
                    table_name=UserDeviceSession.__tablename__)
                local_list_response_user_device_session = global_object_lapa_database_helper.insert_rows(
                    data=[{UserDeviceSession.user_id.name: local_str_user_id,
                           UserDeviceSession.device_id.name: local_device_id,
                           UserDeviceSession.user_device_session_hashed_refresh_token.name:
                               local_str_hashed_refresh_token}],
                    database_name=local_string_database_name, schema_name=local_string_schema_name,
                    table_name=UserDeviceSession.__tablename__)

                # ======================================================================================
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"user_id": local_str_user_id, "access_token": local_str_access_token,
                             "refresh_token": local_str_refresh_token}
                )

        # ======================================================================================

    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e))
