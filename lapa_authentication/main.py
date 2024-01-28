import base64
from http import HTTPStatus

import bcrypt
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from lapa_database_helper.main import LAPADatabaseHelper
from lapa_database_structure.main import DatabasesEnum, SchemaEnum, TablesEnum
from uvicorn import run

from lapa_authentication.configuration import (
    config_int_host_port,
    config_str_host_ip,
    global_object_square_logger,
)
from lapa_authentication.entity.Models import RegisterUser
from lapa_authentication.utils.CommonEnums import (
    HashingAlgorithm,
    User,
    UserRegistration,
    UserValidation,
)
from lapa_authentication.utils.Helper import (
    get_hash_algorithm_id,
    get_user_registration_id,
    get_user_validation_status_id,
)

local_object_lapa_database_helper = LAPADatabaseHelper()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
@global_object_square_logger.async_auto_logger
async def root():
    return JSONResponse(
        status_code=status.HTTP_200_OK, content={"text": "lapa_authentication"}
    )


@app.post("/register")
@global_object_square_logger.async_auto_logger
async def register(register_user: RegisterUser):
    """
    Description - This API endpoint is used to register user into the authentication database.
    """
    ldict_user_data = dict()
    try:
        lbool_user_created = False

        # =========================================================
        # Check whether the user already exists in the user table
        # =========================================================
        _register_user = register_user.model_dump()
        llst_user_found = local_object_lapa_database_helper.get_rows(
            database_name=DatabasesEnum.authentication.value,
            schema_name=SchemaEnum.public.value,
            table_name=TablesEnum.user.value,
            filters={User.user_email_id.value: _register_user["email"]},
            ignore_filters_and_get_all=False,
        )

        # =========================================================
        # If Yes --> Return msg saying user already exists with the same email id
        # =========================================================
        if len(llst_user_found) > 0:
            return JSONResponse(
                status_code=HTTPStatus.CONFLICT,
                content={
                    "user_created": lbool_user_created,
                    "message": "User already exists with the same email id",
                },
            )
        else:
            # =========================================================
            # If No --> Create user in the user table
            # Generate a random salt
            # =========================================================
            lbyte_salt = bcrypt.gensalt()

            # =========================================================
            # Hash the password with the salt
            # =========================================================
            lbyte_hashed_password = bcrypt.hashpw(
                _register_user["password"].encode("utf-8"), lbyte_salt
            )

            ldict_user_data[User.user_email_id.value] = _register_user["email"]
            ldict_user_data[User.user_password_salt.value] = base64.b64encode(
                lbyte_salt
            ).decode("utf-8")
            ldict_user_data[User.user_password_hash.value] = base64.b64encode(
                lbyte_hashed_password
            ).decode("utf-8")

            # =========================================================
            # Fetch user_validation_status_id where status_description = 'pending'
            # =========================================================
            ldict_user_data[
                UserValidation.user_validation_status_id.value
            ] = get_user_validation_status_id()

            # =========================================================
            # Fetch user_registration_id where registration_description = _register_user['registration_type']
            # =========================================================
            ldict_user_data[
                UserRegistration.user_registration_id.value
            ] = get_user_registration_id(_register_user["registration_type"])
            ldict_user_data[
                HashingAlgorithm.hash_algorithm_id.value
            ] = get_hash_algorithm_id()
            insert_row_response = local_object_lapa_database_helper.insert_rows(
                database_name=DatabasesEnum.authentication.value,
                schema_name=SchemaEnum.public.value,
                table_name=TablesEnum.user.value,
                data=[ldict_user_data],
            )
            if len(insert_row_response) == 1:
                # =========================================================
                # Value inserted into database successful
                # =========================================================
                if "user_id" in insert_row_response[0]:
                    lbool_user_created = True
                    return JSONResponse(
                        status_code=HTTPStatus.CREATED,
                        content={
                            "user_created": lbool_user_created,
                            "message": "User created successfully",
                        },
                    )
            else:
                return JSONResponse(
                    status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                    content={
                        "user_created": lbool_user_created,
                        "message": "User not created",
                    },
                )
    except Exception:
        raise
    finally:
        del ldict_user_data


if __name__ == "__main__":
    try:
        run(app, host=config_str_host_ip, port=config_int_host_port)

    except Exception as exc:
        global_object_square_logger.logger.critical(exc, exc_info=True)
