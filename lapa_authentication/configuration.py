import os
import sys

from lapa_commons.main import read_configuration_from_file_path
from lapa_database_structure.main import DatabasesEnum, SchemaEnum, TablesEnum
from square_logger.main import SquareLogger

try:
    config_file_path = (
            os.path.dirname(os.path.abspath(__file__))
            + os.sep
            + "data"
            + os.sep
            + "config.ini"
    )
    ldict_configuration = read_configuration_from_file_path(config_file_path)

    # get all vars and typecast
    config_str_module_name = ldict_configuration["GENERAL"]["MODULE_NAME"]

    config_str_host_ip = ldict_configuration["ENVIRONMENT"]["HOST_IP"]
    config_int_host_port = int(ldict_configuration["ENVIRONMENT"]["HOST_PORT"])
    config_str_log_file_name = ldict_configuration["ENVIRONMENT"]["LOG_FILE_NAME"]
    config_str_secret_key = ldict_configuration["ENVIRONMENT"]["SECRET_KEY"]
    config_int_access_token_valid_minutes = int(ldict_configuration["ENVIRONMENT"]["ACCESS_TOKEN_VALID_MINUTES"])
    config_int_refresh_token_valid_minutes = int(ldict_configuration["ENVIRONMENT"]["REFRESH_TOKEN_VALID_MINUTES"])

    config_str_database_name = DatabasesEnum.lapa.value
    config_str_schema_name = SchemaEnum.authentication.value
    config_str_user_table_name = TablesEnum.user.value
    config_str_user_log_table_name = TablesEnum.user_log.value
    config_str_user_profile_table_name = TablesEnum.user_profile.value
    config_str_user_authentication_table_name = TablesEnum.user_authentication.value
    config_str_authentication_username_table_name = TablesEnum.authentication_username.value
    # Initialize logger
    global_object_square_logger = SquareLogger(config_str_log_file_name)
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
