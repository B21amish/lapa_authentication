import os
import sys

from lapa_commons.main import read_configuration_from_file_path
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
    # ===========================================
    # general
    config_str_module_name = ldict_configuration["GENERAL"]["MODULE_NAME"]
    # ===========================================

    # ===========================================
    # environment
    config_str_host_ip = ldict_configuration["ENVIRONMENT"]["HOST_IP"]
    config_int_host_port = int(ldict_configuration["ENVIRONMENT"]["HOST_PORT"])
    config_str_log_file_name = ldict_configuration["ENVIRONMENT"]["LOG_FILE_NAME"]
    config_str_secret_key_for_access_token = ldict_configuration["ENVIRONMENT"][
        "SECRET_KEY_FOR_ACCESS_TOKEN"
    ]
    config_str_secret_key_for_refresh_token = ldict_configuration["ENVIRONMENT"][
        "SECRET_KEY_FOR_REFRESH_TOKEN"
    ]
    config_int_access_token_valid_minutes = int(
        ldict_configuration["ENVIRONMENT"]["ACCESS_TOKEN_VALID_MINUTES"]
    )
    config_int_refresh_token_valid_minutes = int(
        ldict_configuration["ENVIRONMENT"]["REFRESH_TOKEN_VALID_MINUTES"]
    )
    # ===========================================

    # ===========================================
    # square_logger
    config_int_log_level = int(ldict_configuration["SQUARE_LOGGER"]["LOG_LEVEL"])
    config_str_log_path = ldict_configuration["SQUARE_LOGGER"]["LOG_PATH"]
    config_int_log_backup_count = int(
        ldict_configuration["SQUARE_LOGGER"]["LOG_BACKUP_COUNT"]
    )
    # ===========================================

    # ===========================================
    # lapa_database_helper

    config_str_lapa_database_protocol = ldict_configuration["LAPA_DATABASE_HELPER"][
        "LAPA_DATABASE_PROTOCOL"
    ]
    config_str_lapa_database_ip = ldict_configuration["LAPA_DATABASE_HELPER"][
        "LAPA_DATABASE_IP"
    ]
    config_int_lapa_database_port = int(
        ldict_configuration["LAPA_DATABASE_HELPER"]["LAPA_DATABASE_PORT"]
    )
    # ===========================================
    # Initialize logger
    global_object_square_logger = SquareLogger(
        pstr_log_file_name=config_str_log_file_name,
        pint_log_level=config_int_log_level,
        pstr_log_path=config_str_log_path,
        pint_log_backup_count=config_int_log_backup_count,
    )
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
