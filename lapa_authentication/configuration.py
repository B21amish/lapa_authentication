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
    config_str_module_name = ldict_configuration["GENERAL"]["MODULE_NAME"]

    config_str_host_ip = ldict_configuration["ENVIRONMENT"]["HOST_IP"]
    config_int_host_port = int(ldict_configuration["ENVIRONMENT"]["HOST_PORT"])
    config_str_log_file_name = ldict_configuration["ENVIRONMENT"]["LOG_FILE_NAME"]
    config_str_secret_key = ldict_configuration["ENVIRONMENT"]["SECRET_KEY"]
    config_int_access_token_valid_minutes = int(ldict_configuration["ENVIRONMENT"]["ACCESS_TOKEN_VALID_MINUTES"])
    config_int_refresh_token_valid_minutes = int(ldict_configuration["ENVIRONMENT"]["REFRESH_TOKEN_VALID_MINUTES"])

    # Initialize logger
    global_object_square_logger = SquareLogger(config_str_log_file_name)
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
