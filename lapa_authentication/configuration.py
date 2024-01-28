import configparser
import os
import sys

from square_logger.main import SquareLogger

try:
    config = configparser.ConfigParser()
    config_file_path = (
        os.path.dirname(os.path.abspath(__file__))
        + os.sep
        + "data"
        + os.sep
        + "config.ini"
    )
    config.read(config_file_path)

    # get all vars and typecast
    config_str_host_ip = config.get("ENVIRONMENT", "HOST_IP")
    config_int_host_port = int(config.get("ENVIRONMENT", "HOST_PORT"))
    config_str_log_file_name = config.get("ENVIRONMENT", "LOG_FILE_NAME")

    # Initialize logger
    global_object_square_logger = SquareLogger(config_str_log_file_name)
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
