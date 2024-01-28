import configparser
import os
import sys

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
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
