# pylint: disable=import-error, line-too-long
"""
Helper file to abstract code configurations from scripts.
"""
import os
import ast
import sys
import glob
from dotenv import load_dotenv
from pathlib import Path
import logging
import logging.handlers
import datetime as dt


class Configurations:
    """
    This class contains initial configurations for logic.
    """

    def __init__(
        self,
        local_run: bool,
        status_code=None,
        task=None,
        status_text="",
    ):
        if local_run:
            self._runtime_host = "local"
        else:
            self._runtime_host = "aws"  # GCP, AWS, Azure
        
        if "AWS_LAMBDA_RUNTIME_API" not in os.environ:
            self._debug_mode = ast.literal_eval(os.environ.get("DEBUG_MODE"))
            self._generate_log_files = ast.literal_eval(
            os.environ.get("GENERATE_LOG_FILES"))
            self._log_file_limit = int(os.environ.get("LOG_FILE_LIMIT"))
        else:
            self._debug_mode = True
            self._generate_log_files = False
            self._log_file_limit = 1
        self._utc_time = dt.datetime.now(dt.timezone.utc)
        self._timestamp = str(self._utc_time).split()[1]
        self._datestamp = str(self._utc_time).split()[0]
        self._status_code = status_code
        self._status_text = status_text
        self._task = task

        self.setup_logging()

        logging.info(
            "Initialized code with the following configurations, %s", vars(
                self)
        )

    ################################################################################
    # region member props
    ################################################################################

    @property
    def log_file_limit(self):
        """
        log_file_limit member property

        Returns:
        int: log_file_limit
        """
        return self._log_file_limit

    @property
    def utc_time(self):
        """
        utc_time member property

        Returns:
        dt.datetime: utc_time
        """
        return self._utc_time

    @property
    def debug_mode(self):
        """
        debug_mode member property

        Returns:
        bool: debug_mode
        """
        return self._debug_mode

    @property
    def generate_log_files(self):
        """
        generate_log_files member property

        Returns:
        bool: generate_log_files
        """
        return self._generate_log_files

    @property
    def timestamp(self):
        """
        timestamp member property

        Returns:
        dt: timestamp
        """
        return self._timestamp

    @property
    def datestamp(self):
        """
        datestamp member property

        Returns:
        datetime: datestamp
        """
        return self._datestamp

    @property
    def task(self):
        """
        task member property

        Returns:
        datetime: task
        """
        return self._task

    @task.setter
    def task(self, task):
        self._task = task

    @property
    def status_code(self):
        """
        status_code member property

        Returns:
        int: status_code
        """
        return self._status_code

    @status_code.setter
    def status_code(self, status_code):
        self._status_code = status_code

    @property
    def status_text(self):
        """
        status_text member property

        Returns:
        str: status_text
        """
        return self._status_text

    @status_text.setter
    def status_text(self, status_text):
        self._status_text = status_text

    @property
    def runtime_host(self):
        """
        runtime_host member property

        Returns:
        str: runtime_host
        """
        return self._runtime_host

    @runtime_host.setter
    def runtime_host(self, runtime_host):
        self._runtime_host = runtime_host

    ################################################################################
    # endregion member props
    ################################################################################

    ################################################################################
    # region member functions
    ################################################################################

    def get_process_info(self) -> dict:
        """
        Returns important code configurations and properties

        Returns:
            dict: code configurations
        """
        return {
            "status_code": self.status_code,
            "status_text": self.status_text,
            "task": self.task,
            "date": self.datestamp,
            "timestamp": self.timestamp,
            "runtime_host": self.runtime_host,
        }

    def setup_logging(
        self,
        file_directory: str = f"{os.getcwd()}/logs",
        file_name: str = f"{Path(sys.argv[0]).name}-{dt.datetime.now()}.txt",
        mode: str = "w",
        encoding: str = "utf-8"
    ) -> None:
        """
        Set-up logging across files.

        Args:
            file_directory (str, optional): The directory to generate logs. Defaults to f"{os.getcwd()}/logs".
            file_name (str, optional): The name of the log file. Defaults to f"{Path(sys.argv[0]).name}-{dt.datetime.now()}.txt".
            mode (str, optional): Write or Append. Defaults to "w".
            encoding (str, optional): File Encoding. Defaults to "utf-8".
        """
        if not self.generate_log_files:
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)

            return

        file_path = f"{file_directory}/{file_name}"

        if not os.path.exists(file_directory):
            os.mkdir(file_directory)

        if self.get_directory_file_count(file_directory) >= self.log_file_limit:
            self.delete_oldest_file_in_directory(file_directory)

        if not os.path.exists(file_path):
            open(file_path, mode, encoding=encoding)

        handler = logging.handlers.RotatingFileHandler(
            filename=file_path,
            mode=mode,
            encoding=encoding
        )

        formatter = logging.Formatter(
            "[%(asctime)s] "
            "%(levelname)s "
            "[%(module)s.%(funcName)s:%(lineno)d] %(message)s",
            "%b %d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def get_directory_file_count(self, directory_path: str) -> int:
        """
        Get number of files in a directory.

        Args:
            directory_path (str): absolute file path to directory

        Returns:
            int: directory file count
        """
        files = [f for f in os.listdir(directory_path) if os.path.isfile(
            os.path.join(directory_path, f))]

        num_files = len(files)

        return num_files

    def delete_oldest_file_in_directory(self, directory_path: str) -> bool:
        """
        Delete the oldest file in the given directory.

        Args:
            directory_path (str): absolute file path to directory

        Returns:
            bool: file deleted true/false
        """
        files = glob.glob(os.path.join(directory_path, '*'))

        if not files:
            return False

        oldest_file = min(files, key=os.path.getmtime)

        try:
            os.remove(oldest_file)
        except OSError:
            return False

        return True

    ################################################################################
    # endregion member functions
    ################################################################################
