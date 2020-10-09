from enum import Enum
import logging
from logging.handlers import RotatingFileHandler

class Force(Enum):
    FORCE = True
    DO_NOT_FORCE = False

class Level(Enum):
    INFO = 0
    WARNING = 1
    ERROR = 2
    CRITICAL = 3
    SUCCESS = 4
    DEBUG = 5

class Printer:

    # ---------------------------------
    # "Private" static class variables
    # ---------------------------------
    __grey = 37
    __red = 91
    __green = 92
    __yellow = 93
    __blue = 94
    __magenta = 95
    __cyan = 96
    __white = 97
    __bold = "\033[1m"
    __not_bold = "\033[21m"
    __mVerbose: bool = False
    __mDebug: bool = False
    __mColorMap = {
        Level.INFO: __blue,
        Level.WARNING: __yellow,
        Level.ERROR: __red,
        Level.SUCCESS: __green,
        Level.DEBUG: __cyan
    }
    __mLevelMap = {
        Level.INFO: "[*] INFO: ",
        Level.WARNING: "[*] WARNING: ",
        Level.ERROR: "[*] ERROR: ",
        Level.SUCCESS: "[*] SUCCESS: ",
        Level.CRITICAL: "[*] CRITICAL: ",
        Level.DEBUG: "[*] DEBUG: "
    }
    __m_enable_logging: bool = False
    __m_logger: logging.Logger = None
    __m_logger_initialized: bool = False
    __m_log_filename: str = ""
    __m_log_max_bytes_per_file: int = 0
    __m_log_max_number_log_files: int = 0
    __m_log_format: str = ""
    __m_log_level: int = 0

    # ---------------------------------
    # "Public" static class variables
    # ---------------------------------
    @property  # getter method
    def logging_enabled(self) -> bool:
        return self.__m_enable_logging

    @property  # getter method
    def verbose(self) -> bool:
        return self.__mVerbose

    @verbose.setter  # setter method
    def verbose(self: object, pVerbose: bool):
        self.__mVerbose = pVerbose

    @property  # getter method
    def debug(self) -> bool:
        return self.__mDebug

    @debug.setter  # setter method
    def debug(self: object, pDebug: bool):
        self.__mDebug = pDebug

    @property  # getter method
    def log_filename(self) -> str:
        return self.__m_log_filename

    @log_filename.setter  # setter method
    def log_filename(self: object, p_log_filename: str):
        self.__m_log_filename = p_log_filename

    @property  # getter method
    def log_max_bytes_per_file(self) -> int:
        return self.__m_log_max_bytes_per_file

    @log_max_bytes_per_file.setter  # setter method
    def log_max_bytes_per_file(self: object, p_log_max_bytes_per_file: int):
        self.__m_log_max_bytes_per_file = p_log_max_bytes_per_file

    @property  # getter method
    def log_max_number_log_files(self) -> int:
        return self.__m_log_max_number_log_files

    @log_max_number_log_files.setter  # setter method
    def log_max_number_log_files(self: object, p_log_max_number_log_files: int):
        self.__m_log_max_number_log_files = p_log_max_number_log_files

    @property  # getter method
    def log_level(self) -> int:
        return self.__m_log_level

    @log_level.setter  # setter method
    def log_level(self: object, p_log_level: int):
        self.__m_log_level = p_log_level

    @property  # getter method
    def log_format(self) -> str:
        return self.__m_log_format

    @log_format.setter  # setter method
    def log_format(self: object, p_log_format: str):
        self.__m_log_format = p_log_format

    # ---------------------------------
    # public instance constructor
    # ---------------------------------
    def __init__(self) -> None:
        logging.basicConfig(filename=self.log_filename, format=self.log_format, level=self.log_level)
        l_handler = RotatingFileHandler(filename=self.log_filename, maxBytes=self.log_max_bytes_per_file,
                                        backupCount=self.log_max_number_log_files)
        l_handler.setLevel(self.log_level)
        self.__m_logger = logging.getLogger(__name__)
        self.__m_logger.addHandler(l_handler)
        self.__m_logger.propagate = False
        self.__m_logger_initialized = True

    # ---------------------------------
    # private instance methods
    # ---------------------------------

    # ---------------------------------
    # public instance methods
    # ---------------------------------

    # ---------------------------------
    # public static class methods
    # ---------------------------------

    @staticmethod
    def __initialize_logger__() -> None:
        logging.basicConfig(filename=Printer.log_filename, format=Printer.log_format, level=Printer.log_level)
        l_handler = RotatingFileHandler(filename=Printer.log_filename, maxBytes=Printer.log_max_bytes_per_file, backupCount=Printer.log_max_number_log_files)
        l_handler.setLevel(Printer.log_level)
        Printer.__m_logger = logging.getLogger(__name__)
        Printer.__m_logger.addHandler(l_handler)
        Printer.__m_logger.propagate = False
        Printer.__m_logger_initialized = True

    @staticmethod
    def enable_logging():
        Printer.__m_enable_logging = True
        if not Printer.__m_logger_initialized:
            Printer.__initialize_logger__()

    @staticmethod
    def disable_logging():
        Printer.__m_enable_logging = False

    @staticmethod
    def print(pMessage: str, pLevel: Level, p_force: bool = False, p_lines_before: int = 0, p_lines_after: int = 0) -> None:
        # Only print INFO and SUCCESS messages if verbose is true
        # Only print DEBUG messages if debug is true
        # Warning, Error are always printed
        try:
            if (pLevel in [Level.INFO, Level.SUCCESS]) and not (Printer.verbose or p_force): return None
            if (pLevel in [Level.DEBUG]) and not Printer.debug: return None

            for i in range(p_lines_before): print()
            print("\033[1;{}m{}{}\033[21;0m".format(Printer.__mColorMap[pLevel], Printer.__mLevelMap[pLevel], pMessage))
            for i in range(p_lines_after): print()

            # Log message according to severity level
            if Printer.__m_enable_logging:
                if pLevel == Level.DEBUG:
                    Printer.__m_logger.debug(pMessage)
                elif pLevel in [Level.INFO, Level.SUCCESS]:
                    Printer.__m_logger.info(pMessage)
                elif pLevel == Level.WARNING:
                    Printer.__m_logger.warning(pMessage)
                elif pLevel == Level.ERROR:
                    Printer.__m_logger.error(pMessage)
                elif pLevel == Level.CRITICAL:
                    Printer.__m_logger.critical(pMessage)

        except Exception as e:
            print(str(e))