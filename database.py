import sqlite3
from printer import Printer, Level
from urllib.request import pathname2url
from enum import Enum
import time


class Mode(Enum):
    READ_ONLY = 'ro'
    READ_WRITE = 'rw'
    READ_WRITE_CREATE = 'rwc'
    IN_MEMORY = 'memory'


class SQLite():

    ATTACHED_DATABASE_FILENAME: int = 2
    SECONDS_PER_DAY = 24 * 60 * 60

    database_filename: str = ""

    @staticmethod
    def __connect_to_database(p_mode: Mode) -> sqlite3.Connection:
        FIRST_ROW = 0
        try:
            l_database_file_uri: str = 'file:{}?mode={}'.format(pathname2url(SQLite.database_filename), p_mode.value)
            l_connection: sqlite3.Connection = sqlite3.connect(l_database_file_uri, uri=True)
            Printer.print("Connected to SQLite version {} database".format(sqlite3.sqlite_version), Level.SUCCESS)
            l_query:str = "SELECT * FROM pragma_database_list();"
            l_rows = SQLite.__execute_query(l_connection, l_query)
            Printer.print("Attached database: {}".format(l_rows[FIRST_ROW][SQLite.ATTACHED_DATABASE_FILENAME]), Level.INFO)
            return l_connection
        except sqlite3.OperationalError as l_error:
            Printer.print("Error connecting to database: {}".format(l_error), Level.ERROR)
            return None
        except Exception as l_error:
            Printer.print("Error connecting to database: {} {}".format(type(l_error).__name__, l_error), Level.ERROR)
            return None

    @staticmethod
    def __print_rows_affected(p_cursor: sqlite3.Cursor, p_query: str) -> None:
        FIRST_ROW = 0
        FIRST_COLUMN = 0
        if "SELECT" not in p_query:
            p_cursor.execute("SELECT changes();")
            l_changes: list = p_cursor.fetchall()
            Printer.print("Rows affected: {}".format(l_changes[FIRST_ROW][FIRST_COLUMN]), Level.INFO)

    @staticmethod
    def __execute_query(p_connection: sqlite3.Connection, p_query: str) -> list:
        try:
            l_cursor: sqlite3.Cursor = p_connection.cursor()
            l_cursor.execute(p_query)
            l_rows: list = l_cursor.fetchall()
            p_connection.commit()
            Printer.print("Executed SQLite query: {}".format(p_query), Level.DEBUG)
            SQLite.__print_rows_affected(l_cursor, p_query)
            return l_rows
        except sqlite3.ProgrammingError as l_error:
            Printer.print("Programming Error: executing SQLite query: {}".format(l_error), Level.ERROR)
        except sqlite3.OperationalError as l_error:
            Printer.print("Operational Error executing SQLite query: {}".format(l_error), Level.ERROR)

    @staticmethod
    def __execute_parameterized_query(p_connection: sqlite3.Connection, p_query: str, p_parameters: tuple) -> list:
        try:
            l_cursor: sqlite3.Cursor = p_connection.cursor()
            l_cursor.execute(p_query, p_parameters)
            l_rows: list = l_cursor.fetchall()
            p_connection.commit()
            Printer.print("Executed SQLite query: {}".format(p_query), Level.DEBUG)
            SQLite.__print_rows_affected(l_cursor, p_query)
            return l_rows
        except sqlite3.ProgrammingError as l_error:
            Printer.print("Programming Error: executing SQLite query: {}".format(l_error), Level.ERROR)
        except sqlite3.OperationalError as l_error:
            Printer.print("Operational Error executing SQLite query: {}".format(l_error), Level.ERROR)

    @staticmethod
    def __execute_parameterized_queries(p_connection: sqlite3.Connection, p_query: str, p_records: list) -> list:
        try:
            l_cursor: sqlite3.Cursor = p_connection.cursor()
            l_cursor.executemany(p_query, p_records)
            l_rows: list = l_cursor.fetchall()
            p_connection.commit()
            Printer.print("Executed SQLite query: {}".format(p_query), Level.DEBUG)
            SQLite.__print_rows_affected(l_cursor, p_query)
            return l_rows
        except sqlite3.ProgrammingError as l_error:
            Printer.print("Programming Error: executing SQLite query: {}".format(l_error), Level.ERROR)
        except sqlite3.OperationalError as l_error:
            Printer.print("Operational Error executing SQLite query: {}".format(l_error), Level.ERROR)

    @staticmethod
    def __verify_table_exists(p_connection: sqlite3.Connection, p_table_name: str) -> bool:
        l_query: str = "SELECT name FROM sqlite_master WHERE type='table' AND name='{}';".format(p_table_name)
        l_rows: list = SQLite.__execute_query(p_connection, l_query)
        if not l_rows:
            Printer.print("Table {} not found in database".format(p_table_name), Level.ERROR)
        return bool(l_rows)

    @staticmethod
    def __enable_foreign_keys(p_connection: sqlite3.Connection) -> None:
        l_query: str = "PRAGMA foreign_keys = 1;"
        Printer.print("Enabling foreign keys", Level.INFO)
        SQLite.__execute_query(p_connection, l_query)
        Printer.print("Enabled foreign keys", Level.SUCCESS)

    @staticmethod
    def verify_database_exists() -> bool:
        l_connection:sqlite3.Connection = None
        try:
            Printer.print("Checking if database is available", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if l_connection:
                return SQLite.__verify_table_exists(l_connection, "study_files")
            else:
                return False
        except sqlite3.Error as l_error:
            Printer.print("Error connecting to database: {}".format(l_error), Level.WARNING)
            return False
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def get_table_column_names(p_table_name: str) -> list:
        NAME = 1
        try:
            Printer.print("Fetching column names for table {}".format(p_table_name), Level.INFO)
            l_column_names: list = SQLite.get_table_column_metadata(p_table_name)
            l_names = []
            for l_column_tuple in l_column_names:
                l_names.append(l_column_tuple[NAME])
            return l_names
        except Exception as l_error:
            Printer.print("Error fetching column names for table {}: {}".format(p_table_name, l_error), Level.WARNING)

    @staticmethod
    def get_table_column_metadata(p_table_name: str) -> list:
        l_connection:sqlite3.Connection = None

        try:
            Printer.print("Fetching column metadata for table {}".format(p_table_name), Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_ONLY)
            l_query = "SELECT * FROM pragma_table_info('{}');".format(p_table_name)
            return SQLite.__execute_query(l_connection, l_query)
        except sqlite3.Error as l_error:
            Printer.print("Error fetching column metadata for table {}: {}".format(p_table_name, l_error), Level.WARNING)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def __convert_epoch_to_string(p_epoch_time: int) -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p_epoch_time))

    @staticmethod
    def create_database() -> None:
        l_connection:sqlite3.Connection = None
        try:
            Printer.print("Creating database", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE_CREATE)
            Printer.print("Connected to database", Level.SUCCESS)

            SQLite.__enable_foreign_keys(l_connection)

        except sqlite3.Error as l_error:
            Printer.print("Error creating database: {}".format(l_error), Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()