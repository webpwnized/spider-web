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
    def __execute_script(p_connection: sqlite3.Connection, p_query: str) -> None:
        try:
            l_cursor: sqlite3.Cursor = p_connection.cursor()
            l_cursor.executescript(p_query)
            Printer.print("Executed SQLite query script: {}".format(p_query), Level.DEBUG)
            SQLite.__print_rows_affected(l_cursor, p_query)
        except sqlite3.ProgrammingError as l_error:
            Printer.print("Programming Error: executing SQLite query script: {}".format(l_error), Level.ERROR)
        except sqlite3.OperationalError as l_error:
            Printer.print("Operational Error executing SQLite query script: {}".format(l_error), Level.ERROR)

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
                return SQLite.__verify_table_exists(l_connection, "Scans")
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


    # ------------------------------------------------------------
    # Database methods
    # ------------------------------------------------------------
    @staticmethod
    def empty_tables() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Emptying database tables", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    DELETE FROM Scans;
                    DELETE FROM VulnerabilityTypes;
                    DELETE FROM Websites;
                    DELETE FROM WebsiteGroups;
                    DELETE FROM ProfileTags;
                    DELETE FROM FalsePositiveImport;
                    VACUUM;
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error emptying database tables", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def create_tables() -> None:
        try:
            Printer.print("Creating database tables", Level.INFO)
            SQLite.__create_issues_table()
        except:
             Printer.print("Error emptying database tables", Level.ERROR)

    @staticmethod
    def create_views() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating views", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE VIEW IF NOT EXISTS WebsiteSDG AS 
                    SELECT * FROM WebsiteGroups
                    WHERE group_name LIKE 'SDG:%';

                    CREATE VIEW IF NOT EXISTS WebsiteOnBsc AS
                    SELECT * FROM WebsiteGroups
                    WHERE group_name = 'On Balanced Score Card (BSC)';

                    DROP VIEW IF EXISTS TrackedIssues;
                    CREATE VIEW TrackedIssues AS
                        SELECT Issues.*, VulnerabilityTypes.cvss_value, VulnerabilityTypes.cvss_severity
                        FROM Issues
                            JOIN VulnerabilityTypes ON Issues.name = VulnerabilityTypes.title AND Issues.type = VulnerabilityTypes.id
                            JOIN Scans ON Issues.scan_id = Scans.id
                            LEFT JOIN FalsePositiveImport ON Issues.name = FalsePositiveImport.issue_name AND Scans.profile_name = FalsePositiveImport.profile_name
                        WHERE VulnerabilityTypes.cvss_value >= 6.0
                            AND Issues.state NOT LIKE '%Fixed%'
                            AND Issues.state NOT LIKE '%FalsePositive%'
                            AND FalsePositiveImport.issue_name IS NULL

                    CREATE VIEW IF NOT EXISTS WebsiteSegment AS
                    SELECT * FROM WebsiteGroups
                    WHERE group_name LIKE 'Segment:%';
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating views", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()       


    # ------------------------------------------------------------
    # Scan table methods
    # ------------------------------------------------------------
    @staticmethod
    def __create_scan_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating scans table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """CREATE TABLE "Scans" (
                    "id"	TEXT NOT NULL,
                    "profile_name"	TEXT,
                    "profile_id" TEXT,
                    "initiated_date"	TEXT,
                    "vulnerability_count"	INTEGER,
                    "website_id"	TEXT,
                    "target_url"    TEXT,
                    "is_compliant"  TEXT,
                    "tags"	TEXT,
                    PRIMARY KEY("id")
                )"""
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating scan table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def insert_scans(p_scans: list) -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "Scans"): 
                SQLite.__create_scan_table()
            Printer.print("Inserting scans", Level.INFO)
            l_query = "INSERT OR IGNORE INTO Scans VALUES(?,?,?,?,?,?,?,?,?);"
            SQLite.__execute_parameterized_queries(l_connection, l_query, p_scans)
            SQLite.__populate_profile_tags()
        except:
             Printer.print("Error inserting scans", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def __create_profile_tag_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating profile tag table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """CREATE TABLE "ProfileTags" (
                    "profile_id"	TEXT,
                    "tag"	TEXT,
                    PRIMARY KEY("profile_id","tag")
                )"""
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating profile tag table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def __populate_profile_tags() -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "ProfileTags"): 
                SQLite.__create_profile_tag_table()
            Printer.print("Inserting profile tags", Level.INFO)
            l_query = """
                 WITH RECURSIVE split(id, tag, str) AS (
                    SELECT profile_id, '', tags||'|' FROM Scans
                    UNION ALL SELECT
                    Id,
                    substr(str, 0, instr(str, '|')),
                    substr(str, instr(str, '|')+1)
                    FROM split WHERE str != ''
                ) 

                INSERT INTO ProfileTags
                SELECT id, tag
                FROM split
                WHERE tag != ''
                ORDER BY id;

                CREATE VIEW IF NOT EXISTS "DevSource" AS SELECT profile_id, max(tag) as tag
                FROM ProfileTags
                WHERE tag LIKE 'Dev Source:%'
                GROUP BY profile_id;

                CREATE VIEW IF NOT EXISTS "ExcludeFromReports" AS SELECT profile_id, tag
                FROM ProfileTags
                WHERE tag = "Not for BSC";
            """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error inserting profile tags", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()


    # ------------------------------------------------------------
    # Website table methods
    # ------------------------------------------------------------
    @staticmethod
    def __create_website_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating websites table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE TABLE "Websites" (
                    "name"	TEXT,
                    "root_url"	TEXT,
                    "technical_contact"	TEXT,
                    "is_verified"	INTEGER,
                    "agent_mode"	TEXT,
                    "groups"	BLOB,
                    "id"	TEXT,
                    PRIMARY KEY("id")
                )
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating websites table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def __create_website_group_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating website groups table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE TABLE "WebsiteGroups" (
                        "website_id"	TEXT,
                        "group_name"	TEXT,
                        PRIMARY KEY("website_id","group_name")
                    )
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating website groups table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def insert_websites(p_websites: list) -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "Websites"): 
                SQLite.__create_website_table()
            Printer.print("Inserting websites", Level.INFO)
            l_query = "INSERT OR IGNORE INTO Websites VALUES(?,?,?,?,?,?,?);"
            SQLite.__execute_parameterized_queries(l_connection, l_query, p_websites)

            SQLite.__populate_website_groups()
        except:
             Printer.print("Error inserting websites", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def __populate_website_groups() -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "WebsiteGroups"): 
                SQLite.__create_website_group_table()

            Printer.print("Populating website group table", Level.INFO)
            l_query = """
                WITH RECURSIVE split(id, group_name, str) AS (
                    SELECT id, '', groups||'|' FROM Websites
                    UNION ALL SELECT
                    Id,
                    substr(str, 0, instr(str, '|')),
                    substr(str, instr(str, '|')+1)
                    FROM split WHERE str != ''
                ) 

                INSERT INTO WebsiteGroups
                SELECT id, group_name
                FROM split
                WHERE group_name != ''
                ORDER BY id;
            """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error populating website group table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    
    # ------------------------------------------------------------
    # Scan Issues table methods
    # ------------------------------------------------------------
    @staticmethod
    def __create_issues_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating issues table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE TABLE IF NOT EXISTS "Issues" (
                        "type"	TEXT,
                        "name"	TEXT,
                        "severity"	TEXT,
                        "affected_url"	TEXT,
                        "state" TEXT,
                        "first_seen"    TEXT,
                        "last_seen" TEXT,
                        "scan_id"	TEXT,
                        PRIMARY KEY("type","name","scan_id")
                    );
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating issues table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def insert_issues(p_scans: list) -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "Issues"): 
                SQLite.__create_issues_table()
            Printer.print("Inserting issues", Level.INFO)
            l_query = "INSERT OR IGNORE INTO Issues VALUES(?,?,?,?,?,?,?,?);"
            SQLite.__execute_parameterized_queries(l_connection, l_query, p_scans)
        except:
             Printer.print("Error inserting issues", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def select_missing_issues() -> list:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            Printer.print("Querying for missing issues", Level.INFO)
            l_query = """
                SELECT Scans.Id
                FROM Scans
                    LEFT JOIN Issues ON Scans.Id = Issues.scan_id
                WHERE Scans.is_compliant = 0
                    AND Issues.scan_id IS NULL
                GROUP BY Scans.id
            """
            return SQLite.__execute_query(l_connection, l_query)
        except:
             Printer.print("Error querying for missing issues", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    # ------------------------------------------------------------
    # Vulnerability Type table methods
    # ------------------------------------------------------------
    @staticmethod
    def __create_vulnerability_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating vulnerability table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE TABLE "VulnerabilityTypes" (
                        "id"	TEXT,
                        "title"	TEXT,
                        "cvss_value"	REAL,
                        "cvss_severity"	TEXT
                    );
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating VulnerabilityTypes table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def insert_vulnerability_types(p_vulns: list) -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "VulnerabilityTypes"): 
                SQLite.__create_vulnerability_table()
            Printer.print("Inserting vulnerabilities", Level.INFO)
            l_query = "INSERT OR IGNORE INTO VulnerabilityTypes VALUES(?,?,?,?);"
            SQLite.__execute_parameterized_queries(l_connection, l_query, p_vulns)
        except:
             Printer.print("Error inserting vulnerabilities", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    # ------------------------------------------------------------
    # Scorecard Results
    # ------------------------------------------------------------

    @staticmethod
    def select_scorecard_results() -> list:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            Printer.print("Querying for scorecard results", Level.INFO)
            l_query = """
                SELECT 
                    WebsiteSDG.group_name,
                    Scans.profile_name, 
                    Scans.target_url, 
                    TrackedIssues.name,
                    TrackedIssues.cvss_value,
                    TrackedIssues.cvss_severity,
                    SUBSTR(DevSource.tag,13,100) as dev_source,
                    SUBSTR(Scans.initiated_date,1,10) as scan_date,
                    Scans.id as scan_id
                FROM
                    Scans
                    JOIN WebsiteOnBsc ON Scans.website_id = WebsiteOnBsc.website_id
                    JOIN TrackedIssues ON Scans.id = TrackedIssues.scan_id
                    LEFT JOIN WebsiteSDG ON Scans.website_id = WebsiteSDG.website_id
                    LEFT JOIN DevSource ON Scans.profile_id = DevSource.profile_id
                    LEFT JOIN ExcludeFromReports ON Scans.profile_id = ExcludeFromReports.profile_id
                WHERE 
                    ExcludeFromReports.profile_id IS NULL

                UNION

                SELECT 
                    WebsiteSDG.group_name,
                    Scans.profile_name, 
                    Scans.target_url, 
                    'Compliant' AS name,
                    '' AS cvss_value,
                    '' AS cvss_severity,
                    SUBSTR(DevSource.tag,13,100) as dev_source,
                    SUBSTR(Scans.initiated_date,1,10) as scan_date,
                    Scans.id as scan_id
                FROM
                    Scans
                    JOIN WebsiteOnBsc ON Scans.website_id = WebsiteOnBsc.website_id
                    LEFT JOIN TrackedIssues ON Scans.id = TrackedIssues.scan_id
                    LEFT JOIN WebsiteSDG ON Scans.website_id = WebsiteSDG.website_id
                    LEFT JOIN DevSource ON Scans.profile_id = DevSource.profile_id
                    LEFT JOIN ExcludeFromReports ON Scans.profile_id = ExcludeFromReports.profile_id
                WHERE 
                    TrackedIssues.scan_id IS NULL
                    AND ExcludeFromReports.profile_id IS NULL
                    
                ORDER BY WebsiteSDG.group_name, Scans.profile_name;
            """
            return SQLite.__execute_query(l_connection, l_query)
        except:
             Printer.print("Error querying for scorecard results", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    # ------------------------------------------------------------
    # False Positive table methods
    # ------------------------------------------------------------
    @staticmethod
    def __create_false_positive_table() -> None:
        l_connection: sqlite3.Connection = None
        try:
            Printer.print("Creating FalsePositiveImport table", Level.INFO)
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            l_query = """
                    CREATE TABLE "FalsePositiveImport" (
                        "profile_name"	TEXT,
                        "issue_name"	TEXT,
                        PRIMARY KEY("profile_name", "issue_name")
                    );
                """
            SQLite.__execute_script(l_connection, l_query)
        except:
             Printer.print("Error creating FalsePositiveImport table", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()

    @staticmethod
    def insert_false_issues(p_issues: list) -> None:
        l_connection: sqlite3.Connection = None
        try:
            l_connection = SQLite.__connect_to_database(Mode.READ_WRITE)
            if not SQLite.__verify_table_exists(l_connection, "FalsePositiveImport"): 
                SQLite.__create_false_positive_table()
            Printer.print("Inserting false issues", Level.INFO)
            l_query = "INSERT OR IGNORE INTO FalsePositiveImport VALUES(?,?);"
            SQLite.__execute_parameterized_queries(l_connection, l_query, p_issues)
        except:
             Printer.print("Error inserting false issues", Level.ERROR)
        finally:
            if l_connection:
                l_connection.close()
