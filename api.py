from printer import Printer, Level, Force
from argparser import Parser
from enum import Enum
from database import SQLite
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from datetime import datetime
from datetime import timezone
from dateutil import parser

import time
import re
import json
import getpass
import requests
import os
import base64
import csv
import pytz
import sys

# Disable warning about insecure proxy when proxy enabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Override(Enum):
    FORCE_OUTPUT = True
    USE_DEFAULTS = False


class OutputFormat(Enum):
    JSON = 'JSON'
    CSV = 'CSV'

    def __str__(self):
        return self.value


class AcceptHeader(Enum):
    JSON = 'JSON'
    CSV = 'CSV'

    def __str__(self):
        return self.value


class ApiAuthenticationMethod(Enum):
    BEARER_TOKEN = 'BEARER_TOKEN'
    BASIC_AUTHENTICATION = 'BASIC_AUTHENTICATION'

    def __str__(self):
        return self.value


class ApiCredentialFormat(Enum):
    REFRESH_TOKEN = 'REFRESH_TOKEN'
    USERNAME_PASSWORD = 'USERNAME_PASSWORD'

    def __str__(self):
        return self.value


class CSVSeparatorFormat(Enum):
    COMMA = 'Comma'
    SEMICOLON = 'Semicolon'
    PIPE = 'Pipe'
    TAB = 'Tab'

    def __str__(self):
        return self.value


class HTTPMethod(Enum):
    GET="GET"
    POST="POST"
    HEAD="HEAD"
    PUT="PUT"
    DELETE="DEELTE"
    CONNECT="CONNECT"
    OPTIONS="OPTIONS"
    TRACE="TRACE"
    PATCH="PATCH"

    def __str__(self):
        return self.value


class FileMode(Enum):
    READ='r'
    READ_BYTES='rb'
    WRITE='w'
    WRITE_CREATE='w+'
    WRITE_BYTES='wb'

    def __str__(self):
        return self.value


class WebsiteUploadFileFields(Enum):
    NAME = 0
    URL = 1
    GROUPS = 2

    def __str__(self):
        return self.value


class PingMethod(Enum):
    INITIAL_TEST = 0
    SECOND_TEST_NO_PROXY = 1
    SECOND_TEST_USE_PROXY = 2

    def __str__(self):
        return self.value


class ExitCodes(Enum):
    EXIT_NORMAL = 0
    NOTHING_TO_REPORT = 4
    ALREADY_REPORTED = 8


class SortDirection(Enum):
    ASCENDING = 'Ascending'
    DECENDING = 'Decending'

    def __str__(self):
        return self.value


class API:

    # ---------------------------------
    # "Private" class variables
    # ---------------------------------
    __c_EASTERN_TIMEZONE = pytz.timezone('US/Eastern')
    __c_DATETIME_FORMAT = '%m-%d-%Y %H:%M'

    __cAPI_KEY_HEADER: str = "Authorization"
    __cUSER_AGENT_HEADER: str = "User-Agent"
    __cUSER_AGENT_VALUE: str = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0"
    __ACCEPT_HEADER: str = "Accept"
    __ACCEPT_JSON_VALUE: str = "application/json"
    __ACCEPT_CSV_VALUE: str = "text/csv"

    __cBASE_URL: str = "https://www.netsparkercloud.com/api/"
    __cAPI_VERSION_1_URL: str = "1.0/"

    __cACCOUNT_LICENSE_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "account/license")
    __cACCOUNT_ME_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "account/me")

    __cAGENTS_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "agents/list")

    __cSCANS_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "scans/list")
    __cSCANS_LIST_BY_WEBSITE_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "scans/listbywebsite")

    __cTEAM_MEMBER_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "teammembers/list")

    __cDISCOVERED_SERVICES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/list")
    __cDISCOVERED_SERVICES_DOWNLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/export")

    __cTECHNOLOGIES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "technologies/list")
    __cOBSOLETE_TECHNOLOGIES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "technologies/outofdatetechnologies")

    __cWEBSITES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/list")
    __cWEBSITES_GET_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/get")
    __cWEBSITES_UPLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/new")
    __cWEBSITES_BY_GROUP_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/getwebsitesbygroup")

    __cWEBSITE_GROUPS_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websitegroups/list")
    __cWEBSITE_GROUPS_UPLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websitegroups/new")

    __cVULNERABILITY_TEMPLATES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "vulnerability/list")
    __cVULNERABILITY_TEMPLATE_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "vulnerability/template")
    __cVULNERABILITY_TEMPLATE_TYPES_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "vulnerability/types")

    __m_script_directory: str = os.path.dirname(__file__)

    __m_verbose: bool = False
    __m_debug: bool = False

    __m_api_key_file:str = ""
    __m_api_authentication_method: str = ""
    __m_api_credential_format: str = ""
    __m_refresh_token: str = ""
    __m_access_token: str = ""
    __m_api_user_id: str = ""
    __m_api_password: str = ""
    __m_api_connection_timeout: int = 30
    __m_verify_https_certificate: bool = True

    __mPrinter: Printer = Printer
    __m_use_proxy: bool = False
    __m_proxy_url: str = ""
    __m_proxy_port: int = 0
    __m_proxy_username: str = ""
    __m_proxy_password: str = ""
    __m_output_format: OutputFormat
    __m_accept_header: AcceptHeader = AcceptHeader.JSON

    # ---------------------------------
    # "Public" class variables
    # ---------------------------------

    @property  # getter method
    def script_directory(self) -> str:
        return self.__m_script_directory

    @script_directory.setter  # setter method
    def script_directory(self: object, pScriptDirectory: str):
        self.__m_script_directory.verbose = pScriptDirectory

    @property  # getter method
    def verbose(self) -> bool:
        return self.__m_verbose

    @verbose.setter  # setter method
    def verbose(self: object, pVerbose: bool):
        self.__m_verbose = pVerbose
        self.__mPrinter.verbose = pVerbose

    @property  # getter method
    def debug(self) -> bool:
        return self.__m_debug

    @debug.setter  # setter method
    def debug(self: object, pDebug: bool):
        self.__m_debug = pDebug
        self.__mPrinter.debug = pDebug

    @property  # getter method
    def refresh_token(self) -> str:
        return self.__m_refresh_token

    @refresh_token.setter  # setter method
    def refresh_token(self: object, p_refresh_token: str):
        self.__m_refresh_token = p_refresh_token

    @property  # getter method
    def access_token(self) -> str:
        return self.__m_access_token

    @access_token.setter  # setter method
    def access_token(self: object, p_access_token: str):
        self.__m_access_token = p_access_token

    @property  # getter method
    def api_key_file(self) -> str:
        return self.__m_api_key_file

    @api_key_file.setter  # setter method
    def api_key_file(self: object, pApiKeyFile: str):
        self.__m_api_key_file = pApiKeyFile

    @property  # getter method
    def api_authentication_method(self) -> str:
        return self.__m_api_authentication_method

    @api_authentication_method.setter  # setter method
    def api_authentication_method(self: object, pApiAuthenticationMethod: str):
        self.__m_api_authentication_method = pApiAuthenticationMethod

    @property  # getter method
    def api_credential_format(self) -> str:
        return self.__m_api_credential_format

    @api_credential_format.setter  # setter method
    def api_credential_format(self: object, pApiCredentialFormat: str):
        self.__m_api_credential_format = pApiCredentialFormat

    @property  # getter method
    def api_user_id(self) -> str:
        return self.__m_api_user_id

    @api_user_id.setter  # setter method
    def api_user_id(self: object, pApiUserID: str):
        self.__m_api_user_id = pApiUserID

    @property  # getter method
    def api_password(self) -> str:
        return self.__m_api_password

    @api_password.setter  # setter method
    def api_password(self: object, pApiPassword: str):
        self.__m_api_password = pApiPassword

    @property  # getter method
    def use_proxy(self) -> bool:
        return self.__m_use_proxy

    @use_proxy.setter  # setter method
    def use_proxy(self: object, p_use_proxy: bool):
        self.__m_use_proxy = p_use_proxy

    @property  # getter method
    def proxy_url(self) -> str:
        return self.__m_proxy_url

    @proxy_url.setter  # setter method
    def proxy_url(self: object, p_proxy_url: str):
        self.__m_proxy_url = p_proxy_url

    @property  # getter method
    def proxy_port(self) -> int:
        return self.__m_proxy_port

    @proxy_port.setter  # setter method
    def proxy_port(self: object, p_proxy_port: int):
        self.__m_proxy_port = p_proxy_port

    @property  # getter method
    def proxy_username(self) -> str:
        return self.__m_proxy_username

    @proxy_username.setter  # setter method
    def proxy_username(self: object, p_proxy_username: str):
        self.__m_proxy_username = p_proxy_username

    @property  # getter method
    def proxy_password(self) -> str:
        return self.__m_proxy_password

    @proxy_password.setter  # setter method
    def proxy_password(self: object, p_proxy_password: str):
        self.__m_proxy_password = p_proxy_password

    @property  # getter method
    def verify_https_certificate(self) -> bool:
        return self.__m_verify_https_certificate

    @verify_https_certificate.setter  # setter method
    def verify_https_certificate(self: object, p_verify_https_certificate: bool):
        self.__m_verify_https_certificate = p_verify_https_certificate

    @property  # getter method
    def output_format(self) -> OutputFormat:
        return self.__m_output_format

    @output_format.setter  # setter method
    def output_format(self: object, p_output_format: OutputFormat):
        self.__m_output_format = p_output_format

    # ---------------------------------
    # public instance constructor
    # ---------------------------------
    def __init__(self, p_parser: Parser) -> None:
        self.__m_verbose: bool = Parser.verbose
        self.__m_debug: bool = Parser.debug
        self.__m_api_key_file = Parser.api_key_file_path
        self.__m_api_connection_timeout = Parser.api_connection_timeout
        self.__m_api_authentication_method = Parser.api_authentication_method
        self.__m_api_credential_format = Parser.api_credential_format
        self.__m_verify_https_certificate = Parser.verify_https_certificate
        self.__m_use_proxy = Parser.use_proxy
        self.__m_proxy_url = Parser.proxy_url
        self.__m_proxy_port = Parser.proxy_port
        self.__m_proxy_username = Parser.proxy_username
        self.__m_proxy_password = Parser.proxy_password
        self.__mPrinter.verbose = Parser.verbose
        self.__mPrinter.debug = Parser.debug
        self.__m_output_format = Parser.output_format
        SQLite.database_filename = Parser.database_filename
        self.__parse_api_key()

    # ---------------------------------
    # private instance methods
    # ---------------------------------
    def __parse_api_key(self) -> None:
        try:
            l_file = "{}/{}".format(self.script_directory, self.api_key_file)
            self.__mPrinter.print("Parsing API credentials from {}".format(l_file), Level.INFO)

            with open(l_file, FileMode.READ.value) as l_key_file:
                l_json_data = json.load(l_key_file)
                if self.api_credential_format == ApiCredentialFormat.REFRESH_TOKEN.value:
                    self.__mPrinter.print("Parsing refresh token from {}".format(l_file), Level.INFO)
                    self.__m_refresh_token = l_json_data["credentials"]["refresh-token"]
                    self.__mPrinter.print("Parsed refresh token", Level.SUCCESS)
                    self.__get_access_token()
                elif self.api_credential_format == ApiCredentialFormat.USERNAME_PASSWORD.value:
                    self.__mPrinter.print("Parsing user ID and password from {}".format(l_file), Level.INFO)
                    self.__m_api_user_id = l_json_data["credentials"]["api-user-id"]
                    self.__m_api_password = l_json_data["credentials"]["api-password"]
                    self.__mPrinter.print("Parsed user ID and password token", Level.SUCCESS)
        except Exception as e:
            self.__mPrinter.print("__parse_api_key() - {0}".format(str(e)), Level.ERROR)

    def __get_access_token(self) -> None:

        self.__mPrinter.print("Trying to retrieve new access token", Level.INFO)

        try:
            l_headers = {
                self.__cAPI_KEY_HEADER: "Bearer {}".format(self.__m_refresh_token),
                self.__cUSER_AGENT_HEADER: self.__cUSER_AGENT_VALUE,
                self.__ACCEPT_HEADER: self.__ACCEPT_JSON_VALUE
            }

            l_http_response = self.__call_api(self.__cID_TOKEN_URL, l_headers)
            self.__m_access_token = json.loads(l_http_response.text)["token"]

            self.__mPrinter.print("Retrieved new access token", Level.SUCCESS)
        except Exception as e:
            self.__mPrinter.print("__get_access_token() - {0}".format(str(e)), Level.ERROR)

    def __connect_to_api(self, p_url: str, p_method: str=HTTPMethod.GET.value, p_data: str=None, p_json: str=None) -> requests.Response:
        l_authentication_header: str = ""
        try:
            self.__mPrinter.print("Connecting to API", Level.INFO)

            if self.api_authentication_method == ApiAuthenticationMethod.BEARER_TOKEN.value:
                l_authentication_header = "JWT {}".format(self.__m_access_token)
            elif self.api_authentication_method == ApiAuthenticationMethod.BASIC_AUTHENTICATION.value:
                l_credentials: str = "{}:{}".format(self.api_user_id, self.api_password)
                l_basic_auth_credentials: str = base64.standard_b64encode(l_credentials.encode("utf-8")).decode("utf-8")
                l_authentication_header = "Basic {}".format(l_basic_auth_credentials)

            l_headers = {
                self.__cAPI_KEY_HEADER: l_authentication_header,
                self.__cUSER_AGENT_HEADER: self.__cUSER_AGENT_VALUE,
                self.__ACCEPT_HEADER: self.__ACCEPT_CSV_VALUE if self.__m_accept_header == OutputFormat.CSV.value else self.__ACCEPT_JSON_VALUE
            }

            if p_method == HTTPMethod.POST.value and p_json:
                l_headers["Content-Type"]="text/json"

            l_http_response = self.__call_api(p_url=p_url, p_headers=l_headers, p_method=p_method, p_data=p_data, p_json=p_json)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except ValueError as e:
            self.__mPrinter.print("__connect_to_api() - {0}".format(str(e)), Level.ERROR)
            raise ValueError("__call_api() - {0}".format(str(e)))
        except Exception as e:
            self.__mPrinter.print("__connect_to_api() - {0}".format(str(e)), Level.ERROR)

    def __call_api(self, p_url: str, p_headers: dict, p_method: str=HTTPMethod.GET.value, p_data: str=None, p_json: str=None) -> requests.Response:
        l_proxies: dict = {}
        try:
            if self.__m_use_proxy:
                self.__mPrinter.print("Using upstream proxy", Level.INFO)
                l_proxies = self.__get_proxies()
            if Parser.debug:
                Printer.print("URL: {}".format(p_url), Level.DEBUG)
                Printer.print("Headers: {}".format(p_headers), Level.DEBUG)
                Printer.print("Proxy: {}".format(l_proxies), Level.DEBUG)
                Printer.print("Verify certificate: {}".format(self.__m_verify_https_certificate), Level.DEBUG)

            try:
                if p_method == HTTPMethod.GET.value:
                    l_http_response = requests.get(url=p_url, headers=p_headers, proxies=l_proxies, timeout=self.__m_api_connection_timeout, verify=self.__m_verify_https_certificate)
                elif p_method == HTTPMethod.POST.value:
                    #Note: data takes precedence over json unless data=None
                    l_http_response = requests.post(url=p_url, headers=p_headers, data=p_data, json=p_json, proxies=l_proxies, timeout=self.__m_api_connection_timeout, verify=self.__m_verify_https_certificate)
            except Exception as lRequestError:
                exit("Fatal - Cannot connect to API. Check connectivity to {}. {}".format(
                    self.__cBASE_URL,
                    'Upstream proxy is enabled in config.py. Ensure proxy settings are correct.' if self.__m_use_proxy else 'The proxy is not enabled. Should it be?'))

            if l_http_response.status_code not in [200, 201]:
                l_error_message ="{} {} - {}".format(l_http_response.status_code, l_http_response.reason, l_http_response.text)
                l_message = "Call to API returned status {}".format(l_error_message)
                raise ValueError(l_message)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except ValueError as e:
            self.__mPrinter.print("__call_api() - {0}".format(str(e)), Level.ERROR)
            raise ValueError("__call_api() - {0}".format(str(e)))
        except Exception as e:
            self.__mPrinter.print("__call_api() - {0}".format(str(e)), Level.ERROR)

    def __get_proxies(self) -> dict:
        try:
            # If proxy in use, create proxy URL in the format of http://user:password@example.com:port
            # Otherwise, return empty dictionary
            SCHEME = 0
            BASE_URL = 1
            l_proxy_handler: str = ""
            if not self.__m_proxy_password:
                self.__m_proxy_password = getpass.getpass('Please Enter Proxy Password: ')
            l_parts = self.__m_proxy_url.split('://')
            l_http_proxy_url: str = 'http://{}{}{}@{}{}{}'.format(
                self.__m_proxy_username if self.__m_proxy_username else '',
                ':' if self.__m_proxy_password else '',
                requests.utils.requote_uri(self.__m_proxy_password) if self.__m_proxy_password else '',
                l_parts[BASE_URL],
                ':' if self.__m_proxy_port else '',
                self.__m_proxy_port if self.__m_proxy_port else ''
            )
            l_https_proxy_url = l_http_proxy_url.replace('http://', 'https://')
            l_password_mask = '*' * len(self.__m_proxy_password)
            l_proxy_handlers = {'http':l_http_proxy_url, 'https':l_https_proxy_url}
            self.__mPrinter.print("Building proxy handlers: {},{}".format(
                l_http_proxy_url.replace(self.__m_proxy_password, l_password_mask),
                l_https_proxy_url.replace(self.__m_proxy_password, l_password_mask)), Level.INFO)
            return l_proxy_handlers
        except Exception as e:
            self.__mPrinter.print("__get_proxies() - {0}".format(str(e)), Level.ERROR)

    def __get_filename_from_content_disposition(self, l_http_response) -> str:
        try:
            l_content_disposition = l_http_response.headers.get('content-disposition')
            if not l_content_disposition:
                return None
            l_filename = re.findall('filename=(.+)', l_content_disposition)
            if not l_filename:
                return None
            return l_filename[0]
        except Exception as e:
            self.__mPrinter.print("__get_filename_from_content_disposition() - {0}".format(str(e)), Level.ERROR)

    def __print_json(self, p_json) -> None:
        try:
            for l_dict in p_json["List"]:
                print(l_dict)
        except Exception as e:
            self.__mPrinter.print("__print_json() - {0}".format(str(e)), Level.ERROR)

    def __print_next_page(self, p_base_url: str, p_json, p_print_csv_function) -> None:
        try:
            l_current_page_number: int = int(p_json["PageNumber"])
            l_next_page_number: int = l_current_page_number + 1
            l_base_url = p_base_url.replace("page={}".format(l_current_page_number),
                                            "page={}".format(l_next_page_number))
            l_http_response = self.__connect_to_api(l_base_url)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                self.__print_json(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                p_print_csv_function(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__print_next_page(l_base_url, l_json, p_print_csv_function)

        except Exception as e:
            self.__mPrinter.print("__print_next_page() - {0}".format(str(e)), Level.ERROR)

    def __get_next_page(self, p_base_url: str, p_json) -> list:
        try:
            l_current_page_number: int = int(p_json["PageNumber"])
            l_next_page_number: int = l_current_page_number + 1
            l_base_url = p_base_url.replace("page={}".format(l_current_page_number),
                                            "page={}".format(l_next_page_number))
            l_http_response = self.__connect_to_api(l_base_url)
            l_json = json.loads(l_http_response.text)

            l_list: list = l_json["List"]

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                l_list.extend(self.__get_next_page(l_base_url, l_json))

            return l_list
        except Exception as e:
            self.__mPrinter.print("__get_next_page() - {0}".format(str(e)), Level.ERROR)

    def __url_is_valid(self, p_url: str) -> bool:
        try:
            l_url_pattern = re.compile(
                r'^(?:http)s?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-_]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-_]{2,}\.?))'  # domain...
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            return re.match(l_url_pattern, p_url)
        except Exception as e:
            self.__mPrinter.print("__url_is_valid() - {0}".format(str(e)), Level.ERROR)

    def __url_is_secure(self, p_url: str) -> bool:
        try:
            l_https_pattern = re.compile(r'^https://', re.IGNORECASE)
            return re.match(l_https_pattern, p_url)
        except Exception as e:
            self.__mPrinter.print("__url_is_secure() - {0}".format(str(e)), Level.ERROR)

    # ---------------------------------
    # public instance methods
    # ---------------------------------
    def test_connectivity(self) -> None:
        try:
            l_url = self.__cACCOUNT_LICENSE_URL
            l_http_response = self.__connect_to_api(l_url)
            if not self.verbose:
                self.__mPrinter.print("Connected to API", Level.SUCCESS, True)
        except Exception as e:
            self.__mPrinter.print("test_connectivity() - Connection test failed. Unable to connect to API. {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Common Methods
    # ------------------------------------------------------------
    def __write_csv(self, p_header: list, p_data: list) -> None:
        try:
            if Parser.output_filename:
                self.__mPrinter.print("Opening file {} for writing".format(Parser.output_filename), Level.INFO)
                l_file = open(Parser.output_filename, FileMode.WRITE_CREATE.value)
            else:
                l_file = sys.stdout

            self.__mPrinter.print("Writing {} rows to {}".format(len(p_data), l_file.name), Level.INFO)
            l_csv_writer = csv.writer(l_file, quoting=csv.QUOTE_ALL)
            l_csv_writer.writerow(p_header)
            l_csv_writer.writerows(p_data)
            self.__mPrinter.print("Wrote {} rows to {}".format(len(p_data), l_file.name), Level.INFO)

        except Exception as e:
            self.__mPrinter.print("__write_csv() - {0}".format(str(e)), Level.ERROR)
        finally:
            if Parser.output_filename and l_file:
                l_file.close()

    def __get_unpaged_data(self, p_url: str, p_endpoint_name: str) -> list:
        try:
            self.__mPrinter.print("Fetching {} information".format(p_endpoint_name), Level.INFO)

            l_http_response = self.__connect_to_api(p_url=p_url)

            self.__mPrinter.print("Fetched {} information".format(p_endpoint_name), Level.SUCCESS)
            self.__mPrinter.print("Parsing {} information".format(p_endpoint_name), Level.INFO)
            l_json: list = json.loads(l_http_response.text)
            self.__mPrinter.print("Found {} {}".format(len(l_json), p_endpoint_name), Level.INFO)
            self.__mPrinter.print("Fetched {} information".format(p_endpoint_name), Level.INFO)

            return l_json

        except Exception as e:
            self.__mPrinter.print("__get_unpaged_data() - {0}".format(str(e)), Level.ERROR)

    def __get_paged_data(self, p_url: str, p_endpoint_name: str) -> list:
        try:
            self.__mPrinter.print("Fetching {} information".format(p_endpoint_name), Level.INFO)

            l_http_response = self.__connect_to_api(p_url=p_url)

            self.__mPrinter.print("Fetched {} information".format(p_endpoint_name), Level.SUCCESS)
            self.__mPrinter.print("Parsing {} information".format(p_endpoint_name), Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_sites: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} {}".format(l_number_sites, p_endpoint_name), Level.INFO)

            l_list: list = l_json["List"]

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                l_list.extend(self.__get_next_page(p_url, l_json))

            self.__mPrinter.print("Fetched {} information".format(p_endpoint_name), Level.INFO)

            return l_list

        except Exception as e:
            self.__mPrinter.print("__get_paged_data() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Account Methods
    # ------------------------------------------------------------
    def __get_account_header(self) -> list:
        return ["Name", "Email", "Time Zone"]

    def __parse_account_json_to_csv(self, p_json: list) -> list:
        try:
            l_account: list = []
            l_account.append([p_json["DisplayName"], p_json["Email"], p_json["TimeZoneInfo"]])
            return l_account
        except Exception as e:
            self.__mPrinter.print("__parse_account_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_account_csv(self, p_json: list):
        try:
            l_header: list = self.__get_account_header()
            l_account: list = self.__parse_account_json_to_csv(p_json)

            self.__write_csv(l_header, l_account)
        except Exception as e:
            self.__mPrinter.print("__print_account_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_account(self) -> list:
        try:
            return self.__get_unpaged_data(self.__cACCOUNT_ME_URL, "account")
        except Exception as e:
            self.__mPrinter.print("__get_account() - {0}".format(str(e)), Level.ERROR)

    def get_account(self) -> None:
        try:
            l_list: list = self.__get_account()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_account_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_account() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # License Methods
    # ------------------------------------------------------------
    def __get_license_header(self) -> list:
        return ["Site Count", "Site Limit", "Percent Used", "Start Date",
                "End Date", "Whitelisted", "License Type", "Remaining Days", "Status"]

    def __parse_license_json_to_csv(self, p_json: list) -> list:
        TWO_DECIMAL_PLACES:int = 2

        try:
            l_license: list = []

            l_site_count: str = p_json["SubscriptionSiteCount"]
            l_site_limit: str = p_json["SubscriptionMaximumSiteLimit"]
            l_percent_sites_used: float = round(l_site_count / l_site_limit,
                                                TWO_DECIMAL_PLACES) if l_site_limit != 0 else 0.0
            l_license_start_date: str = p_json["SubscriptionStartDate"]
            l_license_end_date: str = p_json["SubscriptionEndDate"]
            l_whitelisted: list = p_json["IsAccountWhitelisted"]

            l_license_type: list = p_json["Licenses"][0]["ProductDefinition"]
            l_license_remaining_days: list = p_json["Licenses"][0]["ValidForDays"]
            l_license_status: list = p_json["Licenses"][0]["IsActive"]

            l_license.append([l_site_count, l_site_limit, l_percent_sites_used, l_license_start_date,
                l_license_end_date, l_whitelisted, l_license_type, l_license_remaining_days,
                l_license_status])

            return l_license
        except Exception as e:
            self.__mPrinter.print("__parse_license_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_license_csv(self, p_license):
        try:
            l_header: list = self.__get_license_header()
            l_license: list = self.__parse_license_json_to_csv(p_license)

            self.__write_csv(l_header, l_license)
        except Exception as e:
            self.__mPrinter.print("__print_license_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_license(self) -> list:
        try:
            return self.__get_unpaged_data(self.__cACCOUNT_LICENSE_URL, "license")
        except Exception as e:
            self.__mPrinter.print("__get_license() - {0}".format(str(e)), Level.ERROR)

    def get_license(self) -> None:
        try:
            l_json: list = self.__get_license()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_license_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_license() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Team Member Methods
    # ------------------------------------------------------------
    def __get_team_members_header(self) -> list:
        return ["Name", "Email", "Enabled?", "Manage Apps?", "Manage Issues?", "Manage Issues (Restricted)?",
                "Manage Team?", "Manage Websites?", "Start Scan?", "View Reports?", "API Access?", "2FA?",
                "Groups"]

    def __parse_team_members_json_to_csv(self, p_json: list) -> list:
        try:
            l_team_members: list = []
            for l_user in p_json:
                l_groups: str = ",".join(l_user["SelectedGroups"])
                l_team_members.append([l_user["Name"], l_user["Email"], l_user["UserState"],
                        l_user["CanManageApplication"], l_user["CanManageIssues"], l_user["CanManageIssuesAsRestricted"],
                        l_user["CanManageTeam"], l_user["CanManageWebsites"], l_user["CanStartScan"],
                        l_user["CanViewScanReports"], l_user["IsApiAccessEnabled"],
                        l_user["IsTwoFactorAuthenticationEnabled"],
                        l_groups])
            return l_team_members
        except Exception as e:
            self.__mPrinter.print("__parse_team_members_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_team_members_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_team_members_header()
            l_team_members: list = self.__parse_team_members_json_to_csv(p_json)

            self.__write_csv(l_header, l_team_members)
        except Exception as e:
            self.__mPrinter.print("__print_team_members_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_team_members(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cTEAM_MEMBER_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            return self.__get_paged_data(l_base_url, "team members")
        except Exception as e:
            self.__mPrinter.print("__get_team_members() - {0}".format(str(e)), Level.ERROR)

    def get_team_members(self) -> None:
        try:
            l_json: list = self.__get_team_members()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_team_members_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_team_members() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Technologies Methods
    # ------------------------------------------------------------
    def __get_technologies_header(self) -> list:
        return ["Website Name", "Category", "Name", "Display Name", " Identified Version", "End of Life?",
                "Out of Date?", "Critical Issues", "High Issues", "Medium Issues", "Low Issues",
                "Info Issues", "Latest Version", "Last Seen", "ID", "Website ID", "Scan ID"]

    def __parse_technologies_json_to_csv(self, p_json: list) -> list:
        try:
            l_technologies: list = []
            for l_technology in p_json:
                l_technologies.append([l_technology["WebsiteName"], l_technology["Category"], l_technology["Name"],
                                       l_technology["DisplayName"], l_technology["IdentifiedVersion"],
                                       l_technology["EndOfLife"], l_technology["IsOutofDate"],
                                       l_technology["IssueCriticalCount"], l_technology["IssueHighCount"],
                                       l_technology["IssueMediumCount"], l_technology["IssueLowCount"],
                                       l_technology["IssueInfoCount"], l_technology["LatestVersion"],
                                       l_technology["LastSeenDate"], l_technology["Id"], l_technology["WebsiteId"],
                                       l_technology["ScanTaskId"]
                ])
            return l_technologies
        except Exception as e:
            self.__mPrinter.print("__parse_technologies_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_technologies_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_technologies_header()
            l_team_members: list = self.__parse_technologies_json_to_csv(p_json)

            self.__write_csv(l_header, l_team_members)
        except Exception as e:
            self.__mPrinter.print("__print_technologies_csv() - {0}".format(str(e)), Level.ERROR)

    def __handle_technologies(self, p_list: list) -> None:
        try:
            if self.__m_output_format == OutputFormat.JSON.value:
                print(p_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_technologies_csv(p_list)

        except Exception as e:
            self.__mPrinter.print("__handle_technologies() - {0}".format(str(e)), Level.ERROR)

    def __get_technologies(self, p_url: str) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                p_url, Parser.page_number, Parser.page_size
            )
            if Parser.website_name:
                l_base_url = "{}&webSiteName={}".format(l_base_url, Parser.website_name)
            if Parser.technology_name:
                l_base_url = "{}&technologyName={}".format(l_base_url, Parser.technology_name)

            return self.__get_paged_data(l_base_url, "technologies")
        except Exception as e:
            self.__mPrinter.print("__get_technologies() - {0}".format(str(e)), Level.ERROR)

    def get_technologies(self) -> None:
        try:
            l_json: list = self.__get_technologies(self.__cTECHNOLOGIES_LIST_URL)
            self.__handle_technologies(l_json)
        except Exception as e:
            self.__mPrinter.print("get_technologies() - {0}".format(str(e)), Level.ERROR)

    def get_obsolete_technologies(self) -> None:
        try:
            l_json: list = self.__get_technologies(self.__cOBSOLETE_TECHNOLOGIES_LIST_URL)
            self.__handle_technologies(l_json)
        except Exception as e:
            self.__mPrinter.print("get_obsolete_technologies() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Web Site Groups Methods
    # ------------------------------------------------------------
    def __get_website_groups_header(self) -> list:
        return ["Name", "Number Websites", "ID"]

    def __parse_website_groups_json_to_csv(self, p_json: list) -> list:
        try:
            l_website_groups: list = []
            for l_website_group in p_json:
                l_website_groups.append([l_website_group["Name"], l_website_group["TotalWebsites"], l_website_group["Id"]])
            return l_website_groups
        except Exception as e:
            self.__mPrinter.print("__parse_website_groups_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_website_groups_csv(self, p_json: list):
        try:
            l_header: list = self.__get_website_groups_header()
            l_website_groups: list = self.__parse_website_groups_json_to_csv(p_json)

            self.__write_csv(l_header, l_website_groups)
        except Exception as e:
            self.__mPrinter.print("__print_website_groups_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_website_groups(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cWEBSITE_GROUPS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            return self.__get_paged_data(l_base_url, "website groups")
        except Exception as e:
            self.__mPrinter.print("__get_website_groups() - {0}".format(str(e)), Level.ERROR)

    def get_website_groups(self) -> None:
        try:
            l_json: list = self.__get_website_groups()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_website_groups_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_website_groups() - {0}".format(str(e)), Level.ERROR)

    def upload_website_groups(self) -> None:
        try:
            self.__mPrinter.print("Opening file {}".format(Parser.input_filename), Level.INFO)
            l_input_file = open(Parser.input_filename,FileMode.READ.value).read().split('\n')
            for l_line in l_input_file:
                if l_line:
                    self.__mPrinter.print("Uploading website group {}".format(l_line), Level.INFO)
                    l_json=json.loads('{"Name": "'+l_line+'"}')
                    l_http_response = self.__connect_to_api(p_url=self.__cWEBSITE_GROUPS_UPLOAD_URL,
                                                            p_method=HTTPMethod.POST.value,
                                                            p_data=None, p_json=l_json)
                    self.__mPrinter.print("Uploaded website group {}".format(l_line), Level.INFO)
        except Exception as e:
            self.__mPrinter.print("upload_website_groups() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Discovered Services Methods
    # ------------------------------------------------------------
    def __get_discovered_services(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cDISCOVERED_SERVICES_LIST_URL, Parser.page_number, Parser.page_size)
            return self.__get_paged_data(l_base_url, "discovered services")
        except Exception as e:
            self.__mPrinter.print("__get_discovered_services() - {0}".format(str(e)), Level.ERROR)

    def get_discovered_services(self) -> None:
        try:
            l_json: list = self.__get_discovered_services()
            print(l_json)
        except Exception as e:
            self.__mPrinter.print("get_discovered_services() - {0}".format(str(e)), Level.ERROR)

    def download_discovered_services(self) -> None:
        try:
            self.__mPrinter.print("Fetching discovered services information", Level.INFO)
            l_base_url = "{0}?csvSeparator={1}".format(self.__cDISCOVERED_SERVICES_DOWNLOAD_URL, Parser.output_separator)
            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched discovered services information", Level.SUCCESS)

            self.__mPrinter.print("Writing issues to file {}".format(Parser.output_filename), Level.INFO)
            open(Parser.output_filename, FileMode.WRITE.value).write(l_http_response.text)
            self.__mPrinter.print("Wrote issues to file {}".format(Parser.output_filename), Level.SUCCESS)

        except Exception as e:
            self.__mPrinter.print("download_discovered_services() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Upload Website Methods
    # ------------------------------------------------------------
    def __map_business_unit(self, p_url: str) -> str:
        try:
            if "connectship" in p_url:
                l_business_unit = 'Business Unit: ConnectShip'
            elif "coyote" in p_url:
                l_business_unit = 'Business Unit: Coyote / Freightex'
            elif "freightex" in p_url:
                l_business_unit = 'Business Unit: Coyote / Freightex'
            elif "iship" in p_url:
                l_business_unit = 'Business Unit: IShip - Production'
            elif "marken" in p_url:
                l_business_unit = 'Business Unit: Marken'
            elif "nightline" in p_url:
                l_business_unit = 'Business Unit: Nightline'
            elif "pieffe" in p_url:
                l_business_unit = 'Business Unit: Pieffe'
            elif "polarspeed" in p_url:
                l_business_unit = 'Business Unit: Polar Speed'
            elif "poltraf" in p_url:
                l_business_unit = 'Business Unit: Poltraf'
            elif "sttas" in p_url:
                l_business_unit = 'Business Unit: STTAS'
            elif "upscapital" in p_url:
                l_business_unit = 'Business Unit: UPS Capital / Parcel Pro'
            elif "parcelpro" in p_url:
                l_business_unit = 'Business Unit: UPS Capital / Parcel Pro'
            elif "upsfreight" in p_url:
                l_business_unit = 'Business Unit: UPS Freight / Overnite'
            elif "overnite" in p_url:
                l_business_unit = 'Business Unit: UPS Freight / Overnite'
            elif "cemelog" in p_url:
                l_business_unit = 'Business Unit: UPS Healthcare Hungary'
            elif "upsstore" in p_url:
                l_business_unit = 'Business Unit: UPS Store'
            elif "ups.com.tr" in p_url:
                l_business_unit = 'Business Unit: Unsped Packet Servisi'
            else:
                l_business_unit = 'Business Unit: United Parcel Service'

            return l_business_unit
        except Exception as e:
            self.__mPrinter.print("__map_business_unit() - {0}".format(str(e)), Level.ERROR)

    def __build_website_json(self, p_agent_mode: str, p_url: str, p_groups: str, p_name: str) -> str:
        try:
            l_groups_string: str = self.__parse_website_groups(p_groups, p_url)

            l_json_string = '{"AgentMode": "' + p_agent_mode + '","RootUrl": "' + p_url + '"'

            if l_groups_string:
                l_json_string += ',"Groups": [' + l_groups_string + ']'

            l_json_string += ',"LicenseType":"Subscription", "Name": "' + p_name + '"}'

            return l_json_string
        except Exception as e:
            self.__mPrinter.print("__build_website_json() - {0}".format(str(e)), Level.ERROR)

    def __parse_website_url(self, p_url: str) -> str:
        try:
            l_url = p_url.lower()
            if not self.__url_is_valid(l_url):
                raise ValueError('__parse_url(): URL is not valid: {}'.format(l_url))
            if not self.__url_is_secure(l_url):
                raise ValueError('__parse_url(): URL is not secure. Protocol must be HTTPS: {}'.format(l_url))
            l_url = 'https://{0}/'.format(urlparse(l_url).hostname)
            return l_url
        except Exception as e:
            self.__mPrinter.print("__parse_website_url() - {0}".format(str(e)), Level.ERROR)

    def __parse_website_groups(self, p_groups: str, p_url: str) -> str:
        try:
            l_groups: list = p_groups.split("|")
            l_groups_string: str = ', '.join('"{0}"'.format(g) for g in l_groups)
            l_business_unit: str = self.__map_business_unit(p_url)

            # Add the business unit group based on the URL
            if l_groups_string:
                l_groups_string = '{0}, "{1}"'.format(l_groups_string, l_business_unit)
            else:
                l_groups_string = '"{0}"'.format(l_business_unit)

            return l_groups_string
        except Exception as e:
            self.__mPrinter.print("__parse_website_groups() - {0}".format(str(e)), Level.ERROR)

    def __parse_website_name(self, p_url: str) -> str:
        # l_name: str = p_name
        # if not l_name:
        #     raise ValueError('Name is blank')
        # return l_name
        # Change requested by TS to use domain name as site name instead of HS site name
        return urlparse(p_url).hostname.lower()

    def __upload_websites(self, p_websites: list) -> None:
        # Documentation: https://www.netsparkercloud.com/docs/index#/
        try:
            l_name: str = ""
            l_url: str = ""
            l_groups: str = ""

            l_file_timestamp_pattern: str = '%a-%b-%d-%Y-%H-%M-%S'
            l_output_file = open("{}{}{}{}".format(Parser.input_filename, ".failed.", time.strftime(l_file_timestamp_pattern), ".csv"), FileMode.WRITE_CREATE.value)
            l_csv_writer = csv.writer(l_output_file)

            for l_website in p_websites:
                try:
                    #l_name = self.__parse_website_name(l_website[WebsiteUploadFileFields.NAME.value])
                    l_name = self.__parse_website_name(l_website[WebsiteUploadFileFields.URL.value])
                    l_url = self.__parse_website_url(l_website[WebsiteUploadFileFields.URL.value])
                    l_groups = l_website[WebsiteUploadFileFields.GROUPS.value]
                    l_agent_mode: str = "Cloud" if "Segment: Externally Vendor Hosted" in l_groups else "Internal"
                    l_json_string = self.__build_website_json(l_agent_mode, l_url, l_groups, l_name)
                    l_json=json.loads(l_json_string)

                    self.__mPrinter.print("Uploading website {}".format(l_name), Level.INFO)
                    l_http_response = self.__connect_to_api(p_url=self.__cWEBSITES_UPLOAD_URL,
                                                           p_method=HTTPMethod.POST.value,
                                                           p_data=None, p_json=l_json)

                    if l_http_response:
                        self.__mPrinter.print("Uploaded website {0}".format(l_name), Level.INFO, Force.FORCE)
                    else:
                        raise ImportError("Unable to upload website {}".format(l_name))

                except ValueError as e:
                    self.__mPrinter.print(e, Level.ERROR, Force.FORCE)
                    l_csv_writer.writerow([l_name, l_url, l_groups, e])
                except ImportError as e:
                    self.__mPrinter.print(e, Level.ERROR, Force.FORCE)
                    l_csv_writer.writerow([l_name, l_url, l_groups, e])
                except Exception as e:
                    self.__mPrinter.print(e, Level.ERROR, Force.FORCE)
                    l_csv_writer.writerow([l_name, l_url, l_groups, e])
        except FileNotFoundError as e:
            self.__mPrinter.print("__upload_websites(): Cannot find the input file - {0}".format(str(e)), Level.ERROR)
        except Exception as e:
            self.__mPrinter.print("__upload_websites() - {0}:{1}".format(l_name, str(e)), Level.ERROR)
        finally:
            if l_output_file:
                l_output_file.close()

    def __parse_website_upload(self) -> list:
        try:
            self.__mPrinter.print("Opening file for reading {}".format(Parser.input_filename), Level.INFO)
            with open(Parser.input_filename, FileMode.READ.value) as l_input_file:
                l_csv_reader = csv.reader(l_input_file)

                l_sites: list = []
                for l_row in l_csv_reader:
                    if l_row:
                        l_sites.append((
                            l_row[WebsiteUploadFileFields.NAME.value],
                            l_row[WebsiteUploadFileFields.URL.value],
                            l_row[WebsiteUploadFileFields.GROUPS.value])
                        )
            return l_sites
        except FileNotFoundError as e:
            self.__mPrinter.print("__parse_website_upload(): Cannot find the input file {0} - {1}".format(Parser.input_filename, str(e)), Level.ERROR)
            raise FileNotFoundError(e)
        except Exception as e:
            self.__mPrinter.print("__parse_website_upload() - {0}:{1}".format(l_name, str(e)), Level.ERROR)
        finally:
            if l_input_file:
                l_input_file.close()

    def upload_websites(self) -> None:
        # Documentation: https://www.netsparkercloud.com/docs/index#/
        # PRECONDITION: The website is in at least one website group
        try:
            l_sites: list = self.__parse_website_upload()
            self.__upload_websites(l_sites)
        except Exception as e:
            self.__mPrinter.print("upload_websites() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Common Web Site Methods
    # ------------------------------------------------------------
    def __get_websites_header(self) -> list:
        return ["Name", "URL", "Technical Contact", "Verified?", "Agent", "Groups", "ID"]

    def __parse_website_json(self, p_json: list) -> list:
        try:
            l_groups: list = p_json["Groups"]
            l_groups_string: str = ""
            for l_group in l_groups:
                l_groups_string = "{},{}".format(l_groups_string, l_group["Name"])
            return [
                p_json["Name"], p_json["RootUrl"], p_json["TechnicalContactEmail"],
                p_json["IsVerified"], p_json["AgentMode"], l_groups_string[1:],
                p_json["Id"]
            ]
        except Exception as e:
            self.__mPrinter.print("__parse_websites_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Web Site Methods
    # ------------------------------------------------------------
    def __parse_website_json_to_csv(self, p_json: list) -> list:
        try:
            l_websites: list = []
            l_websites.append(self.__parse_website_json(p_json))
            return l_websites
        except Exception as e:
            self.__mPrinter.print("__parse_websites_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_website_csv(self, p_json: list) -> None:
        try:
            l_websites: list = self.__parse_website_json_to_csv(p_json)
            l_header: list = self.__get_websites_header()

            self.__write_csv(l_header, l_websites)

        except Exception as e:
            self.__mPrinter.print("__print_website_csv() - {0}".format(str(e)), Level.ERROR)

    def __handle_website(self, p_list: list) -> None:
        try:
            if self.__m_output_format == OutputFormat.JSON.value:
                print(p_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_website_csv(p_list)

        except Exception as e:
            self.__mPrinter.print("__handle_website() - {0}".format(str(e)), Level.ERROR)

    def __get_website_by_name_or_url(self) -> list:
        try:
            l_base_url = "{0}?query={1}".format(
                self.__cWEBSITES_GET_URL, Parser.query
            )
            return self.__get_unpaged_data(l_base_url, "websites")

        except Exception as e:
            self.__mPrinter.print("__get_website_by_name_or_url() - {0}".format(str(e)), Level.ERROR)

    def get_website_by_url(self) -> None:
        try:
            l_list: list = self.__get_website_by_name_or_url()
            self.__handle_website(l_list)
        except Exception as e:
            self.__mPrinter.print("get_website_by_url() - {0}".format(str(e)), Level.ERROR)

    def get_website_by_name(self) -> None:
        try:
            l_list: list = self.__get_website_by_name_or_url()
            self.__handle_website(l_list)
        except Exception as e:
            self.__mPrinter.print("get_website_by_name() - {0}".format(str(e)), Level.ERROR)

    def __get_website_by_id(self) -> list:
        try:
            l_base_url = "{}/{}".format(self.__cWEBSITES_GET_URL, Parser.website_id)
            return self.__get_unpaged_data(l_base_url, "websites")

        except Exception as e:
            self.__mPrinter.print("__get_website_by_id() - {0}".format(str(e)), Level.ERROR)

    def get_website_by_id(self) -> None:
        try:
            l_list: list = self.__get_website_by_id()
            self.__handle_website(l_list)
        except Exception as e:
            self.__mPrinter.print("get_website_by_id() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Web Sites Methods
    # ------------------------------------------------------------
    def __parse_websites_json_to_csv(self, p_json: list) -> list:
        try:
            l_websites: list = []
            for l_website in p_json:
                l_websites.append(self.__parse_website_json(l_website))
            return l_websites
        except Exception as e:
            self.__mPrinter.print("__parse_websites_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_websites_csv(self, p_json: list) -> None:
        try:
            l_websites: list = self.__parse_websites_json_to_csv(p_json)
            l_header: list = self.__get_websites_header()

            self.__write_csv(l_header, l_websites)

        except Exception as e:
            self.__mPrinter.print("__print_websites_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_websites(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cWEBSITES_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            return self.__get_paged_data(l_base_url, "websites")

        except Exception as e:
            self.__mPrinter.print("__get_websites() - {0}".format(str(e)), Level.ERROR)

    def __handle_websites(self, p_list: list) -> None:
        try:
            if self.__m_output_format == OutputFormat.JSON.value:
                print(p_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_websites_csv(p_list)

        except Exception as e:
            self.__mPrinter.print("__handle_websites() - {0}".format(str(e)), Level.ERROR)

    def get_websites(self) -> None:
        try:
            l_list: list = self.__get_websites()
            self.__handle_websites(l_list)
        except Exception as e:
            self.__mPrinter.print("get_websites() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Get Websites by Group (Name or ID)
    # ------------------------------------------------------------
    def ____get_websites_by_group(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}&query={3}".format(
                self.__cWEBSITES_BY_GROUP_LIST_URL,
                Parser.page_number, Parser.page_size, Parser.query
            )
            return self.__get_paged_data(l_base_url, "websites")

        except Exception as e:
            self.__mPrinter.print("____get_websites_by_group() - {0}".format(str(e)), Level.ERROR)

    def __get_websites_by_group(self) -> None:
        try:
            l_list: list = self.____get_websites_by_group()
            self.__handle_websites(l_list)
        except Exception as e:
            self.__mPrinter.print("__get_websites_by_group() - {0}".format(str(e)), Level.ERROR)

    def get_websites_by_group_name(self) -> None:
        self.__get_websites_by_group()

    def get_websites_by_group_id(self) -> None:
        self.__get_websites_by_group()

    # ------------------------------------------------------------
    # Ping Sites Methods
    # ------------------------------------------------------------
    def __get_ping_site_results_header(self) -> list:
        return ["Name", "URL", "Status", "Status Code", "Comment"]

    def __print_ping_site_results_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_ping_site_results_header()
            l_sites: list = self.__parse_ping_site_results_json_to_csv(p_json)

            self.__write_csv(l_header, l_sites)

        except Exception as e:
            self.__mPrinter.print("__print_ping_site_results_csv() - {0}".format(str(e)), Level.ERROR)

    def __handle_ping_sites_results(self, p_list: list) -> None:
        try:
            if self.__m_output_format == OutputFormat.JSON.value:
                print(p_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_ping_site_results_csv(p_list)
        except Exception as e:
            self.__mPrinter.print("__handle_ping_sites_results() - {0}".format(str(e)), Level.ERROR)

    def __web_server_is_up(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["1", "2", "3", "4"]

    def __web_server_is_redirecting(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["3"]

    def __web_server_is_down(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["5"]

    def __cannot_resolve_URL(self, p_status_code: int) -> bool:
        return p_status_code == 502

    def __is_authentication_site(self, p_domain: str) -> bool:
        return p_domain in Parser.authentication_sites

    def __is_authentication_page(self, p_url: str) -> bool:
        return "login" in p_url or "logon" in p_url or "account" in p_url or "returnurl" in p_url or "backurl" in p_url or "authorize" in p_url

    def __ping_url(self, p_url:str, p_method: int):

        l_proxies: dict = {}
        l_site_is_up: bool = False

        self.__mPrinter.print("Testing site {}".format(p_url), Level.INFO)

        if p_method == PingMethod.INITIAL_TEST.value:

            try:
                if self.__m_use_proxy:
                    self.__mPrinter.print("Using upstream proxy", Level.INFO)
                    l_proxies = self.__get_proxies()
                l_http_response = requests.get(url=p_url, proxies=l_proxies, timeout=self.__m_api_connection_timeout,
                                               verify=self.__m_verify_https_certificate, allow_redirects=False)
                l_status_code = l_http_response.status_code
                l_reason = l_http_response.reason
                self.__mPrinter.print("HTTP request return status code {0}-{1}".format(l_status_code, l_reason),
                                      Level.SUCCESS)
                if self.__web_server_is_down(l_status_code):
                    raise requests.exceptions.ConnectionError
                l_site_is_up = True
            except requests.exceptions.RequestException as e:
                raise requests.exceptions.ConnectionError

        elif p_method == PingMethod.SECOND_TEST_NO_PROXY.value:

            try:
                self.__mPrinter.print(
                    "Since proxy enabled and site not responding, checking if site might be internal",
                    Level.INFO)
                l_http_response = requests.get(url=p_url, timeout=self.__m_api_connection_timeout, allow_redirects=False)
                l_status_code = l_http_response.status_code
                l_reason = l_http_response.reason
                self.__mPrinter.print(
                    "HTTP request return status code {0}-{1}".format(l_status_code, l_reason),
                    Level.SUCCESS)
                if self.__web_server_is_up(l_status_code):
                    self.__mPrinter.print("The site appears to be internal", Level.SUCCESS)
                l_site_is_up = True
            except requests.exceptions.RequestException as e:
                l_site_is_up = False
                l_status_code = 503
                l_reason = str(e)

        elif p_method == PingMethod.SECOND_TEST_USE_PROXY.value:

            try:
                self.__mPrinter.print(
                    "Since proxy is not enabled and site not responding, checking if site might be external. Using proxy configuration from config.py",
                    Level.INFO)
                l_proxies = self.__get_proxies()
                l_http_response = requests.get(url=p_url, proxies=l_proxies, timeout=self.__m_api_connection_timeout,
                                               verify=self.__m_verify_https_certificate, allow_redirects=False)
                l_status_code = l_http_response.status_code
                l_reason = l_http_response.reason
                self.__mPrinter.print(
                    "HTTP request return status code {0}-{1}".format(l_status_code, l_reason),
                    Level.SUCCESS)
                if self.__web_server_is_up(l_status_code):
                    self.__mPrinter.print("The site appears to be external", Level.SUCCESS)
                l_site_is_up = True

            except requests.exceptions.ProxyError as e:
                l_site_is_up = False
                l_status_code = 503
                l_reason = "Proxy error. Make sure proxy is configured correctly in config.py. {}".format(str(e))
            except requests.exceptions.RequestException as e:
                l_site_is_up = False
                l_status_code = 503
                l_reason = str(e)

        if self.__web_server_is_redirecting(l_status_code):
            l_current_domain = urlparse(l_http_response.url).hostname
            l_redirect_url = l_http_response.next.url.lower()
            l_redirect_path = urlparse(l_redirect_url).path
            l_redirect_domain = urlparse(l_redirect_url).hostname
            self.__mPrinter.print("Server redirected from {} to {}".format(l_current_domain, l_redirect_domain), Level.INFO)
            if l_current_domain == l_redirect_domain:
                if self.__is_authentication_page(l_redirect_url):
                    l_site_is_up = True
                    l_reason = "Server is redirecting to login page {}".format(l_redirect_url)
                else:
                    l_site_is_up = True
                    l_reason = "Server is redirecting within same domain to page {}".format(l_redirect_path)
            elif self.__is_authentication_site(l_redirect_domain):
                l_site_is_up = True
                l_reason = "Server is redirecting to an authentication domain {}".format(l_redirect_domain)
            else:
                l_site_is_up = False
                l_reason = "Domain may be black-holed. Server is redirecting to a different domain to page {}".format(l_redirect_url)

        return l_site_is_up, l_status_code, l_reason

    def __ping_sites(self, p_list: list) -> list:
        try:
            l_results: list = []

            self.__mPrinter.print("Beginning site analysis", Level.INFO)

            for l_record in p_list:
                l_name: str = l_record[WebsiteUploadFileFields.NAME.value]
                l_url: str = l_record[WebsiteUploadFileFields.URL.value]

                try:
                    self.__mPrinter.print("Initial test for site {}".format(l_url), Level.INFO)
                    l_site_is_up, l_status_code, l_reason = self.__ping_url(l_url, PingMethod.INITIAL_TEST.value)
                except requests.exceptions.ConnectionError as e:
                    # Check our current proxy status and try the opposite
                    self.__mPrinter.print("Second test for site {}".format(l_url), Level.INFO)
                    if self.__m_use_proxy:
                        l_site_is_up, l_status_code, l_reason = self.__ping_url(l_url, PingMethod.SECOND_TEST_NO_PROXY.value)
                    else:
                        l_site_is_up, l_status_code, l_reason = self.__ping_url(l_url, PingMethod.SECOND_TEST_USE_PROXY.value)

                l_status:str = "Up" if l_site_is_up else "Down"
                self.__mPrinter.print("Response for site {} ({}): {} {}. Site is {}".format(l_name, l_url, l_status_code, l_reason, l_status), Level.INFO)
                l_results.append([l_name, l_url, l_status, l_status_code, l_reason])

            return l_results

        except Exception as e:
            self.__mPrinter.print("__ping_sites() - {0}".format(str(e)), Level.ERROR)

    def ping_sites(self) -> None:

        try:
            l_sites: list = []
            l_list: list = self.__get_websites()
            for l_record in l_list:
                l_sites.append((l_record["Name"], l_record["RootUrl"]))
            l_results: list = self.__ping_sites(l_sites)
            self.__handle_ping_sites_results(l_results)
        except Exception as e:
            self.__mPrinter.print("ping_sites() - {0}".format(str(e)), Level.ERROR)

    def ping_sites_in_file(self) -> None:

        try:
            l_sites: list = self.__parse_website_upload()
            l_results = self.__ping_sites(l_sites)
            self.__handle_ping_sites_results(l_results)
        except Exception as e:
            self.__mPrinter.print("ping_sites_in_file() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Vulnerability Templates Methods
    # ------------------------------------------------------------
    def __get_vulnerability_templates_header(self) -> list:
        return ["Type", "Name", "CVSSv3", "Severity"]

    def __parse_vulnerability_templates_json_to_csv(self, p_json: list) -> list:
        try:
            l_vulnerability_templates: list = []

            for l_template in p_json:
                l_cvssv3: str = "0.0"
                try:
                    l_cvssv3 = l_template["Cvss31Vector"]["Base"]["Score"]["Value"]
                    if not l_cvssv3:
                        raise ValueError()
                except:
                    try:
                        l_cvssv3 = l_template["CvssVector"]["Base"]["Score"]["Value"]
                    except:
                        pass
                l_vulnerability_templates.append([l_template["Type"], l_template["Description"], l_cvssv3, l_template["Severity"]])

            return l_vulnerability_templates
        except Exception as e:
            self.__mPrinter.print("__parse_vulnerability_templates_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_vulnerability_templates_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_vulnerability_templates_header()
            l_vulnerability_templates: list = self.__parse_vulnerability_templates_json_to_csv(p_json)

            self.__write_csv(l_header, l_vulnerability_templates)
        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_templates_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_vulnerability_templates(self) -> list:
        try:
            l_base_url = "{0}?reportPolicyId={1}".format(
                self.__cVULNERABILITY_TEMPLATES_LIST_URL,
                Parser.report_policy_id
            )
            return self.__get_unpaged_data(l_base_url, "vulnerability templates")

        except Exception as e:
            self.__mPrinter.print("__get_vulnerability_templates() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_templates(self) -> None:
        try:
            l_list: list = self.__get_vulnerability_templates()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_vulnerability_templates_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_templates() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Vulnerability Template Methods
    # ------------------------------------------------------------
    def __get_vulnerability_template_header(self) -> list:
        return ["Name", "CVSSv3", "Severity", "Description"]

    def __parse_vulnerability_template_json_to_csv(self, p_json: list) -> list:
        try:
            l_vulnerability_template: list = []

            l_dict: dict = p_json[0]
            l_cvssv3: str = "0.0"
            try:
                l_cvssv3 = str(l_dict["Cvss31Vector"]["Base"]["Score"]["Value"])
                if not l_cvssv3:
                    raise ValueError()
            except:
                try:
                    l_cvssv3 = str(l_dict["CvssVector"]["Base"]["Score"]["Value"])
                except:
                    pass

            l_vulnerability_template.append([l_dict["Description"], l_cvssv3, l_dict["Severity"], l_dict["Summary"]])

            return l_vulnerability_template
        except Exception as e:
            self.__mPrinter.print("__parse_vulnerability_template_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_vulnerability_template_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_vulnerability_template_header()
            l_vulnerability_template: list = self.__parse_vulnerability_template_json_to_csv(p_json)

            self.__write_csv(l_header, l_vulnerability_template)
        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_template_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_vulnerability_template(self) -> list:
        try:
            l_base_url = "{0}?type={1}".format(
                self.__cVULNERABILITY_TEMPLATE_URL,
                Parser.vulnerability_type, Parser.report_policy_id
            )
            return self.__get_unpaged_data(l_base_url, "vulnerability template")

        except Exception as e:
            self.__mPrinter.print("__get_vulnerability_template() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_template(self) -> None:
        try:
            l_list: list = self.__get_vulnerability_template()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_dict)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_vulnerability_template_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_template() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Vulnerability Types Methods
    # ------------------------------------------------------------
    def __get_vulnerability_types_header(self) -> list:
        return ["Name"]

    def __parse_vulnerability_types_json_to_csv(self, p_json: list) -> list:
        try:
            l_vulnerability_types: list = []

            for l_vulnerability_type in p_json:
                l_vulnerability_types.append([l_vulnerability_type])
            return l_vulnerability_types
        except Exception as e:
            self.__mPrinter.print("__parse_vulnerability_types_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_vulnerability_types_csv(self, p_json: list) -> None:
        try:
            l_header: list = self.__get_vulnerability_types_header()
            l_vulnerability_types: list = self.__parse_vulnerability_types_json_to_csv(p_json)

            self.__write_csv(l_header, l_vulnerability_types)
        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_types_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_vulnerability_types(self) -> list:
        try:
            return self.__get_unpaged_data(self.__cVULNERABILITY_TEMPLATE_TYPES_URL, "vulnerability types")
        except Exception as e:
            self.__mPrinter.print("__get_vulnerability_types() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_types(self) -> None:
        try:
            l_list: list = self.__get_vulnerability_types()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_vulnerability_types_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_types() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Agents Methods
    # ------------------------------------------------------------
    def __get_agents_header(self) -> list:
        return ["Needs Update?", "Name", "IP address", "Status", "Version", "Last Heartbeat",
                "VDB Version", "Operating System", "Architecture", "ID"]

    def __parse_agents_json_to_csv(self, p_json: list) -> list:
        try:
            l_agents: list = []
            for l_agent in p_json:
                l_agents.append([
                    l_agent["IsAgentNeedsUpdate"], l_agent["Name"], l_agent["IpAddress"],
                    l_agent["State"], l_agent["Version"], self.__format_datetime(parser.parse(l_agent["Heartbeat"])),
                    l_agent["VdbVersion"], l_agent["OsDescription"], l_agent["ProcessArchitecture"],
                    l_agent["Id"]
                ])
            return l_agents
        except Exception as e:
            self.__mPrinter.print("__parse_agents_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_agents_csv(self, p_json: list) -> None:
        try:
            l_agents: list = self.__parse_agents_json_to_csv(p_json)
            l_header: list = self.__get_agents_header()

            self.__write_csv(l_header, l_agents)
        except Exception as e:
            self.__mPrinter.print("__print_agents_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_agents(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cAGENTS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            return self.__get_paged_data(l_base_url, "agents")

        except Exception as e:
            self.__mPrinter.print("__get_agents() - {0}".format(str(e)), Level.ERROR)

    def get_agents(self) -> None:
        try:
            l_list: list = self.__get_agents()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_agents_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_agents() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Report Helper Methods
    # ------------------------------------------------------------
    def __format_exitcode(self, p_exitcode: ExitCodes) -> str:
        return "{} ({})".format(p_exitcode.value, p_exitcode.name)

    def __format_datetime(self, p_datetime: datetime) -> str:
        return "{} EST".format(p_datetime.astimezone(self.__c_EASTERN_TIMEZONE).strftime(self.__c_DATETIME_FORMAT))

    def __create_breadcrumb(self, p_filename: str) -> None:
        try:
            Printer.print("Creating breadcrumb file {}".format(p_filename), Level.INFO)
            l_file = open(p_filename, FileMode.WRITE_CREATE.value)
            l_file.write(str(int(datetime.now().timestamp())))
            Printer.print("Created breadcrumb file {}".format(p_filename), Level.INFO)
        except Exception as e:
            self.__mPrinter.print("__create_breadcrumb() - {0}".format(str(e)), Level.ERROR)
        finally:
            if l_file:
                l_file.close()

    def __read_breadcrumb(self, p_filename: str) -> datetime:
        try:
            Printer.print("Reading breadcrumb file {}".format(p_filename), Level.INFO)
            with open(p_filename, FileMode.READ.value) as l_file:
                l_string: str = l_file.read()
                if l_string:
                    l_time: datetime = datetime.fromtimestamp(int(l_string))
                    Printer.print("Timestamp in breadcrumb file {} is {}".format(p_filename, self.__format_datetime(l_time)), Level.INFO)
                    return l_time
                else:
                    raise ValueError("Breadcrumb file {} is empty".format(p_filename))
            Printer.print("Closing breadcrumb file {}".format(p_filename), Level.INFO)
        except FileNotFoundError as e:
            self.__mPrinter.print("__read_breadcrumb() - File not found {0}".format(str(e)), Level.INFO)
            raise FileNotFoundError(e)
        except ValueError as e:
            self.__mPrinter.print("__read_breadcrumb() - {0}".format(str(e)), Level.ERROR)
            raise ValueError(e)
        except Exception as e:
            self.__mPrinter.print("__read_breadcrumb() - {0}".format(str(e)), Level.ERROR)
            raise Exception(e)

    def __already_reported(self, p_filename: str, p_notification_interval: int) -> bool:
        try:
            Printer.print("Checking if issues already reported today", Level.INFO)
            l_current_time: datetime = datetime.today()
            l_breadcrumb_time: datetime = self.__read_breadcrumb(p_filename)
            l_difference = l_current_time - l_breadcrumb_time
            l_difference_minutes = l_difference.total_seconds() // 60
            l_already_reported = l_difference_minutes < p_notification_interval

            Printer.print("Current time: {}".format(self.__format_datetime(l_current_time)), Level.INFO)
            Printer.print("Breadcrumb time: {}".format(self.__format_datetime(l_breadcrumb_time)) ,Level.INFO)
            Printer.print("Difference: {} minutes".format(l_difference_minutes), Level.INFO)
            Printer.print("Notification interval: {} minutes".format(p_notification_interval), Level.INFO)
            Printer.print("Already reported?: {}".format(l_already_reported), Level.INFO)

            return (l_already_reported)
        except ValueError as e:
            return False
        except FileNotFoundError as e:
            return False
        except Exception as e:
            self.__mPrinter.print("__already_reported() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Report Methods
    # ------------------------------------------------------------
    def __parse_unresponsive_agents(self, p_agents: list) -> list:
        try:
            l_unresponsive_agents: list = []
            l_now: datetime = datetime.now(timezone.utc)

            Printer.print("Parsing unresponsive agents", Level.INFO)

            for l_dict in p_agents:
                l_heartbeat_time: datetime = parser.parse(l_dict["Heartbeat"])
                l_diff = (l_now - l_heartbeat_time)
                if l_diff.seconds > Parser.agent_heartbeat_too_long_seconds:
                    l_unresponsive_agents.append(l_dict)
                    Printer.print(
                        "Unresponsive agent found. {} Current time: {}. Last heartbeat: {}. Difference: {}. State: {}".format(
                            l_dict["Name"],
                            self.__format_datetime(l_now),
                            self.__format_datetime(l_heartbeat_time),
                            l_diff,
                            l_dict["State"]
                        ), Level.INFO)

            Printer.print("{} unresponsive agents found".format(len(l_unresponsive_agents)), Level.INFO)
            return l_unresponsive_agents
        except Exception as e:
            self.__mPrinter.print("__parse_unresponsive_agents() - {0}".format(str(e)), Level.ERROR)

    def report_agents_missing_heartbeat(self) -> int:
        try:
            if Parser.unattended and self.__already_reported(Parser.agent_heartbeat_breadcrumb_filename, Parser.agent_heartbeat_notification_interval_minutes):
                Printer.print("Already reported in today. Exiting with status {}".format(
                    self.__format_exitcode(ExitCodes.ALREADY_REPORTED)), Level.INFO)
                return ExitCodes.ALREADY_REPORTED.value

            l_list = self.__get_agents()
            l_unresponsive_agents: list = self.__parse_unresponsive_agents(l_list)

            if l_unresponsive_agents:
                if self.__m_output_format == OutputFormat.JSON.value:
                    print(l_unresponsive_agents)
                elif self.__m_output_format == OutputFormat.CSV.value:
                    self.__print_agents_csv(l_unresponsive_agents)

                if Parser.unattended:
                    self.__create_breadcrumb(Parser.agent_heartbeat_breadcrumb_filename)

                Printer.print("Exiting with status code {}".format(self.__format_exitcode(ExitCodes.EXIT_NORMAL)), Level.INFO)
                return ExitCodes.EXIT_NORMAL.value
            else:
                Printer.print("No unresponsive agents found", Level.SUCCESS)
                Printer.print("Exiting with status code {}".format(self.__format_exitcode(ExitCodes.NOTHING_TO_REPORT)), Level.INFO)
                return ExitCodes.NOTHING_TO_REPORT.value

        except Exception as e:
            self.__mPrinter.print("report_agents_missing_heartbeat() - {0}".format(str(e)), Level.ERROR)

    def __parse_disabled_agents(self, p_agents: list) -> list:
        try:
            l_disabled_agents: list = []

            Printer.print("Parsing disabled agents", Level.INFO)

            for l_dict in p_agents:
                l_state: str = l_dict["State"]
                if l_state in ["Disabled"]:
                    l_disabled_agents.append(l_dict)
                    Printer.print("Disabled agent found. {} State: {}".format(l_dict["Name"], l_state), Level.INFO)

            Printer.print("{} disabled agents found".format(len(l_disabled_agents)), Level.INFO)
            return l_disabled_agents
        except Exception as e:
            self.__mPrinter.print("__parse_disabled_agents() - {0}".format(str(e)), Level.ERROR)

    def report_disabled_agents(self) -> int:
        try:
            if Parser.unattended and self.__already_reported(
                    Parser.disabled_agents_breadcrumb_filename, Parser.disabled_agents_notification_interval_minutes):
                Printer.print("Already reported in today. Exiting with status {}".format(
                    self.__format_exitcode(ExitCodes.ALREADY_REPORTED)), Level.INFO)
                return ExitCodes.ALREADY_REPORTED.value

            l_list = self.__get_agents()
            l_disabled_agents: list = self.__parse_disabled_agents(l_list)

            if l_disabled_agents:
                if self.__m_output_format == OutputFormat.JSON.value:
                    print(l_disabled_agents)
                elif self.__m_output_format == OutputFormat.CSV.value:
                    self.__print_agents_csv(l_disabled_agents)

                if Parser.unattended:
                    self.__create_breadcrumb(Parser.disabled_agents_breadcrumb_filename)

                Printer.print("Exiting with status code {}".format(self.__format_exitcode(ExitCodes.EXIT_NORMAL)), Level.INFO)
                return ExitCodes.EXIT_NORMAL.value
            else:
                Printer.print("No disabled agents found", Level.SUCCESS)
                Printer.print("Exiting with status code {}".format(self.__format_exitcode(ExitCodes.NOTHING_TO_REPORT)), Level.INFO)
                return ExitCodes.NOTHING_TO_REPORT.value

        except Exception as e:
            self.__mPrinter.print("report_disabled_agents() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Get Scans Methods
    # ------------------------------------------------------------
    def __get_scans_header(self) -> list:
        return ["Website Name", "Website URL", "Target URL",
                "Initiated At", "Duration", "Agent Name", "Type", "State", "Phase",
                "Is Complete?", "Total Vulnerability Count", "VulnerabilityCriticalCount",
                "VulnerabilityHighCount", "VulnerabilityMediumCount", "VulnerabilityLowCount",
                "VulnerabilityBestPracticeCount", "VulnerabilityInfoCount"]

    def __parse_scans_json_to_csv(self, p_json: list) -> list:
        try:
            l_scans: list = []
            for l_scan in p_json:
                l_scans.append([
                    l_scan["WebsiteName"], l_scan["WebsiteUrl"], l_scan["TargetUrl"],
                    self.__format_datetime(parser.parse(l_scan["InitiatedAt"])),
                    l_scan["Duration"], l_scan["AgentName"], l_scan["ScanType"], l_scan["State"],
                    l_scan["Phase"], l_scan["IsCompleted"], l_scan["TotalVulnerabilityCount"],
                    l_scan["VulnerabilityCriticalCount"], l_scan["VulnerabilityHighCount"],
                    l_scan["VulnerabilityMediumCount"], l_scan["VulnerabilityLowCount"],
                    l_scan["VulnerabilityBestPracticeCount"],l_scan["VulnerabilityInfoCount"]
                ])
            return l_scans
        except Exception as e:
            self.__mPrinter.print("__parse_scans_json_to_csv() - {0}".format(str(e)), Level.ERROR)

    def __print_scans_csv(self, l_json: list) -> None:
        try:
            l_scans: list = self.__parse_scans_json_to_csv(l_json)
            l_header: list = self.__get_scans_header()

            self.__write_csv(l_header, l_scans)
        except Exception as e:
            self.__mPrinter.print("__print_scans_csv() - {0}".format(str(e)), Level.ERROR)

    def __get_scans(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cSCANS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            return self.__get_paged_data(l_base_url, "scans")

        except Exception as e:
            self.__mPrinter.print("__get_scans() - {0}".format(str(e)), Level.ERROR)

    def get_scans(self):
        try:
            l_list: list = self.__get_scans()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_scans_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_scans() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Get Scans by Websites Methods
    # ------------------------------------------------------------
    def __get_scans_by_website(self) -> list:
        try:
            l_base_url = "{0}?page={1}&pageSize={2}&initiatedDateSortType={3}".format(
                self.__cSCANS_LIST_BY_WEBSITE_URL,
                Parser.page_number, Parser.page_size, Parser.initiated_date_sort_direction
            )
            if Parser.website_url:
                l_base_url = "{}&websiteUrl={}".format(l_base_url, Parser.website_url)
            if Parser.target_url:
                l_base_url = "{}&targetUrl={}".format(l_base_url, Parser.target_url)
            return self.__get_paged_data(l_base_url, "scans")

        except Exception as e:
            self.__mPrinter.print("__get_scans_by_website() - {0}".format(str(e)), Level.ERROR)

    def get_scans_by_website(self):
        try:
            l_list: list = self.__get_scans_by_website()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_list)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_scans_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_scans_by_wesbsite() - {0}".format(str(e)), Level.ERROR)

    # ------------------------------------------------------------
    # Business Scorecard Report Methods
    # ------------------------------------------------------------
    def report_business_scorecard(self):
        try:
            print("Not Implemented. Waiting on scan endpoints.")
            return 0

        except Exception as e:
            self.__mPrinter.print("report_business_scorecard() - {0}".format(str(e)), Level.ERROR)