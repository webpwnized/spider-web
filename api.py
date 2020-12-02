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
    ALREADY_REPORTED_TODAY = 8


class API:

    # ---------------------------------
    # "Private" class variables
    # ---------------------------------
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

    __cTEAM_MEMBER_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "teammembers/list")

    __cDISCOVERED_SERVICES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/list")
    __cDISCOVERED_SERVICES_DOWNLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/export")

    __cWEBSITES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/list")
    __cWEBSITES_UPLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websites/new")

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

    def __call_api(self, p_url: str, p_headers: dict, p_method: str=HTTPMethod.GET.value, p_data: str=None, p_json: str=None):
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

    def __get_proxies(self):
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

    def __get_filename_from_content_disposition(self, l_http_response):

        l_content_disposition = l_http_response.headers.get('content-disposition')
        if not l_content_disposition:
            return None
        l_filename = re.findall('filename=(.+)', l_content_disposition)
        if not l_filename:
            return None
        return l_filename[0]

    def __print_json(self, p_json):
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
        l_url_pattern = re.compile(
            r'^(?:http)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(l_url_pattern, p_url)

    def __url_is_secure(self, p_url: str) -> bool:
        l_https_pattern = re.compile(r'^https://', re.IGNORECASE)
        return re.match(l_https_pattern, p_url)

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
            self.__mPrinter.print("Connection test failed. Unable to connect to API. {0}".format(str(e)), Level.ERROR)

    def get_account(self) -> None:
        try:
            self.__mPrinter.print("Fetching account information", Level.INFO)
            l_http_response = self.__connect_to_api(self.__cACCOUNT_ME_URL)
            self.__mPrinter.print("Fetched account information", Level.SUCCESS)
            self.__mPrinter.print("Parsing account information", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                l_name: str = l_json["DisplayName"]
                l_email: str = l_json["Email"]
                l_timezone: str = l_json["TimeZoneInfo"]
                print("Name, Email, Time Zone")
                print("{},{},{}".format(l_name, l_email, l_timezone))

        except Exception as e:
            self.__mPrinter.print("get_account() - {0}".format(str(e)), Level.ERROR)

    def get_license(self) -> None:
        TWO_DECIMAL_PLACES:int = 2

        try:
            self.__mPrinter.print("Fetching license information", Level.INFO)
            l_http_response = self.__connect_to_api(self.__cACCOUNT_LICENSE_URL)
            self.__mPrinter.print("Fetched license information", Level.SUCCESS)
            self.__mPrinter.print("Parsing license information", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                #l_percent_sites_used: float = 0.0
                l_percent_credit_used: float = 0.0

                l_site_count: str = l_json["SubscriptionSiteCount"]
                l_site_limit: str = l_json["SubscriptionMaximumSiteLimit"]
                l_percent_sites_used: float = round(l_site_count / l_site_limit, TWO_DECIMAL_PLACES) if l_site_limit != 0 else 0.0
                l_license_start_date: str = l_json["SubscriptionStartDate"]
                l_license_end_date: str = l_json["SubscriptionEndDate"]
                l_whitelisted: list = l_json["IsAccountWhitelisted"]

                #l_scan_credit_count: list = l_json["ScanCreditCount"]
                #l_scan_credit_limit: list = l_json["UsedScanCreditCount"]
                #l_percent_credit_used: float = round(l_scan_credit_count / l_scan_credit_limit, TWO_DECIMAL_PLACES) if l_scan_credit_limit != 0 else 0.0

                l_license_type: list = l_json["Licenses"][0]["ProductDefinition"]
                l_license_remaining_days: list = l_json["Licenses"][0]["ValidForDays"]
                l_license_status: list = l_json["Licenses"][0]["IsActive"]

                print("Site Count, Site Limit, Percent Used, Start Date, "
                      "End Date, Whitelisted, License Type, Remaining Days, Status")
                print("{},{},{},{},{},{},{},{},{}".format(
                    l_site_count, l_site_limit, l_percent_sites_used, l_license_start_date,
                    l_license_end_date, l_whitelisted, l_license_type, l_license_remaining_days,
                    l_license_status
                ))

        except Exception as e:
            self.__mPrinter.print("get_license() - {0}".format(str(e)), Level.ERROR)

    def __print_agents_csv(self, p_list):
        try:
            print('"Needs Update?", "Name", "IP address", "Status", "Version", "Last Heartbeat", '
                  '"VDB Version", "Operating System", "Architecture", "ID"')
            for l_agent in p_list:
                print('"{}","{}","{}","{}","{}","{}","{}","{}","{}","{}"'.format(
                    l_agent["IsAgentNeedsUpdate"], l_agent["Name"], l_agent["IpAddress"],
                    l_agent["State"], l_agent["Version"], l_agent["Heartbeat"],
                    l_agent["VdbVersion"], l_agent["OsDescription"], l_agent["ProcessArchitecture"],
                    l_agent["Id"]
                ))
        except Exception as e:
            self.__mPrinter.print("__print_agents_csv() - {0}".format(str(e)), Level.ERROR)

    def __output_agents_to_file(self, p_agents: list):
        try:
            l_agents: list = []
            l_field_names: list = ["Needs Update?", "Name", "IP address", "Status", "Version",
                                   "Last Heartbeat", "VDB Version", "Operating System", "Architecture",
                                   "ID"]

            for l_agent in p_agents:
                l_agents.append([
                    l_agent["IsAgentNeedsUpdate"], l_agent["Name"], l_agent["IpAddress"],
                    l_agent["State"], l_agent["Version"], l_agent["Heartbeat"],
                    l_agent["VdbVersion"], l_agent["OsDescription"], l_agent["ProcessArchitecture"],
                    l_agent["Id"]
                ])

            self.__mPrinter.print("Opening file {} for writing".format(Parser.output_filename), Level.INFO)
            with open(Parser.output_filename, FileMode.WRITE_CREATE.value) as l_file:
                l_csv_writer = csv.writer(l_file)
                l_csv_writer.writerow(l_field_names)
                l_csv_writer.writerows(l_agents)
            self.__mPrinter.print("Wrote {} agents to file {}".format(len(p_agents), Parser.output_filename), Level.INFO)

        except Exception as e:
            self.__mPrinter.print("__output_agents_to_file() - {0}".format(str(e)), Level.ERROR)

    def __get_agents(self) -> list:
        try:
            self.__mPrinter.print("Fetching agent information", Level.INFO)

            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cAGENTS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            l_http_response = self.__connect_to_api(p_url=l_base_url)

            self.__mPrinter.print("Fetched agent information", Level.SUCCESS)
            self.__mPrinter.print("Parsing agent information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_sites: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} agent".format(l_number_sites), Level.INFO)

            l_list: list = l_json["List"]

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                l_list.extend(self.__get_next_page(l_base_url, l_json))

            self.__mPrinter.print("Fetched agent information", Level.INFO)

            return l_list

        except Exception as e:
            self.__mPrinter.print("__get_agents() - {0}".format(str(e)), Level.ERROR)

    def get_agents(self) -> None:
        try:
            l_list = self.__get_agents()

            if self.__m_output_format == OutputFormat.JSON.value:
                for l_dict in l_list:
                    print(l_dict)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_agents_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_agents() - {0}".format(str(e)), Level.ERROR)

    def __create_breadcrumb(self, p_filename: str) -> None:
        try:
            Printer.print("Creating breadcrumb file {}".format(p_filename), Level.INFO)
            l_file = open(p_filename, FileMode.WRITE_CREATE.value)
            l_file.write(str(int(datetime.now().timestamp())))
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
                    return l_time
                else:
                    raise ValueError("File {} is empty".format(p_filename))
        except FileNotFoundError as e:
            self.__mPrinter.print("__read_breadcrumb() - File not found {0}".format(str(e)), Level.INFO)
            raise FileNotFoundError(e)
        except ValueError as e:
            self.__mPrinter.print("__read_breadcrumb() - {0}".format(str(e)), Level.ERROR)
            raise ValueError(e)
        except Exception as e:
            self.__mPrinter.print("__read_breadcrumb() - {0}".format(str(e)), Level.ERROR)
            raise Exception(e)

    def already_reported_today(self) -> bool:
        try:
            l_todays_time: datetime = datetime.today()
            l_breadcrumb_time: datetime = self.__read_breadcrumb(Parser.agent_heartbeat_breadcrumb_filename)
            l_target_time = l_todays_time - l_breadcrumb_time
            return (l_target_time.seconds // 60 < Parser.agent_heartbeat_notification_interval_minutes)
        except ValueError as e:
            return False
        except FileNotFoundError as e:
            return False
        except Exception as e:
            self.__mPrinter.print("already_reported_today() - {0}".format(str(e)), Level.ERROR)

    def report_agents_missing_heartbeat(self) -> int:
        try:
            l_unresponsive_agents: list = []

            if self.already_reported_today():
                Printer.print("Already reported in today. Exiting.", Level.INFO)
                return ExitCodes.ALREADY_REPORTED_TODAY.value

            l_list = self.__get_agents()

            l_now: datetime = datetime.now(timezone.utc)
            for l_dict in l_list:
                l_heartbeat_time: datetime = parser.parse(l_dict["Heartbeat"])
                l_diff = (l_now - l_heartbeat_time)
                if l_diff.seconds > Parser.agent_heartbeat_too_long_seconds:
                    l_unresponsive_agents.append(l_dict)

            if l_unresponsive_agents:
                Printer.print("{} unresponsive agents found".format(len(l_unresponsive_agents)), Level.INFO)

                if self.already_reported_today():
                    Printer.print("Already reported in today. Exiting.", Level.INFO)
                    return ExitCodes.ALREADY_REPORTED_TODAY.value

                self.__output_agents_to_file(l_unresponsive_agents)
                self.__create_breadcrumb(Parser.agent_heartbeat_breadcrumb_filename)

                return ExitCodes.EXIT_NORMAL.value
            else:
                Printer.print("No unresponsive agents found", Level.SUCCESS)
                return ExitCodes.NOTHING_TO_REPORT.value

        except Exception as e:
            self.__mPrinter.print("report_agents_missing_heartbeat() - {0}".format(str(e)), Level.ERROR)

    def __print_team_members_csv(self, p_json):
        try:
            l_list: list = p_json["List"]
            for l_user in l_list:
                l_groups: str = ",".join(l_user["SelectedGroups"])
                print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
                    l_user["Name"], l_user["Email"], l_user["UserState"],
                    l_user["CanManageApplication"], l_user["CanManageIssues"], l_user["CanManageIssuesAsRestricted"],
                    l_user["CanManageTeam"], l_user["CanManageWebsites"], l_user["CanStartScan"],
                    l_user["CanViewScanReports"], l_user["IsApiAccessEnabled"],
                    l_user["IsTwoFactorAuthenticationEnabled"],
                    l_groups
                ))
        except Exception as e:
            self.__mPrinter.print("__print_team_members_csv() - {0}".format(str(e)), Level.ERROR)

    def get_team_members(self) -> None:
        try:
            self.__mPrinter.print("Fetching team member information", Level.INFO)

            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cTEAM_MEMBER_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched team member information", Level.SUCCESS)
            self.__mPrinter.print("Parsing team member information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_agents: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} team members".format(l_number_agents), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                self.__print_json(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name, Email, Enabled?, Manage Apps?, Manage Issues?, Manage Issues (Restricted)?, "
                      "Manage Team?, Manage Websites?, Start Scan?, View Reports?, API Access?, 2FA?, "
                      "Groups")
                self.__print_team_members_csv(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__print_next_page(l_base_url, l_json, self.__print_team_members_csv)

        except Exception as e:
            self.__mPrinter.print("get_team_members() - {0}".format(str(e)), Level.ERROR)

    def __print_website_groups_csv(self, p_json):
        try:
            l_list: list = p_json["List"]
            for l_group in l_list:
                print("{},{}".format(
                    l_group["Name"], l_group["TotalWebsites"]
                ))
        except Exception as e:
            self.__mPrinter.print("__print_website_groups_csv() - {0}".format(str(e)), Level.ERROR)

    def get_website_groups(self) -> None:
        try:
            self.__mPrinter.print("Fetching website groups information", Level.INFO)

            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cWEBSITE_GROUPS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            l_http_response = self.__connect_to_api(p_url=l_base_url)

            self.__mPrinter.print("Fetched website groups information", Level.SUCCESS)
            self.__mPrinter.print("Parsing website groups information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_groups: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} website groups".format(l_number_groups), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                self.__print_json(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name, Number Websites")
                self.__print_website_groups_csv(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__print_next_page(l_base_url, l_json, self.__print_website_groups_csv)

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

    def get_discovered_services(self) -> None:
        try:
            self.__mPrinter.print("Fetching discovered services information", Level.INFO)
            self.output_format = OutputFormat.JSON.value

            l_base_url = "{0}?page={1}&pageSize={2}".format(self.__cDISCOVERED_SERVICES_LIST_URL, Parser.page_number, Parser.page_size)
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched discovered services information", Level.SUCCESS)
            self.__mPrinter.print("Parsing discovered services information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_agents: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} discovered services".format(l_number_agents), Level.INFO)

            self.__print_json(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__print_next_page(l_base_url, l_json, None)

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

    def __map_business_unit(self, p_url: str) -> str:

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
            l_business_unit = 'Business Unit: UPS Capital / ParcelPro'
        elif "parcelpro" in p_url:
            l_business_unit = 'Business Unit: UPS Capital / ParcelPro'
        elif "upsfreight" in p_url:
            l_business_unit = 'Business Unit: UPS Freight / Overnite Business'
        elif "overnite" in p_url:
            l_business_unit = 'Business Unit: UPS Freight / Overnite Business'
        elif "cemelog" in p_url:
            l_business_unit = 'Business Unit: UPS Healthcare Hungary'
        elif "upsstore" in p_url:
            l_business_unit = 'Business Unit: UPS Store'
        elif "ups.com.tr" in p_url:
            l_business_unit = 'Business Unit: Unsped Packet Servisi'
        else:
            l_business_unit = 'Business Unit: United Parcel Service'

        return l_business_unit

    def __build_website_json(self, p_agent_mode: str, p_url: str, p_groups: str, p_name: str) -> str:
        l_groups_string: str = self.__parse_website_groups(p_groups, p_url)

        l_json_string = '{"AgentMode": "' + p_agent_mode + '","RootUrl": "' + p_url + '"'

        if l_groups_string:
            l_json_string += ',"Groups": [' + l_groups_string + ']'

        l_json_string += ',"LicenseType":"Subscription", "Name": "' + p_name + '"}'

        return l_json_string

    def __parse_website_url(self, p_url: str) -> str:
        l_url: str = ""
        l_url = p_url.lower()
        if not self.__url_is_valid(l_url):
            raise ValueError('__parse_url(): URL is not valid: {}'.format(l_url))
        if not self.__url_is_secure(l_url):
            raise ValueError('__parse_url(): URL is not secure. Protocol must be HTTPS: {}'.format(l_url))
        l_url = 'https://{0}/'.format(urlparse(l_url).hostname)
        return l_url

    def __parse_website_groups(self, p_groups: str, p_url: str) -> str:
        l_groups: list = p_groups.split("|")
        l_groups_string: str = ', '.join('"{0}"'.format(g) for g in l_groups)
        l_business_unit: str = self.__map_business_unit(p_url)

        # Add the business unit group based on the URL
        if l_groups_string:
            l_groups_string = '{0}, "{1}"'.format(l_groups_string, l_business_unit)
        else:
            l_groups_string = '"{0}"'.format(l_business_unit)

        return l_groups_string

    def __parse_website_name(self, p_name: str) -> str:
        l_name: str = p_name
        if not l_name:
            raise ValueError('Name is blank')
        return l_name

    def __upload_websites(self, p_websites: list) -> None:
        # Documentation: https://www.netsparkercloud.com/docs/index#/
        # PRECONDITION: The website is in at least one website group
        try:
            l_name: str = ""
            l_url: str = ""
            l_groups: str = ""

            l_output_file = open("{}{}{}{}".format(Parser.input_filename, ".failed.", time.strftime("%Y_%m_%d_%H_%M"), ".csv"), FileMode.WRITE_CREATE.value)
            l_csv_writer = csv.writer(l_output_file)

            for l_website in p_websites:
                try:
                    l_name = self.__parse_website_name(l_website[WebsiteUploadFileFields.NAME.value])
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

                l_name: str = ""
                l_sites: list = []
                for l_row in l_csv_reader:
                    if l_row:
                        l_name = l_row[WebsiteUploadFileFields.NAME.value]
                        l_sites.append((l_name,
                                           l_row[WebsiteUploadFileFields.URL.value],
                                           l_row[WebsiteUploadFileFields.GROUPS.value]))
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

    def __print_vulnerability_templates_csv(self, p_json):
        try:
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
                print('"{}",{},{}'.format(
                    l_template["Description"], l_cvssv3, l_template["Severity"]
                ))
        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_templates_csv() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_templates(self) -> None:
        try:
            self.__mPrinter.print("Fetching vulnerability templates", Level.INFO)

            l_base_url = "{0}?reportPolicyId={1}".format(
                self.__cVULNERABILITY_TEMPLATES_LIST_URL,
                Parser.report_policy_id
            )
            l_http_response = self.__connect_to_api(p_url=l_base_url)

            self.__mPrinter.print("Fetched vulnerability templates", Level.SUCCESS)
            self.__mPrinter.print("Parsing vulnerability templates", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_templates: int = len(l_json)
            self.__mPrinter.print("Found {} vulnerability templates".format(l_number_templates), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name, CVSSv3, Severity")
                self.__print_vulnerability_templates_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_templates() - {0}".format(str(e)), Level.ERROR)

    def __print_vulnerability_template_csv(self, p_json):
        try:
            l_dict = p_json[0]
            l_cvssv3: str = "0.0"
            try:
                l_cvssv3 = l_dict["Cvss31Vector"]["Base"]["Score"]["Value"]
                if not l_cvssv3:
                    raise ValueError()
            except:
                try:
                    l_cvssv3 = l_dict["CvssVector"]["Base"]["Score"]["Value"]
                except:
                    pass

            print('"{}",{},{},"{}"'.format(
                l_dict["Description"], l_cvssv3, l_dict["Severity"], l_dict["Summary"]
            ))

        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_templates_csv() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_template(self) -> None:
        try:
            self.__mPrinter.print("Fetching vulnerability template", Level.INFO)

            l_base_url = "{0}?type={1}&reportPolicyId={2}".format(
                self.__cVULNERABILITY_TEMPLATE_URL,
                Parser.vulnerability_type, Parser.report_policy_id
            )
            l_http_response = self.__connect_to_api(p_url=l_base_url)

            self.__mPrinter.print("Fetched vulnerability template", Level.SUCCESS)
            self.__mPrinter.print("Parsing vulnerability template", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name, CVSSv3, Severity, Description")
                self.__print_vulnerability_template_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_template() - {0}".format(str(e)), Level.ERROR)

    def __print_vulnerability_types_csv(self, p_json):
        try:
            for l_type in p_json:
                print(l_type)
        except Exception as e:
            self.__mPrinter.print("__print_vulnerability_types_csv() - {0}".format(str(e)), Level.ERROR)

    def get_vulnerability_types(self) -> None:
        try:
            self.__mPrinter.print("Fetching vulnerability types", Level.INFO)

            l_http_response = self.__connect_to_api(p_url=self.__cVULNERABILITY_TEMPLATE_TYPES_URL)

            self.__mPrinter.print("Fetched vulnerability types", Level.SUCCESS)
            self.__mPrinter.print("Parsing vulnerability types", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_types: int = len(l_json)
            self.__mPrinter.print("Found {} vulnerability types".format(l_number_types), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name")
                self.__print_vulnerability_types_csv(l_json)

        except Exception as e:
            self.__mPrinter.print("get_vulnerability_types() - {0}".format(str(e)), Level.ERROR)

    def __print_websites_csv(self, p_list):
        try:
            print("Name, URL, Technical Contact, Verified?, Agent, Groups")
            for l_site in p_list:
                l_groups: list = l_site["Groups"]
                l_groups_string: str = ""
                for l_group in l_groups:
                    l_groups_string = "{},{}".format(l_groups_string, l_group["Name"])
                print("{},{},{},{},{},{}".format(
                    l_site["Name"], l_site["RootUrl"], l_site["TechnicalContactEmail"],
                    l_site["IsVerified"], l_site["AgentMode"], l_groups_string[1:]
                ))
        except Exception as e:
            self.__mPrinter.print("__print_websites_csv() - {0}".format(str(e)), Level.ERROR)

    def get_websites(self) -> None:
        try:
            l_list: list = self.__get_websites()

            if self.__m_output_format == OutputFormat.JSON.value:
                for l_dict in l_list:
                    print(l_dict)
            elif self.__m_output_format == OutputFormat.CSV.value:
                self.__print_websites_csv(l_list)

        except Exception as e:
            self.__mPrinter.print("get_websites() - {0}".format(str(e)), Level.ERROR)

    def __web_server_is_up(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["1", "2", "3", "4"]

    def __web_server_is_redirecting(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["3"]

    def __web_server_is_down(self, p_status_code: int) -> bool:
        return str(p_status_code)[0] in ["5"]

    def __cannot_resolve_URL(self, p_status_code: int) -> bool:
        return p_status_code == 502

    def __is_authentication_site(self, l_domain: str) -> bool:
        return l_domain in Parser.authentication_sites

    def __get_websites(self) -> list:
        try:
            self.__mPrinter.print("Fetching website information", Level.INFO)

            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cWEBSITES_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            l_http_response = self.__connect_to_api(p_url=l_base_url)

            self.__mPrinter.print("Fetched website information", Level.SUCCESS)
            self.__mPrinter.print("Parsing website information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_sites: int = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} websites".format(l_number_sites), Level.INFO)

            l_list: list = l_json["List"]

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                l_list.extend(self.__get_next_page(l_base_url, l_json))

            self.__mPrinter.print("Fetched website information", Level.INFO)

            return l_list

        except Exception as e:
            self.__mPrinter.print("__get_websites() - {0}".format(str(e)), Level.ERROR)

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

            except requests.exceptions.RequestException as e:
                l_site_is_up = False
                l_status_code = 503
                l_reason = str(e)

        if self.__web_server_is_redirecting(l_status_code):
            l_current_domain = urlparse(l_http_response.url).hostname
            l_redirect_domain = urlparse(l_http_response.next.url).hostname
            self.__mPrinter.print("Server redirected from {} to {}".format(l_current_domain, l_redirect_domain), Level.INFO)
            if l_current_domain == l_redirect_domain:
                l_site_is_up = True
                l_reason = "Server is redirecting to the same domain"
            elif self.__is_authentication_site(l_redirect_domain):
                l_site_is_up = True
                l_reason = "Server is redirecting to an authentication domain {}".format(l_redirect_domain)
            else:
                l_site_is_up = False
                l_reason = "Server is redirecting to a different domain {}".format(l_redirect_domain)

        return l_site_is_up, l_status_code, l_reason

    def __ping_sites(self, p_list: list) -> None:
        try:
            l_site_is_up: bool = False
            l_status_code: int = 0
            l_reason: str = ""

            self.__mPrinter.print("Beginning site analysis", Level.INFO)
            print('"Name", "URL", "Status", "Status Code", "Comment"')

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
                print('"{}", "{}", "{}", "{}", "{}"'.format(
                    l_name, l_url, l_status, l_status_code, l_reason)
                )

        except Exception as e:
            self.__mPrinter.print("__ping_sites() - {0}".format(str(e)), Level.ERROR)

    def ping_sites(self) -> None:

        try:
            l_sites: list = []
            l_list: list = self.__get_websites()
            for l_record in l_list:
                l_sites.append((l_record["Name"], l_record["RootUrl"]))
            self.__ping_sites(l_sites)

        except Exception as e:
            self.__mPrinter.print("ping_sites() - {0}".format(str(e)), Level.ERROR)

    def ping_sites_in_file(self) -> None:

        try:
            l_sites: list = self.__parse_website_upload()
            self.__ping_sites(l_sites)

        except Exception as e:
            self.__mPrinter.print("ping_sites_in_file() - {0}".format(str(e)), Level.ERROR)