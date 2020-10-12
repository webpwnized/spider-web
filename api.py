from printer import Printer, Level
from argparser import Parser
from enum import Enum
from database import SQLite
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import re
import json
import getpass
import requests
import os
import base64

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

    __cWEBSITE_GROUPS_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "websitegroups/list")

    __cDISOCOVERED_SERVICES_LIST_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/list")
    __cDISOCOVERED_SERVICES_DOWNLOAD_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "discovery/export")

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

            with open(l_file) as l_key_file:
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

    def __connect_to_api(self, p_url: str) -> requests.Response:
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

            l_http_response = self.__call_api(p_url, l_headers)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except Exception as e:
            self.__mPrinter.print("__connect_to_api() - {0}".format(str(e)), Level.ERROR)

    def __call_api(self, p_url: str, p_headers: dict):
        try:
            l_proxies: dict = {}
            if self.__m_use_proxy:
                self.__mPrinter.print("Using upstream proxy", Level.INFO)
                l_proxies = self.__get_proxies()
            if Parser.debug:
                Printer.print("URL: {}".format(p_url), Level.DEBUG)
                Printer.print("Headers: {}".format(p_headers), Level.DEBUG)
                Printer.print("Proxy: {}".format(l_proxies), Level.DEBUG)
                Printer.print("Verify certificate: {}".format(self.__m_verify_https_certificate), Level.DEBUG)
            l_http_response = requests.get(url=p_url, headers=p_headers, proxies=l_proxies, timeout=self.__m_api_connection_timeout, verify=self.__m_verify_https_certificate)
            if l_http_response.status_code != 200:
                l_status_code = str(l_http_response.status_code)
                l_detail = ""
                l_error_message =""
                if "detail" in l_http_response.text:
                    l_detail = " - {}".format(json.loads(l_http_response.text)["detail"])
                if "errorMessages" in l_http_response.text:
                    l_error_messages = json.loads(l_http_response.text)["errorMessages"][0]
                    l_error_message = " - {}:{}".format(l_error_messages["code"],l_error_messages["message"])
                l_message = "Call to API returned status {}{}{}".format(l_status_code, l_detail, l_error_message)
                raise ValueError(l_message)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except Exception as lRequestError:
            self.__mPrinter.print("Cannot connect to API: {} {}".format(type(lRequestError).__name__, lRequestError), Level.ERROR)
            exit("Fatal Cannot connect to API. Check connectivity to {}. {}".format(
                    self.__cBASE_URL,
                    'Upstream proxy is enabled in config.py. Ensure proxy settings are correct.' if self.__m_use_proxy else 'The proxy is not enabled. Should it be?'))

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

    def __get_next_page(self, p_base_url: str, p_json, p_print_csv_function) -> None:
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
                self.__get_next_page(l_base_url, l_json, p_print_csv_function)

        except Exception as e:
            self.__mPrinter.print("__get_next_page() - {0}".format(str(e)), Level.ERROR)

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

    def __print_agents_csv(self, p_json):
        try:
            l_list: list = p_json["List"]
            for l_agent in l_list:
                print("{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
                    l_agent["IsAgentNeedsUpdate"], l_agent["Name"], l_agent["IpAddress"],
                    l_agent["State"], l_agent["Version"], l_agent["Heartbeat"],
                    l_agent["AutoUpdateEnabled"], l_agent["Launched"], l_agent["VdbVersion"],
                    "{} {}".format(l_agent["OsDescription"], l_agent["OsArchitecture"]),
                    l_agent["FrameworkDescription"], l_agent["ProcessArchitecture"],
                    l_agent["HasWaitingCommand"], l_agent["Id"]
                ))
        except Exception as e:
            self.__mPrinter.print("__print_agents_csv() - {0}".format(str(e)), Level.ERROR)

    def get_agents(self) -> None:
        try:
            self.__mPrinter.print("Fetching agent information", Level.INFO)

            l_base_url = "{0}?page={1}&pageSize={2}".format(
                self.__cAGENTS_LIST_URL,
                Parser.page_number, Parser.page_size
            )
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched agent information", Level.SUCCESS)
            self.__mPrinter.print("Parsing agent information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_agents: list = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} agents".format(l_number_agents), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                self.__print_json(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                #TODO: Need agents to test with
                print("Needs Update?, Name, IP address, Status, Version, Last Heartbeat, Auto Update?, "
                      "Launched, VDB Version, Operating System, Framework, Architecture, Has Waiting Command, "
                      "ID")
                self.__print_agents_csv(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__get_next_page(l_base_url, l_json, self.__print_agents_csv)

        except Exception as e:
            self.__mPrinter.print("get_agents() - {0}".format(str(e)), Level.ERROR)

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
            l_number_agents: list = l_json["TotalItemCount"]
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
                self.__get_next_page(l_base_url, l_json, self.__print_team_members_csv)

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
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched website groups information", Level.SUCCESS)
            self.__mPrinter.print("Parsing website groups information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_agents: list = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} website groups".format(l_number_agents), Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                self.__print_json(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Name, Number Websites")
                self.__print_website_groups_csv(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__get_next_page(l_base_url, l_json, self.__print_website_groups_csv)

        except Exception as e:
            self.__mPrinter.print("get_website_groups() - {0}".format(str(e)), Level.ERROR)

    def get_discovered_services(self) -> None:
        try:
            self.__mPrinter.print("Fetching discovered services information", Level.INFO)
            self.output_format = OutputFormat.JSON.value

            l_base_url = "{0}?page={1}&pageSize={2}".format(self.__cDISOCOVERED_SERVICES_LIST_URL, Parser.page_number, Parser.page_size)
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched discovered services information", Level.SUCCESS)
            self.__mPrinter.print("Parsing discovered services information", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_number_agents: list = l_json["TotalItemCount"]
            self.__mPrinter.print("Found {} discovered services".format(l_number_agents), Level.INFO)

            self.__print_json(l_json)

            l_next_page = l_json["HasNextPage"]
            if l_next_page:
                self.__get_next_page(l_base_url, l_json, None)

        except Exception as e:
            self.__mPrinter.print("get_discovered_services() - {0}".format(str(e)), Level.ERROR)

    def download_discovered_services(self) -> None:
        try:
            self.__mPrinter.print("Fetching discovered services information", Level.INFO)

            l_base_url = "{0}?csvSeparator={1}".format(self.__cDISOCOVERED_SERVICES_DOWNLOAD_URL, Parser.output_separator)
            l_http_response = self.__connect_to_api(l_base_url)

            self.__mPrinter.print("Fetched discovered services information", Level.SUCCESS)
            self.__mPrinter.print("Writing issues to file {}".format(Parser.output_filename), Level.INFO)
            open(Parser.output_filename, 'w').write(l_http_response.text)
            self.__mPrinter.print("Wrote issues to file {}".format(Parser.output_filename), Level.SUCCESS)

        except Exception as e:
            self.__mPrinter.print("download_discovered_services() - {0}".format(str(e)), Level.ERROR)
