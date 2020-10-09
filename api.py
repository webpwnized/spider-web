from printer import Printer, Level
from argparser import Parser
from enum import Enum
from database import SQLite
from urllib import parse

import re
import json
import getpass
import requests
import os

l_script_directory = os.path.dirname(__file__)


class Override(Enum):
    FORCE_OUTPUT = True
    USE_DEFAULTS = False


class OutputFormat(Enum):
    JSON = 'JSON'
    CSV = 'CSV'

    def __str__(self):
        return self.value


class ExposureActivityStatus(Enum):
    ACTIVE = 'active'
    INACTIVE = 'inactive'

    def __str__(self):
        return self.value


class ExposureLastEventWindow(Enum):
    LAST_7_DAYS = 'LAST_7_DAYS'
    LAST_14_DAYS = 'LAST_14_DAYS'
    LAST_30_DAYS = 'LAST_30_DAYS'
    LAST_60_DAYS = 'LAST_60_DAYS'
    LAST_90_DAYS = 'LAST_90_DAYS'
    LAST_180_DAYS = 'LAST_180_DAYS'
    LAST_365_DAYS = 'LAST_365_DAYS'

    def __str__(self):
        return self.value


class ExposureSeverity(Enum):
    ROUTINE = 'ROUTINE'
    WARNING = 'WARNING'
    CRITICAL = 'CRITICAL'

    def __str__(self):
        return self.value


class ExposureEventType(Enum):
    APPEARANCE = 'appearance'
    REAPPEARANCE = 'reappearance'
    DISAPPEARANCE = 'disappearance'

    def __str__(self):
        return self.value


class IssueProgressStatus(Enum):
    NEW = 'New'
    INVESTIGATING = 'Investigating'
    INPROGRESS = 'InProgress'

    def __str__(self):
        return self.value


class IssuePriority(Enum):
    CRITICAL = 'Critical'
    HIGH = 'High'
    MEDIUM = 'Medium'
    LOW = 'Low'

    def __str__(self):
        return self.value


class IssueActivityStatus(Enum):
    ACTIVE = 'Active'
    INACTIVE = 'Inactive'

    def __str__(self):
        return self.value


class IssueSortableFields(Enum):
    CREATED = "created"
    CREATED_DESC = "-created"
    MODIFIED = "modified"
    MODIFIED_DESC = "-modified"
    ASSIGNEE_USERNAME = "assigneeUsername"
    ASSIGNEE_USERNAME_DESC = "-assigneeUsername"
    PRIORITY = "priority"
    PRIORITY_DESC = "-priority"
    PROGRESS_STATUS = "progressStatus"
    PROGRESS_STATUS_DESC = "-progressStatus"
    ACTIVITY_STATUS = "activityStatus"
    ACTIVITY_STATUS_DESC = "-activityStatus"
    HEADLINE = "headline"
    HEADLINE_DESC = "-headline"

    def __str__(self):
        return self.value

class AcceptHeader(Enum):
    JSON = 'JSON'
    CSV = 'CSV'


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

    __cBASE_URL: str = "https://expander.expanse.co/api/"
    __cAPI_VERSION_1_URL: str = "v1/"
    __cAPI_VERSION_2_URL: str = "v2/"

    __cID_TOKEN_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "IdToken/")
    __cENTITY_URL:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "Entity/")
    __cASSETS_ENTITY_URL:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_2_URL, "assets/entities")

    __cASSETS_IP_RANGE_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_2_URL, "ip-range")
    __cEXPOSURE_TYPES_URL:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_2_URL, "configurations/exposures/")
    __cEXPOSURES_IP_PORTS_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_2_URL, "exposures/ip-ports")
    __cSUMMARIES_IP_PORTS_COUNTS_URL: str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_2_URL, "summaries/ip-ports/counts")

    #Issues
    __cISSUES_ISSUE_TYPES_URL:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "issues/issueTypes")
    __cISSUES_ISSUES_COUNT:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "issues/issues/count")
    __cISSUES_ISSUES:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "issues/issues")
    __cISSUES_ISSUES_JSON:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "issues/issues")
    __cISSUES_ISSUES_CSV:  str = "{}{}{}".format(__cBASE_URL, __cAPI_VERSION_1_URL, "issues/issues/csv")

    __m_verbose: bool = False
    __m_debug: bool = False
    __m_api_key_file:str = ""
    __m_refresh_token: str = ""
    __m_access_token: str = ""
    __m_verify_https_certificate: bool = True
    __m_api_connection_timeout: int = 30
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
    def output_format(self) -> bool:
        return self.__m_output_format

    @output_format.setter  # setter method
    def output_format(self: object, p_output_format: bool):
        self.__m_output_format = p_output_format

    # ---------------------------------
    # public instance constructor
    # ---------------------------------
    def __init__(self, p_parser: Parser) -> None:
        self.__m_verbose: bool = Parser.verbose
        self.__m_debug: bool = Parser.debug
        self.__m_api_key_file = Parser.api_key_file_path
        self.__m_api_connection_timeout = Parser.api_connection_timeout
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
            l_file = "{}/{}".format(l_script_directory, self.api_key_file)
            self.__mPrinter.print("Parsing refresh token from {}".format(l_file), Level.INFO)
            with open(l_file) as l_key_file:
                l_json_data = json.load(l_key_file)
                self.__m_refresh_token = l_json_data["credentials"]["refresh-token"]
            self.__mPrinter.print("Parsed refresh token", Level.SUCCESS)
            self.__get_access_token()
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
        try:
            self.__mPrinter.print("Connecting to API", Level.INFO)

            l_headers = {
                self.__cAPI_KEY_HEADER: "JWT {}".format(self.__m_access_token),
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

    # ---------------------------------
    # public instance methods
    # ---------------------------------
    def test_connectivity(self) -> None:
        try:
            l_url = self.__cASSETS_IP_RANGE_URL
            l_http_response = self.__connect_to_api(l_url)
            if not self.verbose:
                self.__mPrinter.print("Connected to API", Level.SUCCESS, True)
        except Exception as e:
            self.__mPrinter.print("Connection test failed. Unable to connect to API. {0}".format(str(e)), Level.ERROR)

    def test_authentication(self) -> None:
        try:
            self.__get_access_token()
            self.__mPrinter.print("JWT access token: JWT {}".format(self.__m_access_token), Level.SUCCESS, True)
        except Exception as e:
            self.__mPrinter.print("Authentication test failed. {0}".format(str(e)), Level.ERROR)

    def __parse_exposure_types(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_tuple = (l_item['severity'] or 'None', l_item['categoryName'] or 'None', l_item['fullNameSingular'], l_item['exposureType'])
                if Parser.verbose:
                    l_tuple = l_tuple + (','.join(l_item['sortableFields']),)

                if Parser.exposure_severity:
                    if l_item['severity'] == Parser.exposure_severity.value:
                        l_list.append(l_tuple)
                else:
                    l_list.append(l_tuple)

            l_list.sort(key=lambda t: (t[0], t[1]))

            l_header = ("Severity", "Category", "Exposure", "Type")
            if Parser.verbose:
                l_header = l_header + ("Sortable Fields",)
            l_records = [l_header]
            l_records.extend(l_list)

            return l_records
        except Exception as e:
            self.__mPrinter.print("__parse_exposure_types() - {0}".format(str(e)), Level.ERROR)

    def list_exposure_types(self) -> None:
        try:
            self.__mPrinter.print("Fetching exposure types", Level.INFO)
            l_http_response = self.__connect_to_api(self.__cEXPOSURE_TYPES_URL)
            self.__mPrinter.print("Fetched exposure types", Level.SUCCESS)
            self.__mPrinter.print("Parsing exposure types", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                if Parser.exposure_severity:
                    l_data: list = l_json["data"]
                    for l_dict in l_data:
                        if l_dict['severity'] == Parser.exposure_severity.value:
                            print(l_dict)
                else:
                    print(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                l_data: list = l_json["data"]
                l_list: list = self.__parse_exposure_types(l_data)
                for l_tuple in l_list:
                    print(','.join('{0}'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("list_exposure_types() - {0}".format(str(e)), Level.ERROR)

    def __parse_exposures(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_tuple = (l_item['severity'] or 'None', l_item['exposureType'] or 'None', l_item['businessUnit']['name'], l_item['ip'], l_item['portNumber'], l_item['portProtocol'])
                l_list.append(l_tuple)

            l_list.sort(key=lambda t: (t[0], t[1], t[2], t[4]))
            return l_list
        except Exception as e:
            self.__mPrinter.print("__parse_exposures() - {0}".format(str(e)), Level.ERROR)

    def get_exposures(self) -> None:
        try:
            self.__mPrinter.print("Fetching exposed ports", Level.INFO)
            self.__m_accept_header = Parser.output_format

            l_base_url = "{0}?limit={1}&offset={2}&exposureType={3}&inet={4}&content={5}&activityStatus={6}&lastEventTime={7}&lastEventWindow={8}&severity={9}&eventType={10}&tag={11}&businessUnit={12}&portNumber={13}&sort={14}".format(
                self.__cEXPOSURES_IP_PORTS_URL,
                Parser.exposure_limit, Parser.exposure_offset, Parser.exposure_type, Parser.exposure_inet,
                Parser.exposure_content, Parser.exposure_activity_status, Parser.exposure_last_event_time, Parser.exposure_last_event_window,
                Parser.exposure_severity, Parser.exposure_event_type, Parser.exposure_tag, Parser.exposure_business_unit,
                Parser.exposure_port_number, Parser.exposure_sort
            )
            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched exposed ports", Level.SUCCESS)
            self.__mPrinter.print("Parsing exposed ports", Level.INFO)
            print(l_http_response.text)

        except Exception as e:
            self.__mPrinter.print("get_exposures() - {0}".format(str(e)), Level.ERROR)

    def __parse_summarized_exposures(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_count: int = l_item['count']
                if l_count:
                    l_tuple = (l_item['type'], l_count)
                    l_list.append(l_tuple)

            l_list.sort(key=lambda t: t[1], reverse=True)
            return l_list
        except Exception as e:
            self.__mPrinter.print("__parse_summarized_exposures() - {0}".format(str(e)), Level.ERROR)

    def summarize_exposed_ip_ports(self) -> None:
        try:
            self.__mPrinter.print("Collecting summary", Level.INFO)

            l_base_url = "{0}?businessUnit={1}&tag={2}&inet={3}&content={4}&activityStatus={5}&lastEventTime={6}&lastEventWindow={7}&eventType={8}&exposureType={9}&severity={10}&portNumber={11}".format(
                self.__cSUMMARIES_IP_PORTS_COUNTS_URL,
                Parser.exposure_business_unit, Parser.exposure_tag, Parser.exposure_inet, Parser.exposure_content,
                Parser.exposure_activity_status, Parser.exposure_last_event_time, Parser.exposure_last_event_window, Parser.exposure_event_type,
                Parser.exposure_type, Parser.exposure_severity, Parser.exposure_port_number
            )
            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Collected summary", Level.SUCCESS)
            self.__mPrinter.print("Parsing summary", Level.INFO)

            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_data: list = l_json["data"]
                l_list: list = self.__parse_summarized_exposures(l_data)
                for l_tuple in l_list:
                    print(','.join('{0}'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("summarize_exposed_ip_ports() - {0}".format(str(e)), Level.ERROR)

    def __parse_entities(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_tuple = (l_item['name'], l_item['id'])
                l_list.append(l_tuple)

            l_list.sort(key=lambda t: t[0], reverse=False)
            return l_list
        except Exception as e:
            self.__mPrinter.print("__parse_entities() - {0}".format(str(e)), Level.ERROR)

    def get_entities(self) -> None:
        try:
            self.__mPrinter.print("Fetching entities", Level.INFO)

            l_http_response = self.__connect_to_api(self.__cENTITY_URL)
            self.__mPrinter.print("Fetched entities", Level.SUCCESS)
            self.__mPrinter.print("Parsing entities", Level.INFO)

            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_data: list = l_json["results"]
                l_list: list = self.__parse_entities(l_data)
                for l_tuple in l_list:
                    print(','.join('{0}'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("get_entities() - {0}".format(str(e)), Level.ERROR)

    def get_asset_entities(self) -> None:
        try:
            self.__mPrinter.print("Collecting assets", Level.INFO)

            l_base_url = "{0}?limit={1}".format(self.__cASSETS_ENTITY_URL, Parser.asset_limit)
            if Parser.asset_page_token:
                l_base_url = "{0}&pageToken={1}".format(l_base_url, Parser.asset_page_token)

            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Collected assets", Level.SUCCESS)
            self.__mPrinter.print("Parsing assets", Level.INFO)

            l_json = json.loads(l_http_response.text)
            l_url = l_json['pagination']['next']
            #self.get_asset_entities()

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_data: list = l_json["data"]
                l_list: list = self.__parse_summarized_exposures(l_data)
                for l_tuple in l_list:
                    print(','.join('{0}'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("get_asset_entities() - {0}".format(str(e)), Level.ERROR)

    def list_issue_types(self) -> None:
        try:
            self.__mPrinter.print("Fetching issue types", Level.INFO)
            l_http_response = self.__connect_to_api(self.__cISSUES_ISSUE_TYPES_URL)
            self.__mPrinter.print("Fetched issue types", Level.SUCCESS)
            self.__mPrinter.print("Parsing issue types", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_data: list = l_json["data"]

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)

            elif self.__m_output_format == OutputFormat.CSV.value:
                for l_dict in l_data:
                    print(",".join(l_dict.values()))

        except Exception as e:
            self.__mPrinter.print("list_issue_types() - {0}".format(str(e)), Level.ERROR)

    def get_issues_count(self) -> None:
        try:
            self.__mPrinter.print("Fetching issues count", Level.INFO)

            l_base_url = "{0}?contentSearch={1}&providerId={2}&providerName={3}&businessUnitId={4}&businessUnitName={5}&" \
                         "assigneeUsername={6}&issueTypeId={7}&issueTypeName={8}&inetSearch={9}&domainSearch={10}&" \
                         "portNumber={11}&progressStatus={12}&activityStatus={13}&priority={14}&tagId={15}&" \
                         "tagName={16}&createdAfter={17}&createdBefore={18}&modifiedAfter={19}&modifiedBefore={20}&".format(
                self.__cISSUES_ISSUES_COUNT,
                Parser.issue_content_search, Parser.issue_provider_id, Parser.issue_provider_name, Parser.issue_business_unit, Parser.issue_business_unit_name,
                Parser.issue_assignee_username, Parser.issue_type_id, Parser.issue_type_name, Parser.issue_inet_search, Parser.issue_domain_search,
                Parser.issue_port_number, Parser.issue_progress_status, Parser.issue_activity_status, Parser.issue_priority, Parser.issue_tag_id,
                Parser.issue_tag_name, Parser.issue_created_after, Parser.issue_created_before, Parser.issue_modified_after, Parser.issue_modified_before
            )

            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched issues count", Level.SUCCESS)
            self.__mPrinter.print("Parsing issues count", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                print("Overflow, Count")
                print("{0}, {1}".format(l_json["overflow"], l_json["count"]))

        except Exception as e:
            self.__mPrinter.print("get_issues_count() - {0}".format(str(e)), Level.ERROR)

    def __get_next_page(self, l_next_page: str) -> None:
        try:
            l_http_response = self.__connect_to_api(l_next_page)
            l_json = json.loads(l_http_response.text)
            print(l_json["data"])
            l_next_page = l_json["pagination"]["next"]
            if l_next_page:
                self.__get_next_page(l_next_page)

        except Exception as e:
            self.__mPrinter.print("get_next_page() - {0}".format(str(e)), Level.ERROR)

    def get_issues(self) -> None:
        l_url: str = ""
        l_filename: str = ""

        try:
            self.__m_accept_header = Parser.output_format
            self.__mPrinter.print("Fetching issues", Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                l_url = self.__cISSUES_ISSUES_JSON
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_url = self.__cISSUES_ISSUES_CSV

            l_base_url = "{0}?limit={1}&contentSearch={2}&providerId={3}&providerName={4}&" \
                         "businessUnitId={5}&businessUnitName={6}&assigneeUsername={7}&issueTypeId={8}&issueTypeName={9}&" \
                         "inetSearch={10}&domainSearch={11}&portNumber={12}&progressStatus={13}&activityStatus={14}&" \
                         "priority={15}&tagId={16}&tagName={17}&createdAfter={18}&createdBefore={19}&" \
                         "modifiedAfter={20}&modifiedBefore={21}&sort={22}".format(
                l_url,
                Parser.issue_limit, Parser.issue_content_search, Parser.issue_provider_id, Parser.issue_provider_name,
                Parser.issue_business_unit, Parser.issue_business_unit_name, Parser.issue_assignee_username, Parser.issue_type_id, Parser.issue_type_name,
                Parser.issue_inet_search, Parser.issue_domain_search, Parser.issue_port_number, Parser.issue_progress_status, Parser.issue_activity_status,
                Parser.issue_priority, Parser.issue_tag_id, Parser.issue_tag_name, Parser.issue_created_after, Parser.issue_created_before,
                Parser.issue_modified_after, Parser.issue_modified_before, Parser.issue_sort
            )

            if Parser.issue_page_token:
                l_base_url = "{0}{1}{2}".format(l_base_url, "&pageToken=", Parser.issue_page_token)

            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched issues", Level.SUCCESS)
            self.__mPrinter.print("Parsing issues", Level.INFO)

            if self.__m_output_format == OutputFormat.JSON.value:
                l_json = json.loads(l_http_response.text)
                print(l_json["data"])
                l_next_page = l_json["pagination"]["next"]
                if l_next_page:
                    self.__get_next_page(l_next_page)
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_filename = Parser.issue_csv_filename if Parser.issue_csv_filename else self.__get_filename_from_content_disposition(l_http_response)
                self.__mPrinter.print("Writing issues to file {}".format(l_filename), Level.INFO)
                open(l_filename, 'w').write(l_http_response.text)
                self.__mPrinter.print("Wrote issues to file {}".format(l_filename), Level.SUCCESS)

        except Exception as e:
            self.__mPrinter.print("get_issues() - {0}".format(str(e)), Level.ERROR)

    def __parse_issue(self, l_data: list) -> list:
        l_list: list = []
        try:
            l_header = ("Business Unit", "IP", "Port", "Protocol", "Domain", "Issue Type", "Category", "Priority", "Issue", "Text", "Issue Type ID")

            l_business_unit: str = l_data["businessUnits"][0]["name"]
            i_ip: str = l_data["ip"]
            l_port: str = l_data["portNumber"]
            l_protocol: str = l_data["portProtocol"]
            l_domain: str = l_data["domain"]
            l_issue_type: str = l_data["issueType"]["name"]
            l_category: str = l_data["category"]
            l_priority: str = l_data["priority"]
            l_headline: str = l_data["headline"]
            l_text: str = l_data["helpText"]
            l_issue_type_id: str = l_data["issueType"]["id"]

            l_tuple = (l_business_unit, i_ip, l_port, l_protocol, l_domain, l_issue_type, l_category, l_priority, l_headline, l_text, l_issue_type_id)
            l_list.append(l_tuple)

            l_records = [l_header]
            l_records.extend(l_list)

            return l_records
        except Exception as e:
            self.__mPrinter.print("__parse_issue() - {0}".format(str(e)), Level.ERROR)

    def get_issue(self) -> None:
        #Example issue
        #000e9e47-0e86-33a2-a892-bd8b8cb94187
        try:
            self.__m_accept_header = AcceptHeader.JSON.value
            self.__mPrinter.print("Fetching issue", Level.INFO)

            l_base_url = "{0}/{1}".format(
                self.__cISSUES_ISSUES,
                parse.quote(Parser.issue_id)
            )

            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched issue", Level.SUCCESS)
            self.__mPrinter.print("Parsing issue", Level.INFO)
            l_json = json.loads(l_http_response.text)

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_json)
            elif self.__m_output_format == OutputFormat.CSV.value:
                l_list: list = self.__parse_issue(l_json)
                for l_tuple in l_list:
                    print(','.join('{0}'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("get_issue() - {0}".format(str(e)), Level.ERROR)