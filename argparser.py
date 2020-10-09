import config as Config

class Parser:

    debug: bool = False
    verbose: bool = False
    test_connectivity: bool = False
    check_quota: bool = False
    show_examples: bool = False
    list_studies: bool = False
    api_key_file_path: str = ""
    database_filename: str = ""
    enable_logging: bool = False
    log_filename: str = ""
    log_max_bytes_per_file: int = 0
    log_max_number_log_files: int = 0
    log_level: int = 0
    log_format: str = ""
    use_proxy: bool = False
    proxy_url: str = ""
    proxy_port: int = 0
    proxy_username: str = ""
    proxy_password: str = ""
    verify_https_certificate = True

    # static methods
    @staticmethod
    def parse_configuration(p_args, p_config: Config) -> None:
        Parser.verbose = p_args.verbose
        Parser.debug = (p_args.debug if p_args.debug else p_config.DEBUG)
        Parser.api_key_file_path = p_config.API_KEY_FILE_PATH
        Parser.api_connection_timeout = p_config.API_CONNECTION_TIMEOUT
        Parser.verify_https_certificate = p_config.VERIFY_HTTPS_CERTIFICATE
        Parser.database_filename = p_config.DATABASE_FILENAME
        Parser.enable_logging = p_config.LOG_ENABLE_LOGGING
        Parser.log_filename = p_config.LOG_FILENAME
        Parser.log_max_bytes_per_file = p_config.LOG_MAX_BYTES_PER_FILE
        Parser.log_max_number_log_files = p_config.LOG_MAX_NUMBER_LOG_FILES
        Parser.log_level = p_config.LOG_LEVEL
        Parser.log_format = p_config.LOG_FORMAT
        Parser.use_proxy = p_config.USE_PROXY
        Parser.proxy_url = p_config.PROXY_URL
        Parser.proxy_port = p_config.PROXY_PORT
        Parser.proxy_username = p_config.PROXY_USERNAME
        Parser.proxy_password = p_config.PROXY_PASSWORD
        Parser.show_examples = p_args.examples
        Parser.show_usage = p_args.usage
        Parser.test_connectivity = p_args.test
        Parser.authenticate = p_args.authenticate
        Parser.list_asset_entities = p_args.list_asset_entities
        Parser.asset_limit = p_args.asset_limit or ""
        Parser.asset_page_token = p_args.asset_page_token or ""
        Parser.list_business_units = p_args.list_business_units
        Parser.list_exposure_types = p_args.list_exposure_types
        Parser.list_exposures = p_args.list_exposures
        Parser.list_exposure_summaries = p_args.list_exposure_summaries
        Parser.exposure_limit = p_args.exposure_limit or ""
        Parser.exposure_offset = p_args.exposure_offset or 0
        Parser.exposure_type = p_args.exposure_type or ""
        Parser.exposure_inet = p_args.exposure_inet or ""
        Parser.exposure_content = p_args.exposure_content or ""
        Parser.exposure_activity_status = p_args.exposure_activity_status or ""
        Parser.exposure_last_event_time = p_args.exposure_last_event_time or ""
        Parser.exposure_last_event_window = p_args.exposure_last_event_window or ""
        Parser.exposure_severity = p_args.exposure_severity or ""
        Parser.exposure_event_type = p_args.exposure_event_type or ""
        Parser.exposure_tag = p_args.exposure_tag or ""
        Parser.exposure_business_unit = p_args.exposure_business_unit or ""
        Parser.exposure_port_number = p_args.exposure_port_number or ""
        Parser.exposure_sort = p_args.exposure_sort or ""

        # Issues Methods
        Parser.list_issue_types = p_args.list_issue_types
        Parser.get_issues_count = p_args.get_issues_count
        Parser.get_issues = p_args.get_issues
        Parser.get_issue = p_args.get_issue

        # Issues Methods Options
        Parser.issue_id = p_args.issue_id or ""
        Parser.issue_limit = p_args.issue_limit or ""
        Parser.issue_page_token = p_args.issue_page_token or ""
        Parser.issue_content_search = p_args.issue_content_search or ""
        Parser.issue_provider_id = p_args.issue_provider_id or ""
        Parser.issue_provider_name = p_args.issue_provider_name or ""
        Parser.issue_business_unit = p_args.issue_business_unit or ""
        Parser.issue_business_unit_name = p_args.issue_business_unit_name or ""
        Parser.issue_assignee_username = p_args.issue_assignee_username or ""
        Parser.issue_type_id = p_args.issue_type_id or ""
        Parser.issue_type_name = p_args.issue_type_name or ""
        Parser.issue_inet_search = p_args.issue_inet_search or ""
        Parser.issue_domain_search = p_args.issue_domain_search or ""
        Parser.issue_port_number = p_args.issue_port_number or ""
        Parser.issue_progress_status = p_args.issue_progress_status or ""
        Parser.issue_activity_status = p_args.issue_activity_status or ""
        Parser.issue_priority = p_args.issue_priority or ""
        Parser.issue_tag_id = p_args.issue_tag_id or ""
        Parser.issue_tag_name = p_args.issue_tag_name or ""
        Parser.issue_created_after = p_args.issue_created_after or ""
        Parser.issue_created_before = p_args.issue_created_before or ""
        Parser.issue_modified_after = p_args.issue_modified_after or ""
        Parser.issue_modified_before = p_args.issue_modified_before or ""
        Parser.issue_sort = p_args.issue_sort or ""
        Parser.issue_csv_filename = p_args.issue_csv_filename or ""

        Parser.output_format = p_args.output_format.value.upper() if hasattr(p_args.output_format, 'value') else None