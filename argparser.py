import config as Config

class Parser:

    debug: bool = False
    verbose: bool = False
    test_connectivity: bool = False
    show_examples: bool = False
    api_authentication_method: str = ""
    api_key_file_path: str = ""
    database_filename: str = ""
    enable_logging: bool = False
    log_filename: str = ""
    log_max_bytes_per_file: int = 0
    log_max_number_log_files: int = 0
    log_level: int = 0
    log_format: str = ""
    use_proxy: bool = False
    use_proxy_authentication: bool = False
    proxy_url: str = ""
    proxy_port: int = 0
    proxy_username: str = ""
    proxy_password: str = ""
    verify_https_certificate = True

    # static methods
    @staticmethod
    def parse_configuration(p_args, p_config: Config) -> None:
        Parser.verbose = p_args.verbose
        Parser.version = p_args.version
        Parser.debug = (p_args.debug if p_args.debug else p_config.DEBUG)
        Parser.api_authentication_method = p_config.API_AUTHENTICATION_METHOD
        Parser.api_credential_format = p_config.API_CREDENTIAL_FORMAT
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
        Parser.use_proxy_authentication = p_config.USE_PROXY_AUTHENTICATION
        Parser.proxy_username = p_config.PROXY_USERNAME
        Parser.proxy_password = p_config.PROXY_PASSWORD

        Parser.show_examples = p_args.examples
        Parser.show_usage = p_args.usage
        Parser.test_connectivity = p_args.test

        # Universal options
        Parser.page_number = p_args.page_number
        Parser.page_size = p_args.page_size
        Parser.input_filename = p_args.input_filename

        # Account
        Parser.get_account = p_args.get_account
        Parser.get_license = p_args.get_license

        # Agents
        Parser.get_agents = p_args.get_agents

        # Discovered Services
        Parser.get_discovered_services = p_args.get_discovered_services
        Parser.download_discovered_services = p_args.download_discovered_services
        Parser.output_filename = p_args.output_filename
        Parser.output_separator = p_args.output_separator

        #Issues
        Parser.get_issues = p_args.get_issues
        Parser.download_issues = p_args.download_issues

        # Issues options
        Parser.issue_severity = p_args.issue_severity or ""
        Parser.issue_last_seen_date = p_args.issue_last_seen_date or ""
        Parser.issue_include_raw_details = p_args.issue_include_raw_details or "False"
        Parser.issue_integration = p_args.issue_integration or ""
        Parser.issue_start_date = p_args.issue_start_date or ""
        Parser.issue_end_date = p_args.issue_end_date or ""

        # Role
        Parser.get_role = p_args.get_role
        Parser.role_id = p_args.role_id

        # Roles
        Parser.get_roles = p_args.get_roles
        Parser.get_permissions = p_args.get_permissions

        # Scans
        Parser.get_scans = p_args.get_scans
        Parser.get_scheduled_scans = p_args.get_scheduled_scans
        Parser.get_scans_by_website = p_args.get_scans_by_website
        Parser.website_url = p_args.website_url
        Parser.target_url = p_args.target_url
        Parser.sort_direction = p_args.sort_direction

        # Scan Profiles
        Parser.get_scan_profiles = p_args.get_scan_profiles
        Parser.get_scan_profile = p_args.get_scan_profile
        Parser.scan_profile_id = p_args.scan_profile_id
        Parser.scan_profile_name = p_args.scan_profile_name

        # Scan Results
        Parser.get_scan_results = p_args.get_scan_results
        Parser.scan_id = p_args.scan_id

        # Teams Members
        Parser.get_teams = p_args.get_teams

        # Team Member
        Parser.get_team_member = p_args.get_team_member

        # Team Members
        Parser.get_team_members = p_args.get_team_members
        Parser.get_account_managers = p_args.get_account_managers
        Parser.get_account_owners = p_args.get_account_owners
        Parser.get_api_accounts = p_args.get_api_accounts
        Parser.get_scan_accounts = p_args.get_scan_accounts
        Parser.get_disabled_accounts = p_args.get_disabled_accounts
        Parser.get_unused_accounts = p_args.get_unused_accounts
        Parser.create_team_member = p_args.create_team_member
        Parser.upload_team_members = p_args.upload_team_members
        Parser.delete_team_member = p_args.delete_team_member

        # Team Member Attributes
        Parser.team_member_id = p_args.team_member_id
        Parser.team_member_name = p_args.team_member_name
        Parser.team_member_email = p_args.team_member_email
        Parser.team_member_sso_email = p_args.team_member_sso_email
        Parser.team_member_groups = p_args.team_member_groups
        Parser.unused_accounts_idle_days_permitted = p_config.UNUSED_ACCOUNTS_IDLE_DAYS_PERMITTED

        # Technologies
        Parser.get_technologies = p_args.get_technologies
        Parser.get_obsolete_technologies = p_args.get_obsolete_technologies
        Parser.technology_name = p_args.technology_name

        # Website
        Parser.get_website_by_url = p_args.get_website_by_url
        Parser.get_website_by_name = p_args.get_website_by_name
        Parser.get_website_by_id = p_args.get_website_by_id

        Parser.website_url = p_args.website_url
        Parser.website_name = p_args.website_name or ""
        Parser.website_id = p_args.website_id

        if Parser.get_website_by_url:
            Parser.query = Parser.website_url
        if Parser.get_website_by_name:
            Parser.query = Parser.website_name

        # Websites
        Parser.get_websites = p_args.get_websites
        Parser.upload_websites = p_args.upload_websites
        Parser.get_websites_by_group_name = p_args.get_websites_by_group_name
        Parser.get_websites_by_group_id = p_args.get_websites_by_group_id

        Parser.website_group_name = p_args.website_group_name or ""
        Parser.website_group_id = p_args.website_group_id

        if Parser.get_websites_by_group_name:
            Parser.query = Parser.website_group_name
        if Parser.get_websites_by_group_id:
            Parser.query = Parser.website_group_id

        # Website Groups
        Parser.get_website_groups = p_args.get_website_groups
        Parser.upload_website_groups = p_args.upload_website_groups

        # Vulnerabilities
        Parser.get_vulnerability_templates = p_args.get_vulnerability_templates
        Parser.get_vulnerability_template = p_args.get_vulnerability_template
        Parser.get_vulnerability_types = p_args.get_vulnerability_types

        # Vulnerabilities Options
        Parser.report_policy_id = p_args.report_policy_id or ""
        Parser.vulnerability_type = p_args.vulnerability_type

        Parser.output_format = p_args.output_format.value.upper() if hasattr(p_args.output_format, 'value') else None

        # Auxiliary Features
        Parser.ping_sites = p_args.ping_sites
        Parser.ping_sites_in_file = p_args.ping_sites_in_file

        # Ping Sites feature configuration
        Parser.ping_sites_excluded_domains = p_config.PING_SITES_EXCLUDED_DOMAINS
        Parser.ping_sites_api_connection_timeout = p_config.PING_SITES_API_CONNECTION_TIMEOUT
        Parser.ping_sites_authentication_sites = p_config.PING_SITES_AUTHENTICATION_SITES
        Parser.ping_sites_authentication_page_keywords = p_config.PING_SITES_AUTHENTICATION_PAGE_KEYWORDS

        #Reporting Options
        Parser.unattended = p_args.unattended
        Parser.report_agents_missing_heartbeat = p_args.report_agents_missing_heartbeat
        Parser.agent_heartbeat_too_long_seconds = p_config.AGENT_HEARTBEAT_TOO_LONG_SECONDS
        Parser.agent_heartbeat_breadcrumb_filename = p_config.AGENT_HEARTBEAT_BREADCRUMB_FILENAME
        Parser.agent_heartbeat_notification_interval_minutes = p_config.AGENT_HEARTBEAT_NOTIFICATION_INTERVAL_MINUTES

        Parser.report_disabled_agents = p_args.report_disabled_agents
        Parser.disabled_agents_too_long_seconds = p_config.DISABLED_AGENTS_TOO_LONG_SECONDS
        Parser.disabled_agents_breadcrumb_filename = p_config.DISABLED_AGENTS_BREADCRUMB_FILENAME
        Parser.disabled_agents_notification_interval_minutes = p_config.DISABLED_AGENTS_NOTIFICATION_INTERVAL_MINUTES

        # Report Issues
        Parser.report_issues = p_args.report_issues
        Parser.report_issues_by_cvss = p_args.report_issues_by_cvss
        Parser.report_issues_by_issue = p_args.report_issues_by_issue
        Parser.report_issues_breadcrumb_filename = p_config.REPORT_ISSUES_BREADCRUMB_FILENAME
        Parser.report_issues_notification_interval_minutes = p_config.REPORT_ISSUES_NOTIFICATION_INTERVAL_MINUTES

        # Report BSC
        Parser.report_bsc = p_args.report_bsc
