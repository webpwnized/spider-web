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
        Parser.proxy_username = p_config.PROXY_USERNAME
        Parser.proxy_password = p_config.PROXY_PASSWORD

        Parser.show_examples = p_args.examples
        Parser.show_usage = p_args.usage
        Parser.test_connectivity = p_args.test

        Parser.get_account = p_args.get_account
        Parser.get_license = p_args.get_license

        Parser.output_format = p_args.output_format.value.upper() if hasattr(p_args.output_format, 'value') else None