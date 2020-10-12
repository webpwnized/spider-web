#!/usr/bin/python3

from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat, CSVSeparatorFormat
import config as __config

from argparse import RawTextHelpFormatter
import argparse
import sys


l_version = '0.0.5'


def print_example_usage():
    print("""
    --------------------------------
    Get Help
    --------------------------------
    spider-web -h
    spider-web --help
    
    spider-web -u
    spider-web --usage
    
    spider-web -e
    spider-web --examples

    --------------------------------
    Test Connectivity
    --------------------------------
    spider-web -t
    spider-web --test

    --------------------------------
    Get Account Information
    --------------------------------
    spider-web -ga
    spider-web --get-account

    spider-web -gl
    spider-web --get-license
    
    --------------------------------
    Get Agent Information
    --------------------------------
    spider-web -aga -pn 1 -ps 200
    spider-web --get-agents --page-number 1 --page-size 200

    --------------------------------
    Get Discovered Services Information
    --------------------------------
    spider-web -dgds -pn 1 -ps 200
    spider-web --get-discovered-services --page-number 1 --page-size 200

    spider-web -ddds -of netsparker.csv -os Comma
    spider-web --download-discovered-services --output-filename netsparker.csv --output-separator Comma

    --------------------------------
    Get Team Member Information
    --------------------------------
    spider-web -tmgtm -pn 1 -ps 200
    spider-web --get-team-members --page-number 1 --page-size 200

    --------------------------------
    Get Website Groups Information
    --------------------------------
    spider-web -wggwg -pn 1 -ps 200
    spider-web --get-website-groups --page-number 1 --page-size 200
    """)

def run_main_program():
    LINES_BEFORE = 1
    LINES_AFTER = 1

    l_api: API = None

    Printer.verbose = Parser.verbose
    Printer.debug = Parser.debug
    Printer.log_filename = Parser.log_filename
    Printer.log_level = Parser.log_level
    Printer.log_max_bytes_per_file = Parser.log_max_bytes_per_file
    Printer.log_max_number_log_files = Parser.log_max_number_log_files
    Printer.log_format = Parser.log_format
    Printer.enable_logging()

    if Parser.show_usage:
        lArgParser.print_usage()
        exit(0)

    if Parser.show_examples:
        print_example_usage()
        exit(0)

    if Parser.test_connectivity or Parser.get_account or Parser.get_license or Parser.get_agents or \
            Parser.get_team_members or Parser.get_website_groups or Parser.get_discovered_services or \
            Parser.download_discovered_services:
        l_api = API(p_parser=Parser)
    else:
        lArgParser.print_usage()
        Printer.print("Required arguments not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)

    if Parser.test_connectivity:
        l_api.test_connectivity()
        exit(0)

    if Parser.get_account:
        l_api.get_account()
        exit(0)

    if Parser.get_license:
        l_api.get_license()
        exit(0)

    if Parser.get_agents:
        l_api.get_agents()
        exit(0)

    if Parser.get_team_members:
        l_api.get_team_members()
        exit(0)

    if Parser.get_website_groups:
        l_api.get_website_groups()
        exit(0)

    if Parser.get_discovered_services:
        l_api.get_discovered_services()
        exit(0)

    if Parser.download_discovered_services:
        l_api.download_discovered_services()
        exit(0)


if __name__ == '__main__':
    lArgParser = argparse.ArgumentParser(description="""
 _____       _     _             _    _      _     
/  ___|     (_)   | |           | |  | |    | |    
\ `--. _ __  _  __| | ___ _ __  | |  | | ___| |__  
 `--. \ '_ \| |/ _` |/ _ \ '__| | |/\| |/ _ \ '_ \\ 
/\__/ / |_) | | (_| |  __/ |    \  /\  /  __/ |_) |
\____/| .__/|_|\__,_|\___|_|     \/  \/ \___|_.__/ 
      | |                                          
      |_|                                          

 Automated NetSparker Analysis - Fortuna Fortis Paratus
 Version: {}
""".format(l_version), formatter_class=RawTextHelpFormatter)
    lArgParser.add_argument('-v', '--verbose',
                            help='Enable verbose output such as current progress and duration',
                            action='store_true')
    lArgParser.add_argument('-d', '--debug',
                            help='Show debug output',
                            action='store_true')
    lArgParser.add_argument('-o', '--output-format',
                            help='Output format',
                            type=OutputFormat,
                            choices=list(OutputFormat),
                            default=OutputFormat.CSV,
                            action='store'
    )

    l_utilities_group = lArgParser.add_argument_group(title="Utilities", description=None)
    l_utilities_group.add_argument('-e', '--examples',
                                  help='Show various examples and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-u', '--usage',
                                  help='Show brief usage and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-t', '--test',
                                  help='Test connectivity to API and exit',
                                  action='store_true')

    l_universal_endpoint_group = lArgParser.add_argument_group(title="Universal Endpoint Options", description=None)
    l_universal_endpoint_group.add_argument('-pn', '--page-number',
                                 help='The page index',
                                 type=int,
                                 default=1,
                                 action='store')
    l_universal_endpoint_group.add_argument('-ps', '--page-size',
                                 help='The page size can be any value between 1 and 200',
                                 type=int,
                                 default=200,
                                 action='store')

    l_account_group = lArgParser.add_argument_group(title="Account Endpoint", description=None)
    l_account_group.add_argument('-ga', '--get-account',
                                 help='Get account information and exit',
                                 action='store_true')
    l_account_group.add_argument('-gl', '--get-license',
                                  help='Get license information and exit',
                                  action='store_true')

    l_agents_group = lArgParser.add_argument_group(title="Agents Endpoint", description=None)
    l_agents_group.add_argument('-aga', '--get-agents',
                                 help='List agents and exit. Output fetched in pages.',
                                 action='store_true')

    l_discovery_group = lArgParser.add_argument_group(title="Discovery Endpoint", description=None)
    l_discovery_group.add_argument('-dsgds', '--get-discovered-services',
                                 help='List discovered services and exit. Output fetched in pages.',
                                 action='store_true')
    l_discovery_group.add_argument('-dsdds', '--download-discovered-services',
                                 help='Download discovered services and exit',
                                 action='store_true')

    l_discovery_options_group = lArgParser.add_argument_group(title="Discovery Endpoint Options", description=None)
    l_discovery_options_group.add_argument('-of', '--output-filename',
        help='Output filename. Default is netsparker.csv',
        type=str,
        action='store')
    l_discovery_options_group.add_argument('-os', '--output-separator',
        help='Output separator for downloaded CSV files. Default is comma. Choices are {}'.format([i.value for i in CSVSeparatorFormat]),
        type=str,
        action='store')

    l_team_member_group = lArgParser.add_argument_group(title="Team Member Endpoint", description=None)
    l_team_member_group.add_argument('-tmgtm', '--get-team-members',
                                 help='List users and exit Output fetched in pages.',
                                 action='store_true')

    l_website_groups_group = lArgParser.add_argument_group(title="Website Groups Endpoint", description=None)
    l_website_groups_group.add_argument('-wggwg', '--get-website-groups',
                                 help='List website groups and exit Output fetched in pages.',
                                 action='store_true')

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()