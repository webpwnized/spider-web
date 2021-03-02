#!/usr/bin/python3

from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat, CSVSeparatorFormat, SortDirection
import config as __config

from argparse import RawTextHelpFormatter
import argparse


l_version = '1.0.37'

def print_version() -> None:
    if Parser.verbose:
        print("Version: {}".format(l_version))
    else:
        print(l_version)

def print_example_usage() -> None:
    print("""
    --------------------------------
    Get Help
    --------------------------------
    spider-web -V
    spider-web --version

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

    spider-web -ga -o JSON
    spider-web --get-account --output-format JSON

    spider-web -ga -of account.txt
    spider-web --get-account --output-file account.txt

    --------------------------------
    Get License Information
    --------------------------------
    spider-web -gl
    spider-web --get-license

    spider-web -gl -o JSON
    spider-web --get-license --output-format JSON

    spider-web -gl -of license.txt
    spider-web --get-license --output-file license.txt
    
    --------------------------------
    Get Agent Information
    --------------------------------
    spider-web -aga -pn 1 -ps 200
    spider-web --get-agents --page-number 1 --page-size 200

    spider-web -aga -pn 1 -ps 200 -of agents.txt
    spider-web --get-agents --page-number 1 --page-size 200 --output-file agents.txt
    
    --------------------------------
    Get Discovered Services Information
    --------------------------------
    spider-web -dgds -pn 1 -ps 200
    spider-web --get-discovered-services --page-number 1 --page-size 200

    spider-web -ddds -of netsparker.csv -os Comma
    spider-web --download-discovered-services --output-filename netsparker.csv --output-separator Comma

    --------------------------------
    Get Scans
    --------------------------------
    spider-web -sgs -pn 1 -ps 200
    spider-web --get-scans --page-number 1 --page-size 200

    --------------------------------
    Get Scans by Website
    --------------------------------
    spider-web -sgsbw -pn 1 -ps 200 -wurl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --website-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

    spider-web -sgsbw -pn 1 -ps 200 -turl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --target-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

    spider-web -sgsbw -pn 1 -ps 200 -wurl "https://bc-sec2.acme.org/"-turl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --website-url "https://bc-sec2.acme.org/" --target-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

    --------------------------------
    Get Scan Profiles
    --------------------------------
    spider-web -spgsp -spid a43fe0f6-cbb0-49de-4b8c-ac93026a2403 -pn 1 -ps 200
    spider-web --get-scan-profile --scan-profile-id a43fe0f6-cbb0-49de-4b8c-ac93026a2403 --page-number 1 --page-size 200

    spider-web -spgsp -spn 'Development: TEC Workspaceone Arm-Diad' -pn 1 -ps 200
    spider-web --get-scan-profile --scan-profile-name 'Development: TEC Workspaceone Arm-Diad' --page-number 1 --page-size 200

    --------------------------------
    Get Scan Profiles
    --------------------------------
    spider-web -spgsps -pn 1 -ps 200
    spider-web --get-scan-profiles --page-number 1 --page-size 200

    --------------------------------
    Get Team Member Information
    --------------------------------
    spider-web -tmgtms -pn 1 -ps 200
    spider-web --get-team-members --page-number 1 --page-size 200

    spider-web -tmgtms -pn 1 -ps 200 -of team-members.txt
    spider-web --get-team-members --page-number 1 --page-size 200 ---output-file team-members.txt

    spider-web -tmgtm -tmid a16df32f-dc5b-441b-4d1e-acdb049ad459
    spider-web --get-team-member --team-member-id a16df32f-dc5b-441b-4d1e-acdb049ad459
    
    spider-web -tmgtm -tme user@company.com
    spider-web --get-team-member --team-member-email user@company.com
    
    spider-web -tmgam -pn 1 -ps 200
    spider-web --get-account-managers --page-number 1 --page-size 200

    spider-web -tmgam -pn 1 -ps 200 -of account-managers.txt
    spider-web --get-account-managers --page-number 1 --page-size 200 ---output-file account-managers.txt

    spider-web -tmgwm -pn 1 -ps 200
    spider-web --get-website-managers --page-number 1 --page-size 200

    spider-web -tmgwm -pn 1 -ps 200 -of website-managers.txt
    spider-web --get-website-managers --page-number 1 --page-size 200 ---output-file website-managers.txt

    spider-web -tmgapia -pn 1 -ps 200
    spider-web --get-api-accounts --page-number 1 --page-size 200

    spider-web -tmgapia -pn 1 -ps 200 -of api-accounts.txt
    spider-web --get-api-accounts --page-number 1 --page-size 200 ---output-file api-accounts.txt

    spider-web -tmgsa -pn 1 -ps 200
    spider-web --get-scan-accounts --page-number 1 --page-size 200

    spider-web -tmgsa -pn 1 -ps 200 -of scan-accounts.txt
    spider-web --get-scan-accounts --page-number 1 --page-size 200 ---output-file scan-accounts.txt

    spider-web -tmgda -pn 1 -ps 200
    spider-web --get-disabled-accounts --page-number 1 --page-size 200

    spider-web -tmgda -pn 1 -ps 200 -of disabled-accounts.txt
    spider-web --get-disabled-accounts --page-number 1 --page-size 200 ---output-file disabled-accounts.txt

    --------------------------------
    Get Technologies
    --------------------------------
    spider-web -tgt -pn 1 -ps 200 -wn www.acme.com
    spider-web --get-technologies --page-number 1 --page-size 200 --website-name www.acme.com

    spider-web -tgt -pn 1 -ps 200 -tn jQuery
    spider-web --get-technologies --page-number 1 --page-size 200 --technology-name jQuery

    spider-web -tgt -pn 1 -ps 200 -of technologies.txt -wn www.acme.com
    spider-web --get-technologies --page-number 1 --page-size 200 --website-name www.acme.com --output-file technologies.txt

    spider-web -tgot -pn 1 -ps 200 -wn www.acme.com
    spider-web --get-obsolete-technologies --page-number 1 --page-size 200 --website-name www.acme.com

    spider-web -tgot -pn 1 -ps 200 -tn jQuery
    spider-web --get-obsolete-technologies --page-number 1 --page-size 200 --technology-name jQuery
    
    spider-web -tgot -pn 1 -ps 200 -of technologies.txt
    spider-web --get-obsolete-technologies --page-number 1 --page-size 200 --website-name www.acme.com ---output-file technologies.txt

    --------------------------------
    Get Website Information
    --------------------------------
    spider-web -wgwbu -pn 1 -ps 200 -wurl "https://www.acme.com"
    spider-web --get-website-by-url --page-number 1 --page-size 200 --website-url "https://www.acme.com"
    
    spider-web -wgwbn -pn 1 -ps 200 -wn www.acme.com
    spider-web --get-website-by-name --page-number 1 --page-size 200 --website-name www.acme.com
    
    spider-web -wgwbid -pn 1 -ps 200 -wid 51e8e4db-5705-460a-613e-ac79036dd4ed
    spider-web --get-website-by-id --page-number 1 --page-size 200 --website-id 51e8e4db-5705-460a-613e-ac79036dd4ed
        
    --------------------------------
    Get Websites Information
    --------------------------------
    spider-web -wgw -pn 1 -ps 200
    spider-web --get-websites --page-number 1 --page-size 200

    spider-web -wgw -pn 1 -ps 200 -of websites.csv
    spider-web --get-websites --page-number 1 --page-size 200 --output-file websites.csv

    --------------------------------
    Get Websites by Group
    --------------------------------

    spider-web -wgwbgn -pn 1 -ps 200 -wgn "On Balanced Score Card (BSC)"
    spider-web --get-websites-by-group-name --page-number 1 --page-size 200 --website-group-name "On Balanced Score Card (BSC)"

    spider-web -wgwbgn -pn 1 -ps 200 -of websites.csv -wgn "On Balanced Score Card (BSC)"
    spider-web --get-websites-by-group-name --page-number 1 --page-size 200 --website-group-name "On Balanced Score Card (BSC)" --output-file websites.csv

    spider-web -wgwbgid -pn 1 -ps 200 -wgid "b9d6581c-9ebe-4e56-3313-ac4e038c2393"
    spider-web --get-websites-by-group-id --page-number 1 --page-size 200 --website-group-id "b9d6581c-9ebe-4e56-3313-ac4e038c2393"

    spider-web -wgwbgid -pn 1 -ps 200 -of websites.csv -wgid "b9d6581c-9ebe-4e56-3313-ac4e038c2393"
    spider-web --get-websites-by-group-id --page-number 1 --page-size 200 --website-group-id "b9d6581c-9ebe-4e56-3313-ac4e038c2393" --output-file websites.csv
 
    --------------------------------
    Upload Website Information
    --------------------------------
    spider-web -wupw -if groups.csv
    spider-web --upload-websites --input-file websites.csv
    
    --------------------------------
    Get Website Groups Information
    --------------------------------
    spider-web -wggwg -pn 1 -ps 200
    spider-web --get-website-groups --page-number 1 --page-size 200

    spider-web -wggwg -pn 1 -ps 200 -of website-groups.csv
    spider-web --get-website-groups --page-number 1 --page-size 200 --output-file website-groups.csv
    
    --------------------------------
    Upload Website Groups Information
    --------------------------------
    spider-web -wgupwg -if groups.csv
    spider-web --upload-website-groups --input-file groups.csv
    
    ----------------------------------------------------------------
    Get Vulnerability Templates Information
    ----------------------------------------------------------------
    spider-web -vgvtemps -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-templates --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtemps -rpi 074018e9-02d3-4e47-a937-6f7684e814da -of vulnerability-templates.txt
    spider-web --get-vulnerability-templates --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da --output-file vulnerability-templates.txt

    ----------------------------------------------------------------
    Get Vulnerability Template Information
    ----------------------------------------------------------------
    
    spider-web -vgvtemp -vt Xss -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-template --vulnerability-type Xss --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtemp -vt Xss -rpi 074018e9-02d3-4e47-a937-6f7684e814da -of vulnerability-template.txt
    spider-web --get-vulnerability-template --vulnerability-type Xss --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da --output-file vulnerability-template.txt

    ----------------------------------------------------------------
    Get Vulnerability Types Information
    ----------------------------------------------------------------
    spider-web -vgvtypes
    spider-web --get-vulnerability-types

    spider-web -vgvtypes -of vulnerability-types.txt
    spider-web --get-vulnerability-types --output-file vulnerability-types.txt

    ----------------------------------------------------------------
    Auxiliary Features and Reports
    ----------------------------------------------------------------
    spider-web -auxps
    spider-web --ping-sites

    spider-web -auxpsif --input-file websites.csv
    spider-web --ping-sites-in-file --input-file websites.csv

    ----------------------------------------------------------------
    Reports: Agents Missing Heartbeat
    ----------------------------------------------------------------        
    spider-web -ramh
    spider-web --report-agents-missing-heartbeat

    spider-web -ramh -o JSON
    spider-web --report-agents-missing-heartbeat --output-format JSON
    
    spider-web -ramh --of unresponsive-agents.csv
    spider-web --report-agents-missing-heartbeat --output-filename unresponsive-agents.csv
    
    spider-web -ramh --of unresponsive-agents.csv --un
    spider-web --report-agents-missing-heartbeat --output-filename unresponsive-agents.csv --unattended

    ----------------------------------------------------------------
    Reports: Disabled Agents
    ----------------------------------------------------------------        
    spider-web -rda
    spider-web --report-disabled-agents

    spider-web -rda -o JSON
    spider-web --report-disabled-agents --output-format JSON
    
    spider-web -rda --of disabled-agents.csv
    spider-web --report-disabled-agents --output-filename disabled-agents.csv
    
    spider-web -rda --of disabled-agents.csv --un
    spider-web --report-disabled-agents --output-filename disabled-agents.csv --unattended

    ----------------------------------------------------------------
    Reports: Business Scorecard
    ----------------------------------------------------------------        
    spider-web -rbsc
    spider-web --report-business-scorecard
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

    if Parser.version:
        print_version()
        exit(0)

    if Parser.test_connectivity or Parser.get_account or Parser.get_license or Parser.get_agents or \
        Parser.get_team_members or Parser.get_website_groups or Parser.get_discovered_services or \
        Parser.download_discovered_services or Parser.get_website_groups or Parser.upload_website_groups or \
        Parser.get_websites or Parser.upload_websites or Parser.get_vulnerability_templates or \
        Parser.get_vulnerability_template or Parser.get_vulnerability_types or Parser.ping_sites or \
        Parser.ping_sites_in_file or Parser.report_agents_missing_heartbeat or Parser.report_disabled_agents or \
        Parser.report_business_scorecard or Parser.get_scans or Parser.get_scans_by_website or \
        Parser.get_website_by_url or Parser.get_website_by_name or Parser.get_website_by_id or \
        Parser.get_websites_by_group_name or Parser.get_websites_by_group_id or Parser.get_technologies or \
        Parser.get_obsolete_technologies or Parser.get_scan_profiles or Parser.get_scan_profile or \
        Parser.get_account_managers or Parser.get_api_accounts or Parser.get_scan_accounts or \
        Parser.get_disabled_accounts or Parser.get_website_managers or Parser.get_team_member:
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

    if Parser.get_team_member:
        if not Parser.team_member_id and not Parser.team_member_email:
            lArgParser.print_usage()
            Printer.print("Either -tmid, --team-member-id or -tme, --team-member-email required but not provided", Level.ERROR, Force.FORCE, LINES_BEFORE,
                          LINES_AFTER)
            exit(0)
        l_api.get_team_member()
        exit(0)

    if Parser.get_team_members:
        l_api.get_team_members()
        exit(0)

    if Parser.get_account_managers:
        l_api.get_account_managers()
        exit(0)

    if Parser.get_website_managers:
        l_api.get_website_managers()
        exit(0)

    if Parser.get_api_accounts:
        l_api.get_api_accounts()
        exit(0)

    if Parser.get_scan_accounts:
        l_api.get_scan_accounts()
        exit(0)

    if Parser.get_disabled_accounts:
        l_api.get_disabled_accounts()
        exit(0)

    if Parser.get_technologies:
        l_api.get_technologies()
        exit(0)

    if Parser.get_obsolete_technologies:
        l_api.get_obsolete_technologies()
        exit(0)

    if Parser.get_website_groups:
        l_api.get_website_groups()
        exit(0)

    if Parser.upload_website_groups:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.upload_website_groups()
        exit(0)

    if Parser.get_discovered_services:
        l_api.get_discovered_services()
        exit(0)

    if Parser.download_discovered_services:
        if not Parser.output_filename:
            lArgParser.print_usage()
            Printer.print("Required argument --output-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.download_discovered_services()
        exit(0)

    if Parser.get_website_by_url:
        if not Parser.website_url:
            lArgParser.print_usage()
            Printer.print("Required argument -wurl, --website-url not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_website_by_url()
        exit(0)

    if Parser.get_website_by_name:
        if not Parser.website_name:
            lArgParser.print_usage()
            Printer.print("Required argument -wn, --website-name not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_website_by_name()
        exit(0)

    if Parser.get_website_by_id:
        if not Parser.website_id:
            lArgParser.print_usage()
            Printer.print("Required argument -wid, --website-id not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_website_by_id()
        exit(0)

    if Parser.get_websites:
        l_api.get_websites()
        exit(0)

    if Parser.get_websites_by_group_name:
        if not Parser.website_group_name:
            lArgParser.print_usage()
            Printer.print("Required argument -wgn, --website-group-name not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_websites_by_group_name()
        exit(0)

    if Parser.get_websites_by_group_id:
        if not Parser.website_group_id:
            lArgParser.print_usage()
            Printer.print("Required argument -wgid, --website-group-id not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_websites_by_group_id()
        exit(0)

    if Parser.upload_websites:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.upload_websites()
        exit(0)

    if Parser.get_vulnerability_templates:
        l_api.get_vulnerability_templates()
        exit(0)

    if Parser.get_vulnerability_template:
        if not Parser.vulnerability_type:
            lArgParser.print_usage()
            Printer.print("Required argument -vt, --vulnerability-type not provided", Level.ERROR, Force.FORCE, LINES_BEFORE,
                          LINES_AFTER)
            exit(0)
        l_api.get_vulnerability_template()
        exit(0)

    if Parser.get_vulnerability_types:
        l_api.get_vulnerability_types()
        exit(0)

    if Parser.ping_sites:
        l_api.ping_sites()
        exit(0)

    if Parser.ping_sites_in_file:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.ping_sites_in_file()
        exit(0)

    if Parser.report_agents_missing_heartbeat:
        exit(l_api.report_agents_missing_heartbeat())

    if Parser.report_disabled_agents:
        exit(l_api.report_disabled_agents())

    if Parser.get_scans:
        l_api.get_scans()
        exit(0)

    if Parser.get_scans_by_website:
        if not Parser.website_url and not Parser.target_url:
            lArgParser.print_usage()
            Printer.print("Either -wurl, --website-url or -turl, --target-url or both required", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_scans_by_website()
        exit(0)

    if Parser.get_scan_profile:
        if not Parser.scan_profile_id and not Parser.scan_profile_name:
            lArgParser.print_usage()
            Printer.print("Either -spid, --scan-profile-id or -spn, --scan-profile-name required", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_scan_profile()
        exit(0)

    if Parser.get_scan_profiles:
        l_api.get_scan_profiles()
        exit(0)

    if Parser.report_business_scorecard:
        l_api.report_business_scorecard()
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
    lArgParser.add_argument('-V', '--version',
                            help='Print version and exit',
                            action='store_true')
    lArgParser.add_argument('-v', '--verbose',
                            help='Enable verbose output',
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
                                 help='The number of records returned per request to the API. The page size can be any value between 1 and 200',
                                 type=int,
                                 default=200,
                                 action='store')
    l_universal_endpoint_group.add_argument('-if', '--input-filename',
                                help='Input filename. File must be propely formatted.',
                                type=str,
                                action='store')
    l_universal_endpoint_group.add_argument('-of', '--output-filename',
                                help='Output filename. For methods that support output files, the method will output to the filename if -of, --output-filename if present.',
                                type=str,
                                action='store')
    l_universal_endpoint_group.add_argument('-os', '--output-separator',
                                help='Output separator for downloaded CSV files. Default is comma. Choices are {}'.format([i.value for i in CSVSeparatorFormat]),
                                default='Comma',
                                type=str,
                                action='store')
    l_universal_endpoint_group.add_argument('-un', '--unattended',
                                help='Unattended mode. In unattended mode, reporting functions will check for breadcrumb files and only report if the specified time has passed since the last report. The specified time is set in the config.py file.',
                                action='store_true')
    l_universal_endpoint_group.add_argument('-wurl', '--website-url',
                                 help='The website URL to search by',
                                 type=str,
                                 action='store')
    l_universal_endpoint_group.add_argument('-wn', '--website-name',
                                 help='The website name to search by',
                                 type=str,
                                 action='store')

    l_account_group = lArgParser.add_argument_group(title="Account Endpoint", description=None)
    l_account_group.add_argument('-ga', '--get-account',
                                 help='Get current user account information and exit',
                                 action='store_true')
    l_account_group.add_argument('-gl', '--get-license',
                                  help='Get system license information and exit',
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
                                 help='Download discovered services as CSV file and exit. Output filename is required. Specify output filename with -o, --output-format.',
                                 action='store_true')

    l_scans_group = lArgParser.add_argument_group(title="Scans Endpoints", description=None)
    l_scans_group.add_argument('-sgs', '--get-scans',
                                 help='List scans and exit. Output fetched in pages.',
                                 action='store_true')
    l_scans_group.add_argument('-sgsbw', '--get-scans-by-website',
                                 help='List scans by website and exit. Output fetched in pages. Requires either -wurl, --website-url or -turl, --target-url or both. Default sort is descending.',
                                 action='store_true')

    l_scans_options_group = lArgParser.add_argument_group(title="Scans Endpoints Options", description=None)
    l_scans_options_group.add_argument('-turl', '--target-url',
                                 help='The target URL of the scan',
                                 type=str,
                                 action='store')
    l_scans_options_group.add_argument('-idsd', '--initiated-date-sort-direction',
                                 help='The scan initiated date sort direction. Choices are {}'.format([i.value for i in SortDirection]),
                                 default='Descending',
                                 type=str,
                                 action='store')

    l_scan_profiles_group = lArgParser.add_argument_group(title="Scans Profile Endpoints", description=None)
    l_scan_profiles_group.add_argument('-spgsp', '--get-scan-profile',
                                 help='List scan profiles and exit. Requires -spid, --scan-profile-id or spn, --scan-profile-name which filters results accordingly. Scan Profile ID takes precedence.',
                                 action='store_true')

    l_scan_profiles_options_group = lArgParser.add_argument_group(title="Scans Profile Endpoints Options", description=None)
    l_scan_profiles_options_group.add_argument('-spid', '--scan-profile-id',
                                 help='The scan profile ID',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-spn', '--scan-profile-name',
                                 help='The scan profile name',
                                 type=str,
                                 action='store')

    l_scan_profiles_group = lArgParser.add_argument_group(title="Scans Profiles Endpoints", description=None)
    l_scan_profiles_group.add_argument('-spgsps', '--get-scan-profiles',
                                 help='List scan profiles and exit. Output fetched in pages.',
                                 action='store_true')

    l_team_member_group = lArgParser.add_argument_group(title="Team Member Endpoints", description=None)
    l_team_member_group.add_argument('-tmgtms', '--get-team-members',
                                 help='List users and exit. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgtm', '--get-team-member',
                                 help='List user profile and exit. Requires -tmid, --team-member-id or -tme, --team-member-email.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgam', '--get-account-managers',
                                 help='List users able to manage team member accounts and exit. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgwm', '--get-website-managers',
                                 help='List users able to manage websites and exit. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgapia', '--get-api-accounts',
                                 help='List users with permissions to access the API and exit. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgsa', '--get-scan-accounts',
                                 help='List users with permissions to start scans and exit. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmgda', '--get-disabled-accounts',
                                 help='List accounts that are disabled and exit. Output fetched in pages.',
                                 action='store_true')

    l_scan_profiles_options_group = lArgParser.add_argument_group(title="Team Member Endpoints Options", description=None)
    l_scan_profiles_options_group.add_argument('-tmid', '--team-member-id',
                                 help='The team member ID',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-tme', '--team-member-email',
                                 help='The team member email address',
                                 type=str,
                                 action='store')

    l_technologies_group = lArgParser.add_argument_group(title="Technologies Endpoints", description=None)
    l_technologies_group.add_argument('-tgt', '--get-technologies',
                                 help='List technologies and exit. Optionally search by -wn, --website-name or -tn, --technology-name or both. Output fetched in pages.',
                                 action='store_true')
    l_technologies_group.add_argument('-tgot', '--get-obsolete-technologies',
                                 help='List obsolete technologies and exit. Optionally search by -wn, --website-name or -tn, --technology-name or both. Output fetched in pages.',
                                 action='store_true')

    l_technologies_group_options_group = lArgParser.add_argument_group(title="Technologies Endpoints Options", description=None)
    l_technologies_group_options_group.add_argument('-tn', '--technology-name',
                                 help='The technology name to search by',
                                 type=str,
                                 action='store')

    l_website_group = lArgParser.add_argument_group(title="Website Endpoints", description=None)
    l_website_group.add_argument('-wgwbu', '--get-website-by-url',
                                 help='List website and exit. Output fetched in pages. Requires -wurl, --website-url.',
                                 action='store_true')
    l_website_group.add_argument('-wgwbn', '--get-website-by-name',
                                 help='List website and exit. Output fetched in pages. Requires -wn, --website-name.',
                                 action='store_true')
    l_website_group.add_argument('-wgwbid', '--get-website-by-id',
                                 help='List website and exit. Output fetched in pages. Requires -wid, --website-id.',
                                 action='store_true')

    l_website_group_options_group = lArgParser.add_argument_group(title="Website Endpoints Options", description=None)
    l_website_group_options_group.add_argument('-wid', '--website-id',
                                 help='The website ID to search by',
                                 type=str,
                                 action='store')

    l_websites_group = lArgParser.add_argument_group(title="Websites Endpoints", description=None)
    l_websites_group.add_argument('-wgw', '--get-websites',
                                 help='List websites and exit. Output fetched in pages.',
                                 action='store_true')
    l_websites_group.add_argument('-wgwbgn', '--get-websites-by-group-name',
                                 help='List websites and exit. Output fetched in pages. Requires -wgn, --website-group-name.',
                                 action='store_true')
    l_websites_group.add_argument('-wgwbgid', '--get-websites-by-group-id',
                                 help='List websites and exit. Output fetched in pages. Requires -wgid, --website-group-id.',
                                 action='store_true')
    l_websites_group.add_argument('-wupw', '--upload-websites',
                                 help='Create websites and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL, SITE_GROUPS. SITE_GROUPS must be pipe delimited. Include input file with -if, --input-filename',
                                 action='store_true')

    l_websites_group_options_group = lArgParser.add_argument_group(title="Websites Endpoints Options", description=None)
    l_websites_group_options_group.add_argument('-wgn', '--website-group-name',
                                 help='The website group name to search by',
                                 type=str,
                                 action='store')
    l_websites_group_options_group.add_argument('-wgid', '--website-group-id',
                                 help='The website group ID to search by',
                                 type=str,
                                 action='store')

    l_website_groups_group = lArgParser.add_argument_group(title="Website Groups Endpoint", description=None)
    l_website_groups_group.add_argument('-wggwg', '--get-website-groups',
                                 help='List website groups and exit. Output fetched in pages.',
                                 action='store_true')
    l_website_groups_group.add_argument('-wgupwg', '--upload-website-groups',
                                 help='Create website groups and exit. Requires properly formatted input file: CSV with fields SITE_GROUP_NAME. Include input file with -if, --input-filename',
                                 action='store_true')

    l_vulnerability_group = lArgParser.add_argument_group(title="Vulnerability Endpoint", description=None)
    l_vulnerability_group.add_argument('-vgvtemps', '--get-vulnerability-templates',
                                 help='List vulnerability templates and exit. Optionally accepts parameter -rpi, --report-policy-id.',
                                 action='store_true')
    l_vulnerability_group.add_argument('-vgvtemp', '--get-vulnerability-template',
                                 help='Get the vulnerability template given vulnerability type and exit. Requires -vt, --vulnerability-type.',
                                 action='store_true')
    l_vulnerability_group.add_argument('-vgvtypes', '--get-vulnerability-types',
                                 help='List vulnerability types and exit',
                                 action='store_true')

    l_vulnerability_options_group = lArgParser.add_argument_group(title="Vulnerability Endpoint Options", description=None)
    l_vulnerability_options_group.add_argument('-rpi', '--report-policy-id',
                                 help='The report policy ID',
                                 type=str,
                                 action='store')
    l_vulnerability_options_group.add_argument('-vt', '--vulnerability-type',
                                 help='The vulnerability type',
                                 type=str,
                                 action='store')

    l_auxiliary_group = lArgParser.add_argument_group(title="Auxiliary Features", description=None)
    l_auxiliary_group.add_argument('-auxps', '--ping-sites',
                                 help='Fetch Scan Profile Target URL from NetSparker API then report status and exit',
                                 action='store_true')
    l_auxiliary_group.add_argument('-auxpsif', '--ping-sites-in-file',
                                 help='Read URL from file then report status and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL. Include input file with -if, --input-filename',
                                 action='store_true')

    l_report_group = lArgParser.add_argument_group(title="Reports", description="Reports can be output to a file. Output filename is optional. Otherwise output is sent to standard out (STDOUT). Specify output filename with -o, --output-format. Report functions allows unattended mode. In unattended mode, functions will only produce output if the configured amount of time has passed the time contained in the breadcrumb file. Configure the breadcrumb filename and the amount of time in config.py.")
    l_report_group.add_argument('-ramh', '--report-agents-missing-heartbeat',
                                 help='Report agents that have not checked in recently and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are checking in.',
                                 action='store_true')
    l_report_group.add_argument('-rda', '--report-disabled-agents',
                                 help='Report disabled agents and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are enabled.',
                                 action='store_true')
    l_report_group.add_argument('-rbsc', '--report-business-scorecard',
                                 help='Report business scorecard (BSC) and exit.',
                                 action='store_true')

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()