#!/usr/bin/python3

from example_usage import ExampleUsage
from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat, CSVSeparatorFormat, SortDirection, IssueSeverity, IssueIncludeRawDetails, IssueIntegration
import config as __config

from argparse import RawTextHelpFormatter
import argparse

l_version = '1.1.15'

def print_version() -> None:
    if Parser.verbose:
        print("Version: {}".format(l_version))
    else:
        print(l_version)


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
        ExampleUsage.print_example_usage()
        exit(0)

    if Parser.version:
        print_version()
        exit(0)

    if Parser.test_connectivity or Parser.get_account or Parser.get_license or Parser.get_agents or Parser.get_agent_groups or \
        Parser.get_team_members or Parser.get_website_groups or Parser.get_discovered_services or \
        Parser.download_discovered_services or Parser.get_website_groups or Parser.upload_website_groups or \
        Parser.get_websites or Parser.upload_websites or Parser.get_vulnerability_templates or \
        Parser.get_vulnerability_template or Parser.get_vulnerability_types or Parser.ping_sites or \
        Parser.ping_sites_in_file or Parser.report_agents_missing_heartbeat or Parser.report_disabled_agents or \
        Parser.report_issues or Parser.get_scans or Parser.get_scheduled_scans or Parser.get_scans_by_website or \
        Parser.get_website_by_url or Parser.get_website_by_name or Parser.get_website_by_id or \
        Parser.get_websites_by_group_name or Parser.get_websites_by_group_id or Parser.get_technologies or \
        Parser.get_obsolete_technologies or Parser.get_scan_profiles or Parser.get_scan_profile or \
        Parser.get_account_managers or Parser.get_api_accounts or Parser.get_scan_accounts or \
        Parser.get_disabled_accounts or Parser.get_account_owners or Parser.get_team_member or \
        Parser.get_scan_results or Parser.upload_team_members or Parser.create_team_member or \
        Parser.get_roles or Parser.get_permissions or Parser.get_role or Parser.delete_team_member or \
        Parser.get_unused_accounts or Parser.get_teams or Parser.get_issues or Parser.download_issues or \
        Parser.report_bsc or Parser.get_unpatched_issues or Parser.disable_team_member or \
        Parser.disable_team_members or Parser.auto_onboard:
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

    if Parser.get_agent_groups:
        l_api.get_agent_groups()
        exit(0)

    if Parser.get_issues:
        l_api.get_issues()
        exit(0)

    if Parser.get_unpatched_issues:
        l_api.get_unpatched_issues()
        exit(0)

    if Parser.download_issues:
        if not Parser.output_filename:
            lArgParser.print_usage()
            Printer.print("Required argument -of, --output-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.download_issues()
        exit(0)

    if Parser.get_roles:
        l_api.get_roles()
        exit(0)

    if Parser.get_permissions:
        l_api.get_permissions()
        exit(0)

    if Parser.get_role:
        if not Parser.role_id:
            lArgParser.print_usage()
            Printer.print("-rid, --role-id is required but not provided", Level.ERROR, Force.FORCE, LINES_BEFORE,
                          LINES_AFTER)
            exit(0)
        l_api.get_role()
        exit(0)

    if Parser.get_teams:
        l_api.get_teams()
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

    if Parser.create_team_member:
        if not (Parser.team_member_name and Parser.team_member_email and Parser.team_member_sso_email and Parser.team_member_groups):
            lArgParser.print_usage()
            Printer.print("Requires -tmn, --team-member-name, -tme, --team-member-email, -tmsso, --team-member-sso-email, and -tmg, --team-member-groups", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.create_team_member()
        exit(0)

    if Parser.delete_team_member:
        if not (Parser.team_member_id):
            lArgParser.print_usage()
            Printer.print("Requires -tmid, --team-member-id", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.delete_team_member()
        exit(0)

    if Parser.disable_team_member:
        if not (Parser.team_member_id):
            lArgParser.print_usage()
            Printer.print("Requires -tmid, --team-member-id", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.disable_team_member()
        exit(0)

    if Parser.disable_team_members:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.disable_team_members()
        exit(0)

    if Parser.upload_team_members:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.upload_team_members()
        exit(0)

    if Parser.get_account_managers:
        l_api.get_account_managers()
        exit(0)

    if Parser.get_account_owners:
        l_api.get_account_owners()
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

    if Parser.get_unused_accounts:
        l_api.get_unused_accounts()
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
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.upload_website_groups()
        exit(0)

    if Parser.get_discovered_services:
        l_api.get_discovered_services()
        exit(0)

    if Parser.download_discovered_services:
        if not Parser.output_filename:
            lArgParser.print_usage()
            Printer.print("Required argument -of, --output-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
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
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
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
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
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

    if Parser.get_scheduled_scans:
        l_api.get_scheduled_scans()
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

    if Parser.get_scan_results:
        if not Parser.scan_id:
            lArgParser.print_usage()
            Printer.print("-sid, --scan-id required", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.get_scan_results()
        exit(0)

    if Parser.report_issues:
        l_api.report_issues()
        exit(0)

    if Parser.report_bsc:
        if not Parser.input_filename and not Parser.output_filename:
            lArgParser.print_usage()
            Printer.print("Required arguments -if, --input-file and -of, --output-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)
            exit(0)
        l_api.report_bsc()
        exit(0)

    if Parser.auto_onboard:
        if not Parser.input_filename:
            lArgParser.print_usage()
            Printer.print("Required argument -if, --input-file not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)  
        l_api.auto_onboard()
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
    l_universal_endpoint_group.add_argument('-wgn', '--website-group-name',
                                 help='The website group name to search by',
                                 type=str,
                                 action='store')
    l_universal_endpoint_group.add_argument('-sd', '--sort-direction',
                                 help='The sort direction. Choices are {}'.format([i.value for i in SortDirection]),
                                 default='Descending',
                                 type=str,
                                 action='store')

    l_account_group = lArgParser.add_argument_group(title="Account Endpoint", description=None)
    l_account_group.add_argument('-ga', '--get-account',
                                 help='Get current user account information and exit',
                                 action='store_true')
    l_account_group.add_argument('-gl', '--get-license',
                                  help='Get system license information and exit',
                                  action='store_true')

    l_agent_groups_group = lArgParser.add_argument_group(title="Agent Groups Endpoint", description=None)
    l_agent_groups_group.add_argument('-aggag', '--get-agent-groups',
                                 help='List agent groups and exit. Output fetched in pages.',
                                 action='store_true')

    l_agents_group = lArgParser.add_argument_group(title="Agents Endpoint", description=None)
    l_agents_group.add_argument('-aga', '--get-agents',
                                 help='List agents and exit. Output fetched in pages.',
                                 action='store_true')

    l_auto_onboard = lArgParser.add_argument_group(title="Auto-Onboard", description=None)
    l_agents_group.add_argument('-aob', '--auto-onboard',
                                 help='Auto-onboard application, creating website and scan profile. Requires SMC bookmarklet json file. Include input file with -if, --input-filename',
                                 action='store_true')

    l_discovery_group = lArgParser.add_argument_group(title="Discovery Endpoint", description=None)
    l_discovery_group.add_argument('-dsgds', '--get-discovered-services',
                                 help='List discovered services and exit. Output fetched in pages.',
                                 action='store_true')
    l_discovery_group.add_argument('-dsdds', '--download-discovered-services',
                                 help='Download discovered services as CSV file and exit. Output filename is required. Specify output filename with -of, --output-filename.',
                                 action='store_true')

    l_discovery_group = lArgParser.add_argument_group(title="Issues Endpoint", description=None)
    l_discovery_group.add_argument('-igi', '--get-issues',
                                 help='List issues and exit. Filter by website name, website group name, or Issues Endpoints Options. Sort by Last Seen Date with -sd, --sort-direction. Default sort is descending. Output fetched in pages.',
                                 action='store_true')
    l_discovery_group.add_argument('-igui', '--get-unpatched-issues',
                                 help='List issues and exit. Filter by website name, website group name, or issue severity. Output fetched in pages.',
                                 action='store_true')
    l_discovery_group.add_argument('-idi', '--download-issues',
                                 help='Download issues as CSV file and exit. Output filename is required. Specify output filename with -of, --output-filename. Filter by website name, website group name, or Issues Endpoints Options.',
                                 action='store_true')

    l_role_options_group = lArgParser.add_argument_group(title="Issues Endpoints Options", description=None)
    l_role_options_group.add_argument('-is', '--issue-severity',
        help='The severity of the issue or vulnerability. Choices are {}'.format([i.value for i in IssueSeverity]),
        type=str,
        action='store')
    l_role_options_group.add_argument('-ilsd', '--issue-last-seen-date',
        help='The last date the issues was found by the scanner. Use the date format defined in your account. Visit /account/changesettings to view the current format.',
        type=str,
        action='store')
    l_role_options_group.add_argument('-iird', '--issue-include-raw-details',
        help='Boolean value determines whether output contains vulnerability details (Remedy, Description etc.) as HTML. Default is False. Choices are {}'.format([i.value for i in IssueIncludeRawDetails]),
        type=bool,
        action='store')
    l_role_options_group.add_argument('-ii', '--issue-integration',
        help='NetSparker does not say what this field is for. Choices are {}'.format([i.value for i in IssueIntegration]),
        type=str,
        action='store')
    l_role_options_group.add_argument('-isd', '--issue-start-date',
        help='Start date in format MM/dd/yyyy 00:00:00',
        type=str,
        action='store')
    l_role_options_group.add_argument('-ied', '--issue-end-date',
        help='End date in format MM/dd/yyyy 00:00:00',
        type=str,
        action='store')

    l_role_group = lArgParser.add_argument_group(title="Role Endpoints", description=None)
    l_role_group.add_argument('-rgr', '--get-role',
                                 help='List role and exit. Requires -rid, --role-id.',
                                 action='store_true')

    l_role_options_group = lArgParser.add_argument_group(title="Role Endpoints Options", description=None)
    l_role_options_group.add_argument('-rid', '--role-id',
                                 help='The ID of the role',
                                 type=str,
                                 action='store')

    l_roles_group = lArgParser.add_argument_group(title="Roles Endpoints", description=None)
    l_roles_group.add_argument('-rgrs', '--get-roles',
                                 help='List roles and exit. Output fetched in pages.',
                                 action='store_true')
    l_roles_group.add_argument('-rgp', '--get-permissions',
                                 help='List permissions and exit.',
                                 action='store_true')

    l_scans_group = lArgParser.add_argument_group(title="Scans Endpoints", description=None)
    l_scans_group.add_argument('-sgs', '--get-scans',
                                 help='List scans and exit. Output fetched in pages.',
                                 action='store_true')
    l_scans_group.add_argument('-sgss', '--get-scheduled-scans',
                                 help='List scheduled scans and exit. Output fetched in pages.',
                                 action='store_true')
    l_scans_group.add_argument('-sgsbw', '--get-scans-by-website',
                                 help='List scans by website and exit. Output fetched in pages. Requires either -wurl, --website-url or -turl, --target-url or both. Sort by Initiated Date with -sd, --sort-direction. . Default sort is descending.',
                                 action='store_true')

    l_scans_options_group = lArgParser.add_argument_group(title="Scans Endpoints Options", description=None)
    l_scans_options_group.add_argument('-turl', '--target-url',
                                 help='The target URL of the scan',
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

    l_scans_group = lArgParser.add_argument_group(title="Scan Results Endpoints", description=None)
    l_scans_group.add_argument('-srgsr', '--get-scan-results',
                                 help='Get scan results and exit. Requires -sid, --scan-id',
                                 action='store_true')

    l_scan_profiles_options_group = lArgParser.add_argument_group(title="Scans Results Endpoints Options", description=None)
    l_scan_profiles_options_group.add_argument('-sid', '--scan-id',
                                 help='The scan ID',
                                 type=str,
                                 action='store')

    l_teams_group = lArgParser.add_argument_group(title="Teams Endpoints", description=None)
    l_teams_group.add_argument('-tgt', '--get-teams',
                                 help='List teams and exit. Output fetched in pages.',
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
    l_team_member_group.add_argument('-tmgao', '--get-account-owners',
                                 help='List the account owners and exit. Output fetched in pages.',
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
    l_team_member_group.add_argument('-tmgua', '--get-unused-accounts',
                                 help='List accounts that are unused and exit. Accounts are considered unused if the Last Login Time is longer that the number of days configured in UNUSED_ACCOUNTS_IDLE_DAYS_PERMITTED. If the user has never logged in, the Created At date is used. Output fetched in pages.',
                                 action='store_true')
    l_team_member_group.add_argument('-tmctm', '--create-team-member',
                                 help='Create a team member and exit. Requires -tmn, --team-member-name, -tme, --team-member-email, -tmsso, --team-member-sso-email, and -tmg, --team-member-groups',
                                 action='store_true')
    l_team_member_group.add_argument('-tmuptm', '--upload-team-members',
                                 help='Create team members and exit. Requires properly formatted input file: CSV with fields TEAM_MEMBER_NAME, TEAM_MEMBER_EMAIL, TEAM_MEMBER_SSO_EMAIL, TEAM_MEMBER_GROUPS. TEAM_MEMBER_GROUPS must be pipe delimited. All the rules of CSV formatting apply such as quoting fields that contain special characters. Include input file with -if, --input-filename',
                                 action='store_true')
    l_team_member_group.add_argument('-tmdtm', '--delete-team-member',
                                 help='Delete a team member and exit. Requires -tmid, --team-member-id',
                                 action='store_true')
    l_team_member_group.add_argument('-tmdatm', '--disable-team-member',
                                 help='Disable a team member and exit. Requires -tmid, --team-member-id',
                                 action='store_true')
    l_team_member_group.add_argument('-tmdatms', '--disable-team-members',
                                 help='Disable a list of team members and exit. Requires properly formatted input file: CSV with field TEAM_MEMBER_ID. Include input file with -if, --input-filename',
                                 action='store_true')

    l_scan_profiles_options_group = lArgParser.add_argument_group(title="Team Member Endpoints Options", description=None)
    l_scan_profiles_options_group.add_argument('-tmid', '--team-member-id',
                                 help='The team member ID',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-tmn', '--team-member-name',
                                 help='The team member full name. It is best practice to quote the name.',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-tme', '--team-member-email',
                                 help='The team member email address',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-tmsso', '--team-member-sso-email',
                                 help='The single-sign on (SSO) email address the team member uses to log in when using SSO',
                                 type=str,
                                 action='store')
    l_scan_profiles_options_group.add_argument('-tmg', '--team-member-groups',
                                 help='The website groups the team member has membership within. TEAM_MEMBER_GROUPS must be pipe delimited if passing more than one. It is best practice to quote the entire string, but do not quote the individual group names.',
                                 type=str,
                                 action='store')

    l_technologies_group = lArgParser.add_argument_group(title="Technologies Endpoints", description=None)
    l_technologies_group.add_argument('-techgt', '--get-technologies',
                                 help='List technologies and exit. Optionally search by -wn, --website-name or -tn, --technology-name or both. Output fetched in pages.',
                                 action='store_true')
    l_technologies_group.add_argument('-techgot', '--get-obsolete-technologies',
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

    l_report_group = lArgParser.add_argument_group(title="Reports", description="Reports can be output to a file. Output filename is optional. Otherwise output is sent to standard out (STDOUT). Specify output filename with -of, --output-filename. Report functions allows unattended mode. In unattended mode, functions will only produce output if the configured amount of time has passed the time contained in the breadcrumb file. Configure the breadcrumb filename and the amount of time in config.py.")
    l_report_group.add_argument('-ramh', '--report-agents-missing-heartbeat',
                                 help='Report agents that have not checked in recently and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are checking in.',
                                 action='store_true')
    l_report_group.add_argument('-rda', '--report-disabled-agents',
                                 help='Report disabled agents and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are enabled.',
                                 action='store_true')
    l_report_group.add_argument('-ri', '--report-issues',
                                 help='Report issues and exit. Report issues by CVSS with -ribc, --report-issues-by-cvss. Report issues by issue with -ribi, --report-issues-by-issue',
                                 action='store_true')
    l_report_group.add_argument('-rbsc', '--report-bsc',
                                 help='Report balanced scorecard data and exit.',
                                 action='store_true')

    l_report_options_group = lArgParser.add_argument_group(title="Reports Endpoint Options", description=None)
    l_report_options_group.add_argument('-ribc', '--report-issues-by-cvss',
                                 help='Report the count of issues by CVSS category',
                                 action='store_true')
    l_report_options_group.add_argument('-ribi', '--report-issues-by-issue',
                                 help='Report the count of issues by issue',
                                 action='store_true')
    l_report_options_group.add_argument('-rbai', '--report-bsc-all-issues',
                                 help='Report all issues including status and remedy',
                                 action='store_const', const=True)
    l_report_options_group.add_argument('-rblo', '--report-bsc-local-only',
                                 help='Using existing data in db file, report balanced scorecard data',
                                 action='store_const', const=True)

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()
