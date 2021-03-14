# Spider Web

### Dependecies

    python 3

### Installation

  1. Run ***./install.sh*** (Linux only) to create symlink and make spider-web.py executable
  2. Copy ***spider-web.key.sample*** to ***spider-web.key***
  3. Copy API user ID and password into ***spider-web.key*** file
  4. Copy ***config.py.sample*** to ***config.py***
  5. Edit ***config.py*** file to have desired settings  
  6. If using proxy, enter proxy settings into ***config.py***. Set ***USE_PROXY=TRUE***. If proxy performs TLS inspection, and proxy CA certificate is not available, setting ***VERIFY_HTTPS_CERTIFICATE=FALSE*** may be an effective, although insecure, workaround. If proxy is authenticated, set the proxy username and password.
  7. Show help with ***spider-web -h***
  8. Test connectivity with ***spider-web -t***

### Usage

    usage: spider-web [-h] [-V] [-v] [-d] [-o {JSON,CSV}] [-e] [-u] [-t] [-pn PAGE_NUMBER] [-ps PAGE_SIZE] [-if INPUT_FILENAME]
                      [-of OUTPUT_FILENAME] [-os OUTPUT_SEPARATOR] [-un] [-wurl WEBSITE_URL] [-wn WEBSITE_NAME] [-ga] [-gl] [-aga]
                      [-dsgds] [-dsdds] [-sgs] [-sgsbw] [-turl TARGET_URL] [-idsd INITIATED_DATE_SORT_DIRECTION] [-spgsp]
                      [-spid SCAN_PROFILE_ID] [-spn SCAN_PROFILE_NAME] [-spgsps] [-srgsr] [-sid SCAN_ID] [-tmgtms] [-tmgtm] [-tmgam]
                      [-tmgwm] [-tmgapia] [-tmgsa] [-tmgda] [-tmid TEAM_MEMBER_ID] [-tme TEAM_MEMBER_EMAIL] [-tgt] [-tgot]
                      [-tn TECHNOLOGY_NAME] [-wgwbu] [-wgwbn] [-wgwbid] [-wid WEBSITE_ID] [-wgw] [-wgwbgn] [-wgwbgid] [-wupw]
                      [-wgn WEBSITE_GROUP_NAME] [-wgid WEBSITE_GROUP_ID] [-wggwg] [-wgupwg] [-vgvtemps] [-vgvtemp] [-vgvtypes]
                      [-rpi REPORT_POLICY_ID] [-vt VULNERABILITY_TYPE] [-auxps] [-auxpsif] [-ramh] [-rda] [-ri] [-ris]

### Options

    optional arguments:
      -h, --help            show this help message and exit
      -V, --version         Print version and exit
      -v, --verbose         Enable verbose output
      -d, --debug           Show debug output
      -o {JSON,CSV}, --output-format {JSON,CSV}
                            Output format
    
    Utilities:
      -e, --examples        Show various examples and exit
      -u, --usage           Show brief usage and exit
      -t, --test            Test connectivity to API and exit
    
    Universal Endpoint Options:
      -pn PAGE_NUMBER, --page-number PAGE_NUMBER
                            The page index
      -ps PAGE_SIZE, --page-size PAGE_SIZE
                            The number of records returned per request to the API. The page size can be any value between 1 and 200
      -if INPUT_FILENAME, --input-filename INPUT_FILENAME
                            Input filename. File must be propely formatted.
      -of OUTPUT_FILENAME, --output-filename OUTPUT_FILENAME
                            Output filename. For methods that support output files, the method will output to the filename if -of, --output-filename if present.
      -os OUTPUT_SEPARATOR, --output-separator OUTPUT_SEPARATOR
                            Output separator for downloaded CSV files. Default is comma. Choices are ['Comma', 'Semicolon', 'Pipe', 'Tab']
      -un, --unattended     Unattended mode. In unattended mode, reporting functions will check for breadcrumb files and only report if the specified time has passed since the last report. The specified time is set in the config.py file.
      -wurl WEBSITE_URL, --website-url WEBSITE_URL
                            The website URL to search by
      -wn WEBSITE_NAME, --website-name WEBSITE_NAME
                            The website name to search by
    
    Account Endpoint:
      -ga, --get-account    Get current user account information and exit
      -gl, --get-license    Get system license information and exit
    
    Agents Endpoint:
      -aga, --get-agents    List agents and exit. Output fetched in pages.
    
    Discovery Endpoint:
      -dsgds, --get-discovered-services
                            List discovered services and exit. Output fetched in pages.
      -dsdds, --download-discovered-services
                            Download discovered services as CSV file and exit. Output filename is required. Specify output filename with -o, --output-format.
    
    Scans Endpoints:
      -sgs, --get-scans     List scans and exit. Output fetched in pages.
      -sgsbw, --get-scans-by-website
                            List scans by website and exit. Output fetched in pages. Requires either -wurl, --website-url or -turl, --target-url or both. Default sort is descending.
    
    Scans Endpoints Options:
      -turl TARGET_URL, --target-url TARGET_URL
                            The target URL of the scan
      -idsd INITIATED_DATE_SORT_DIRECTION, --initiated-date-sort-direction INITIATED_DATE_SORT_DIRECTION
                            The scan initiated date sort direction. Choices are ['Ascending', 'Decending']
    
    Scans Profile Endpoints:
      -spgsp, --get-scan-profile
                            List scan profiles and exit. Requires -spid, --scan-profile-id or spn, --scan-profile-name which filters results accordingly. Scan Profile ID takes precedence.
    
    Scans Profile Endpoints Options:
      -spid SCAN_PROFILE_ID, --scan-profile-id SCAN_PROFILE_ID
                            The scan profile ID
      -spn SCAN_PROFILE_NAME, --scan-profile-name SCAN_PROFILE_NAME
                            The scan profile name
    
    Scans Profiles Endpoints:
      -spgsps, --get-scan-profiles
                            List scan profiles and exit. Output fetched in pages.
    
    Scan Results Endpoints:
      -srgsr, --get-scan-results
                            Get scan results and exit. Requires -sid, --scan-id
    
    Scans Results Endpoints Options:
      -sid SCAN_ID, --scan-id SCAN_ID
                            The scan ID
    
    Team Member Endpoints:
      -tmgtms, --get-team-members
                            List users and exit. Output fetched in pages.
      -tmgtm, --get-team-member
                            List user profile and exit. Requires -tmid, --team-member-id or -tme, --team-member-email.
      -tmgam, --get-account-managers
                            List users able to manage team member accounts and exit. Output fetched in pages.
      -tmgwm, --get-website-managers
                            List users able to manage websites and exit. Output fetched in pages.
      -tmgapia, --get-api-accounts
                            List users with permissions to access the API and exit. Output fetched in pages.
      -tmgsa, --get-scan-accounts
                            List users with permissions to start scans and exit. Output fetched in pages.
      -tmgda, --get-disabled-accounts
                            List accounts that are disabled and exit. Output fetched in pages.
    
    Team Member Endpoints Options:
      -tmid TEAM_MEMBER_ID, --team-member-id TEAM_MEMBER_ID
                            The team member ID
      -tme TEAM_MEMBER_EMAIL, --team-member-email TEAM_MEMBER_EMAIL
                            The team member email address
    
    Technologies Endpoints:
      -tgt, --get-technologies
                            List technologies and exit. Optionally search by -wn, --website-name or -tn, --technology-name or both. Output fetched in pages.
      -tgot, --get-obsolete-technologies
                            List obsolete technologies and exit. Optionally search by -wn, --website-name or -tn, --technology-name or both. Output fetched in pages.
    
    Technologies Endpoints Options:
      -tn TECHNOLOGY_NAME, --technology-name TECHNOLOGY_NAME
                            The technology name to search by
    
    Website Endpoints:
      -wgwbu, --get-website-by-url
                            List website and exit. Output fetched in pages. Requires -wurl, --website-url.
      -wgwbn, --get-website-by-name
                            List website and exit. Output fetched in pages. Requires -wn, --website-name.
      -wgwbid, --get-website-by-id
                            List website and exit. Output fetched in pages. Requires -wid, --website-id.
    
    Website Endpoints Options:
      -wid WEBSITE_ID, --website-id WEBSITE_ID
                            The website ID to search by
    
    Websites Endpoints:
      -wgw, --get-websites  List websites and exit. Output fetched in pages.
      -wgwbgn, --get-websites-by-group-name
                            List websites and exit. Output fetched in pages. Requires -wgn, --website-group-name.
      -wgwbgid, --get-websites-by-group-id
                            List websites and exit. Output fetched in pages. Requires -wgid, --website-group-id.
      -wupw, --upload-websites
                            Create websites and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL, SITE_GROUPS. SITE_GROUPS must be pipe delimited. Include input file with -if, --input-filename
    
    Websites Endpoints Options:
      -wgn WEBSITE_GROUP_NAME, --website-group-name WEBSITE_GROUP_NAME
                            The website group name to search by
      -wgid WEBSITE_GROUP_ID, --website-group-id WEBSITE_GROUP_ID
                            The website group ID to search by
    
    Website Groups Endpoint:
      -wggwg, --get-website-groups
                            List website groups and exit. Output fetched in pages.
      -wgupwg, --upload-website-groups
                            Create website groups and exit. Requires properly formatted input file: CSV with fields SITE_GROUP_NAME. Include input file with -if, --input-filename
    
    Vulnerability Endpoint:
      -vgvtemps, --get-vulnerability-templates
                            List vulnerability templates and exit. Optionally accepts parameter -rpi, --report-policy-id.
      -vgvtemp, --get-vulnerability-template
                            Get the vulnerability template given vulnerability type and exit. Requires -vt, --vulnerability-type.
      -vgvtypes, --get-vulnerability-types
                            List vulnerability types and exit
    
    Vulnerability Endpoint Options:
      -rpi REPORT_POLICY_ID, --report-policy-id REPORT_POLICY_ID
                            The report policy ID
      -vt VULNERABILITY_TYPE, --vulnerability-type VULNERABILITY_TYPE
                            The vulnerability type
    
    Auxiliary Features:
      -auxps, --ping-sites  Fetch Scan Profile Target URL from NetSparker API then report status and exit
      -auxpsif, --ping-sites-in-file
                            Read URL from file then report status and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL. Include input file with -if, --input-filename
    
    Reports:
      Reports can be output to a file. Output filename is optional. Otherwise output is sent to standard out (STDOUT). Specify output filename with -o, --output-format. Report functions allows unattended mode. In unattended mode, functions will only produce output if the configured amount of time has passed the time contained in the breadcrumb file. Configure the breadcrumb filename and the amount of time in config.py.
    
      -ramh, --report-agents-missing-heartbeat
                            Report agents that have not checked in recently and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are checking in.
      -rda, --report-disabled-agents
                            Report disabled agents and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are enabled.
      -ri, --report-issues  Report issues and exit. Report summary with -rs, --report-summary
    
    Reports Endpoint Options:
      -ris, --report-issues-summary
                            Report a summary of the issues

### Examples

#### Get Help
    spider-web -h
    spider-web --help
    
    spider-web -u
    spider-web --usage
    
    spider-web -e
    spider-web --examples

#### Test Connectivity
    spider-web -t
    spider-web --test

#### Get Account Information
    spider-web -ga
    spider-web --get-account

    spider-web -ga -o JSON
    spider-web --get-account --output-format JSON

    spider-web -ga -of account.txt
    spider-web --get-account --output-file account.txt

#### Get License Information
    spider-web -gl
    spider-web --get-license

    spider-web -gl -o JSON
    spider-web --get-license --output-format JSON

    spider-web -gl -of license.txt
    spider-web --get-license --output-file license.txt

#### Get Agent Information
    spider-web -aga -pn 1 -ps 200
    spider-web --get-agents --page-number 1 --page-size 200

    spider-web -aga -pn 1 -ps 200 -of agents.txt
    spider-web --get-agents --page-number 1 --page-size 200 --output-file agents.txt

#### Get Discovered Services Information
    spider-web -dgds -pn 1 -ps 200
    spider-web --get-discovered-services --page-number 1 --page-size 200

    spider-web -ddds -of netsparker.csv -os Comma
    spider-web --download-discovered-services --output-filename netsparker.csv --output-separator Comma

#### Get Scans
    spider-web -sgs -pn 1 -ps 200
    spider-web --get-scans --page-number 1 --page-size 200

#### Get Scans by Website
    spider-web -sgsbw -pn 1 -ps 200 -wurl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --website-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

    spider-web -sgsbw -pn 1 -ps 200 -turl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --target-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

    spider-web -sgsbw -pn 1 -ps 200 -wurl "https://bc-sec2.acme.org/"-turl "https://bc-sec2.acme.org/" -idsd Descending
    spider-web --get-scans-by-website --page-number 1 --page-size 200 --website-url "https://bc-sec2.acme.org/" --target-url "https://bc-sec2.acme.org/" --initiated-date-sort-direction Descending

#### Get Scan Profiles
    spider-web -spgsp -spid a43fe0f6-cbb0-49de-4b8c-ac93026a2403 -pn 1 -ps 200
    spider-web --get-scan-profile --scan-profile-id a43fe0f6-cbb0-49de-4b8c-ac93026a2403 --page-number 1 --page-size 200

    spider-web -spgsp -spn 'Development: TEC Workspaceone Arm-Diad' -pn 1 -ps 200
    spider-web --get-scan-profile --scan-profile-name 'Development: TEC Workspaceone Arm-Diad' --page-number 1 --page-size 200

#### Get Scan Profiles
    spider-web -spgsps -pn 1 -ps 200
    spider-web --get-scan-profiles --page-number 1 --page-size 200

#### Get Team Member Information
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

#### Get Technologies Information
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

#### Get Website Information
    spider-web -wgwbu -pn 1 -ps 200 -wurl "https://www.acme.com"
    spider-web --get-website-by-url --page-number 1 --page-size 200 --website-url "https://www.acme.com"
    
    spider-web -wgwbn -pn 1 -ps 200 -wn www.acme.com
    spider-web --get-website-by-name --page-number 1 --page-size 200 --website-name www.acme.com
    
    spider-web -wgwbid -pn 1 -ps 200 -wid 51e8e4db-5705-460a-613e-ac79036dd4ed
    spider-web --get-website-by-id --page-number 1 --page-size 200 --website-id 51e8e4db-5705-460a-613e-ac79036dd4ed
        
#### Get Websites Information
    spider-web -wgw -pn 1 -ps 200
    spider-web --get-websites --page-number 1 --page-size 200

    spider-web -wgw -pn 1 -ps 200 -of websites.csv
    spider-web --get-websites --page-number 1 --page-size 200 --output-file websites.csv
 
#### Get Websites by Group

    spider-web -wgwbgn -pn 1 -ps 200 -wgn "On Balanced Score Card (BSC)"
    spider-web --get-websites-by-group-name --page-number 1 --page-size 200 --website-group-name "On Balanced Score Card (BSC)"

    spider-web -wgwbgn -pn 1 -ps 200 -of websites.csv -wgn "On Balanced Score Card (BSC)"
    spider-web --get-websites-by-group-name --page-number 1 --page-size 200 --website-group-name "On Balanced Score Card (BSC)" --output-file websites.csv

    spider-web -wgwbgid -pn 1 -ps 200 -wgid "b9d6581c-9ebe-4e56-3313-ac4e038c2393"
    spider-web --get-websites-by-group-id --page-number 1 --page-size 200 --website-group-id "b9d6581c-9ebe-4e56-3313-ac4e038c2393"

    spider-web -wgwbgid -pn 1 -ps 200 -of websites.csv -wgid "b9d6581c-9ebe-4e56-3313-ac4e038c2393"
    spider-web --get-websites-by-group-id --page-number 1 --page-size 200 --website-group-id "b9d6581c-9ebe-4e56-3313-ac4e038c2393" --output-file websites.csv

#### Upload Website Information
    spider-web -wupw -if groups.csv
    spider-web --upload-websites --input-file websites.csv
    
#### Get Website Groups Information
    spider-web -wggwg -pn 1 -ps 200
    spider-web --get-website-groups --page-number 1 --page-size 200

    spider-web -wggwg -pn 1 -ps 200 -of website-groups.csv
    spider-web --get-website-groups --page-number 1 --page-size 200 --output-file website-groups.csv

#### Upload Website Groups Information
    spider-web -wgupwg -if groups.csv
    spider-web --upload-website-groups --input-file groups.csv

#### Get Vulnerability Templates Information
    spider-web -vgvtemps -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-templates --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtemps -rpi 074018e9-02d3-4e47-a937-6f7684e814da -of vulnerability-templates.txt
    spider-web --get-vulnerability-templates --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da --output-file vulnerability-templates.txt

#### Get Vulnerability Template Information
    spider-web -vgvtemp -vt Xss -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-template --vulnerability-type Xss --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtemp -vt Xss -rpi 074018e9-02d3-4e47-a937-6f7684e814da -of vulnerability-template.txt
    spider-web --get-vulnerability-template --vulnerability-type Xss --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da --output-file vulnerability-template.txt

#### Get Vulnerability Types Information
    spider-web -vgvtypes
    spider-web --get-vulnerability-types

    spider-web -vgvtypes -of vulnerability-types.txt
    spider-web --get-vulnerability-types --output-file vulnerability-types.txt

#### Auxiliary Features and Reports
    spider-web -auxps
    spider-web --ping-sites
    
    spider-web -auxpsif --input-file websites.csv
    spider-web --ping-sites-in-file --input-file websites.csv

#### Reports: Agents Missing Heartbeat
    spider-web -ramh
    spider-web --report-agents-missing-heartbeat

    spider-web -ramh -o JSON
    spider-web --report-agents-missing-heartbeat --output-format JSON

    spider-web -ramh --of unresponsive-agents.csv
    spider-web --report-agents-missing-heartbeat --output-filename unresponsive-agents.csv

    spider-web -ramh --of unresponsive-agents.csv --un
    spider-web --report-agents-missing-heartbeat --output-filename unresponsive-agents.csv --unattended

#### Reports: Disabled Agents
    spider-web -rda
    spider-web --report-disabled-agents

    spider-web -rda -o JSON
    spider-web --report-disabled-agents --output-format JSON
    
    spider-web -rda --of disabled-agents.csv
    spider-web --report-disabled-agents --output-filename disabled-agents.csv
    
    spider-web -rda --of disabled-agents.csv --un
    spider-web --report-disabled-agents --output-filename disabled-agents.csv --unattended

#### Reports: Issues
    spider-web -ri -ris
    spider-web --report-issues --report-issues-summary
