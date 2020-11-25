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

    usage: spider-web [-h] [-v] [-d] [-o {JSON,CSV}] [-e] [-u] [-t] [-pn PAGE_NUMBER] [-ps PAGE_SIZE] [-if INPUT_FILENAME]
                      [-of OUTPUT_FILENAME] [-os OUTPUT_SEPARATOR] [-ga] [-gl] [-aga] [-dsgds] [-dsdds] [-tmgtm] [-wgw] [-wupw] [-wggwg]
                      [-wgupwg] [-vgvtemps] [-vgvtemp] [-vgvtypes] [-rpi REPORT_POLICY_ID] [-vt VULNERABILITY_TYPE]

### Options

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         Enable verbose output such as current progress and duration
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
                            Output filename. Default filename is netsparker.csv output to the current directory
      -os OUTPUT_SEPARATOR, --output-separator OUTPUT_SEPARATOR
                            Output separator for downloaded CSV files. Default is comma. Choices are ['Comma', 'Semicolon', 'Pipe', 'Tab']
    
    Account Endpoint:
      -ga, --get-account    Get current user account information and exit
      -gl, --get-license    Get system license information and exit
    
    Agents Endpoint:
      -aga, --get-agents    List agents and exit. Output fetched in pages.
    
    Discovery Endpoint:
      -dsgds, --get-discovered-services
                            List discovered services and exit. Output fetched in pages.
      -dsdds, --download-discovered-services
                            Download discovered services as CSV file and exit. Specify optional output filename with -o, --output-format
    
    Team Member Endpoint:
      -tmgtm, --get-team-members
                            List users and exit. Output fetched in pages.
    
    Website Endpoint:
      -wgw, --get-websites  List websites and exit. Output fetched in pages.
      -wupw, --upload-websites
                            Create websites and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL, SITE_GROUPS. SITE_GROUPS must be pipe delimited. Include input file with -if, --input-filename
    
    Website Groups Endpoint:
      -wggwg, --get-website-groups
                            List website groups and exit. Output fetched in pages.
      -wgupwg, --upload-website-groups
                            Create website groups and exit. Requires properly formatted input file: CSV with fields SITE_GROUP_NAME. Include input file with -if, --input-filename
    
    Vulnerability Endpoint:
      -vgvtemps, --get-vulnerability-templates
                            List vulnerability templates and exit
      -vgvtemp, --get-vulnerability-template
                            Get the vulnerability template given vulnerability type and exit. Requires -vt, --vulnerability-type
      -vgvtypes, --get-vulnerability-types
                            List vulnerability types and exit
    
    Vulnerability Endpoint Options:
      -rpi REPORT_POLICY_ID, --report-policy-id REPORT_POLICY_ID
                            The report policy ID
      -vt VULNERABILITY_TYPE, --vulnerability-type VULNERABILITY_TYPE
                            The vulnerability type
    
    Auxiliary Features:
      -auxps, --ping-sites  Fetch sites from NetSparker API then report status and exit
      -auxpsif, --ping-sites-in-file
                            Read site from file then report status and exit. Requires properly formatted input file: CSV with fields SITE_NAME, SITE_URL. Include input file with -if, --input-filename

    Reports:
      -ramh, --report-agents-missing-heartbeat
                            Report agents that have not checked in recently and exit. Number of seconds is configurable on config.py. Exit code is non-zero if all agents are checking in. Output filename is required. Specify output filename with -o, --output-format.
                        
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

    spider-web -gl
    spider-web --get-license

#### Get Agent Information
    spider-web -aga -pn 1 -ps 200
    spider-web --get-agents --page-number 1 --page-size 200

#### Get Discovered Services Information
    spider-web -dgds -pn 1 -ps 200
    spider-web --get-discovered-services --page-number 1 --page-size 200

    spider-web -ddds -of netsparker.csv -os Comma
    spider-web --download-discovered-services --output-filename netsparker.csv --output-separator Comma

#### Get Team Member Information
    spider-web -tmgtm -pn 1 -ps 200
    spider-web --get-team-members --page-number 1 --page-size 200

#### Get Website Information
    spider-web -wgw -pn 1 -ps 200
    spider-web --get-websites --page-number 1 --page-size 200

    spider-web -wupw -if groups.csv
    spider-web --upload-websites --input-file websites.csv
    
#### Get Website Groups Information
    spider-web -wggwg -pn 1 -ps 200
    spider-web --get-website-groups --page-number 1 --page-size 200

    spider-web -wgupwg -if groups.csv
    spider-web --upload-website-groups --input-file groups.csv

#### Get Vulnerability Template Information
    spider-web -vgvtemps -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-templates --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtemp -vt Xss -rpi 074018e9-02d3-4e47-a937-6f7684e814da
    spider-web --get-vulnerability-template --vulnerability-type Xss --report-policy-id 074018e9-02d3-4e47-a937-6f7684e814da

    spider-web -vgvtypes
    spider-web --get-vulnerability-types

#### Auxiliary Features and Reports
    spider-web -auxps
    spider-web --ping-sites
    
    spider-web -auxpsif --input-file websites.csv
    spider-web --ping-sites-in-file --input-file websites.csv

#### Reports
    spider-web -ramh -of netsparker.csv
    spider-web --report-agents-missing-heartbeat --output-filename netsparker.csv