# Spider Web

### Dependecies

    python3

### Installation

  1. Run ./install.sh (Linux only)
  2. Copy API user ID and password into ***spider-web.key*** file
  3. If using proxy, enter proxy settings into ***config.py***. Set ***USE_PROXY=TRUE***. If proxy performs TLS inspection, and proxy CA certificate is not available, setting ***VERIFY_HTTPS_CERTIFICATE=FALSE*** may be an effective, although insecure, workaround
  4. Show help with ***spider-web -h***
  5. Test connectivity with ***spider-web -t***

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
                            The page size can be any value between 1 and 200
      -if INPUT_FILENAME, --input-filename INPUT_FILENAME
                        Input filename. File must be propely formatted.
      -of OUTPUT_FILENAME, --output-filename OUTPUT_FILENAME
                            Output filename. Default is netsparker.csv
      -os OUTPUT_SEPARATOR, --output-separator OUTPUT_SEPARATOR
                            Output separator for downloaded CSV files. Default is comma. Choices are ['Comma', 'Semicolon', 'Pipe', 'Tab']

    Account Endpoint:
      -ga, --get-account    Get account information and exit
      -gl, --get-license    Get license information and exit
    
    Agents Endpoint:
      -aga, --get-agents    List agents and exit. Output fetched in pages.
    
    Discovery Endpoint:
      -dsgds, --get-discovered-services
                            List discovered services and exit. Output fetched in pages.
      -dsdds, --download-discovered-services
                            Download discovered services and exit
    
    Team Member Endpoint:
      -tmgtm, --get-team-members
                            List users and exit Output fetched in pages.
    
    Website Endpoint:
      -wgw, --get-websites  List websites and exit. Output fetched in pages.
      -wupw, --upload-websites
                            Create websites and exit. Requires properly formatted input file.
    
    Website Groups Endpoint:
      -wggwg, --get-website-groups
                            List website groups and exit. Output fetched in pages.
      -wgupwg, --upload-website-groups
                            Create website groups and exit. Requires properly formatted input file.

    Vulnerability Endpoint:
      -vgvtemps, --get-vulnerability-templates
                            List vulnerability templates and exit
      -vgvtemp, --get-vulnerability-template
                            Get the vulnerability template given vulnerability type and exit
      -vgvtypes, --get-vulnerability-types
                            List vulnerability types and exit
    
    Vulnerability Endpoint Options:
      -rpi REPORT_POLICY_ID, --report-policy-id REPORT_POLICY_ID
                            The report policy ID
      -vt VULNERABILITY_TYPE, --vulnerability-type VULNERABILITY_TYPE
                            The vulnerability type  
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