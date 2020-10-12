# Spider Web

### Usage

    usage: spider-web [-h] [-v] [-d] [-o {JSON,CSV}] [-e] [-u] [-t] [-pn PAGE_NUMBER] [-ps PAGE_SIZE] [-ga] [-gl] [-aga] [-dsgds] [-dsdds]
                      [-of OUTPUT_FILENAME] [-os OUTPUT_SEPARATOR] [-tmgtm] [-wggwg]
                  
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
    
    Discovery Endpoint Options:
      -of OUTPUT_FILENAME, --output-filename OUTPUT_FILENAME
                            Output filename. Default is netsparker.csv
      -os OUTPUT_SEPARATOR, --output-separator OUTPUT_SEPARATOR
                            Output separator for downloaded CSV files. Default is comma. Choices are ['Comma', 'Semicolon', 'Pipe', 'Tab']
    
    Team Member Endpoint:
      -tmgtm, --get-team-members
                            List users and exit Output fetched in pages.
    
    Website Groups Endpoint:
      -wggwg, --get-website-groups
                            List website groups and exit Output fetched in pages.

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

#### Get Website Groups Information
    spider-web -wggwg -pn 1 -ps 200
    spider-web --get-website-groups --page-number 1 --page-size 200