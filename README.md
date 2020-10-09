# Spider Web

### Usage

    usage: spider-web [-h] [-v] [-d] [-o {JSON,CSV}] [-e] [-u] [-t] [-ga] [-gl]

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
    
    Account Endpoint:
      -ga, --get-account    Get account information and exit
      -gl, --get-license    Get license information and exit

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

#### Fetch Account Information
    spider-web -ga
    spider-web --get-account

    spider-web -gl
    spider-web --get-license