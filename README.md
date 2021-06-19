# Spider Web

     _____       _     _             _    _      _     
    /  ___|     (_)   | |           | |  | |    | |    
    \ `--. _ __  _  __| | ___ _ __  | |  | | ___| |__  
     `--. \ '_ \| |/ _` |/ _ \ '__| | |/\| |/ _ \ '_ \ 
    /\__/ / |_) | | (_| |  __/ |    \  /\  /  __/ |_) |
    \____/| .__/|_|\__,_|\___|_|     \/  \/ \___|_.__/ 
          | |                                          
          |_|                                          
    
     Automated NetSparker Analysis - Fortuna Fortis Paratus

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
    
    spider-web -u
    spider-web --usage

### Options

    spider-web -h
    spider-web --help

### Examples

    spider-web -e
    spider-web --examples
