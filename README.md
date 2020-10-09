# Eagle Eye

### Usage

    usage: eagle-eye [-h] [-v] [-d] [-o {JSON,CSV}] [-e] [-u] [-t] [-a] [-lbu]
                     [-lae] [-al ASSET_LIMIT] [-apt ASSET_PAGE_TOKEN] [-lit]
                     [-gic] [-gi] [-gissue] [-iid ISSUE_ID] [-il ISSUE_LIMIT]
                     [-ipt ISSUE_PAGE_TOKEN] [-ics ISSUE_CONTENT_SEARCH]
                     [-ipid ISSUE_PROVIDER_ID] [-ipname ISSUE_PROVIDER_NAME]
                     [-ibu ISSUE_BUSINESS_UNIT] [-ibn ISSUE_BUSINESS_UNIT_NAME]
                     [-iau ISSUE_ASSIGNEE_USERNAME] [-itid ISSUE_TYPE_ID]
                     [-itn ISSUE_TYPE_NAME] [-iis ISSUE_INET_SEARCH]
                     [-ids ISSUE_DOMAIN_SEARCH] [-ipn ISSUE_PORT_NUMBER]
                     [-ips ISSUE_PROGRESS_STATUS] [-ias ISSUE_ACTIVITY_STATUS]
                     [-ip ISSUE_PRIORITY] [-itagid ISSUE_TAG_ID]
                     [-itname ISSUE_TAG_NAME] [-ica ISSUE_CREATED_AFTER]
                     [-icb ISSUE_CREATED_BEFORE] [-ima ISSUE_MODIFIED_AFTER]
                     [-imb ISSUE_MODIFIED_BEFORE] [-isort ISSUE_SORT]
                     [-icf ISSUE_CSV_FILENAME] [-let] [-les] [-le]
                     [-el EXPOSURE_LIMIT] [-eo EXPOSURE_OFFSET]
                     [-et EXPOSURE_TYPE] [-ei EXPOSURE_INET]
                     [-ec EXPOSURE_CONTENT] [-eas {active,inactive}]
                     [-elet EXPOSURE_LAST_EVENT_TIME]
                     [-elew {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}]
                     [-es {ROUTINE,WARNING,CRITICAL}]
                     [-eet {appearance,reappearance,disappearance}]
                     [-etag EXPOSURE_TAG] [-ebu EXPOSURE_BUSINESS_UNIT]
                     [-epn EXPOSURE_PORT_NUMBER] [-esort EXPOSURE_SORT]

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
      -a, --authenticate    Exchange a refresh token for an access token and exit
      -lbu, --list-business-units
                            List business units and exit
    
    Assets API Interface Endpoints:
      Methods to interact with the Assets API
    
      -lae, --list-asset-entities
                            List asset entities and exit
    
    Assets API Interface Endpoint Options:
      Arguments to methods that interact with the Assets API. Use these options with '-lae', '--list-asset-entities'
    
      -al ASSET_LIMIT, --asset-limit ASSET_LIMIT
                            Page size in pagination
      -apt ASSET_PAGE_TOKEN, --asset-page-token ASSET_PAGE_TOKEN
                            Page token for pagination
    
    Issues API Interface Endpoints:
      Methods to interact with the Issues API
    
      -lit, --list-issue-types
                            List issue types and exit
      -gic, --get-issues-count
                            Get a count of issues. Returns the total count of issues matching the provided filters, up to 10K.
      -gi, --get-issues     Get a paginated list of issues.
      -gissue, --get-issue  Get details about an issue
    
    Issues API Interface Endpoint Options:
      Arguments to methods that interact with the Issues API.
    
      -iid ISSUE_ID, --issue-id ISSUE_ID
                            ID of the issue
      -il ISSUE_LIMIT, --issue-limit ISSUE_LIMIT
                            Returns at most this many results in a single api call (default: 100, max: 10,000).
      -ipt ISSUE_PAGE_TOKEN, --issue-page-token ISSUE_PAGE_TOKEN
                            Page token for pagination
      -ics ISSUE_CONTENT_SEARCH, --issue-content-search ISSUE_CONTENT_SEARCH
                            Returns only results whose contents match the given query
      -ipid ISSUE_PROVIDER_ID, --issue-provider-id ISSUE_PROVIDER_ID
                            Comma-separated string; Returns only results that were found on the given providers.
      -ipname ISSUE_PROVIDER_NAME, --issue-provider-name ISSUE_PROVIDER_NAME
                            Comma-separated string; Returns only results that were found on the given providers.
      -ibu ISSUE_BUSINESS_UNIT, --issue-business-unit ISSUE_BUSINESS_UNIT
                            Comma-separated string; Returns only results with a business unit whose ID falls in the provided list.
      -ibn ISSUE_BUSINESS_UNIT_NAME, --issue-business-unit-name ISSUE_BUSINESS_UNIT_NAME
                            Comma-separated string; Returns only results with a business unit whose name falls in the provided list.
      -iau ISSUE_ASSIGNEE_USERNAME, --issue-assignee-username ISSUE_ASSIGNEE_USERNAME
                            Comma-separated string; Returns only results whose assignees username matches one of the given usernames. Use "Unassigned" to fetch issues that are not assigned to any user.
      -itid ISSUE_TYPE_ID, --issue-type-id ISSUE_TYPE_ID
                            Comma-separated string; Returns only results whose issue type ID matches one of the given types.
      -itn ISSUE_TYPE_NAME, --issue-type-name ISSUE_TYPE_NAME
                            Comma-separated string; Returns only results whose issue type name matches one of the given types.
      -iis ISSUE_INET_SEARCH, --issue-inet-search ISSUE_INET_SEARCH
                            Search for results in a given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*.d). Returns results whose identifier includes an IP matching the query.
      -ids ISSUE_DOMAIN_SEARCH, --issue-domain-search ISSUE_DOMAIN_SEARCH
                            Search for a a given domain value via substring match. Returns results whose identifier includes a domain matching the query.
      -ipn ISSUE_PORT_NUMBER, --issue-port-number ISSUE_PORT_NUMBER
                            Comma-separated string; Returns only results whose identifier includes one of the given port numbers.
      -ips ISSUE_PROGRESS_STATUS, --issue-progress-status ISSUE_PROGRESS_STATUS
                            Comma-separated string; Returns only results whose progress status matches one of the given values. ['New', 'Investigating', 'InProgress']
      -ias ISSUE_ACTIVITY_STATUS, --issue-activity-status ISSUE_ACTIVITY_STATUS
                            Comma-separated string; Returns only results whose activity status matches one of the given values. ['Active', 'Inactive']
      -ip ISSUE_PRIORITY, --issue-priority ISSUE_PRIORITY
                            Comma-separated string; Returns only results whose priority matches one of the given values. ['Critical', 'High', 'Medium', 'Low']
      -itagid ISSUE_TAG_ID, --issue-tag-id ISSUE_TAG_ID
                            Comma-separated string; Returns only results that are associated with the provided tag IDs.
      -itname ISSUE_TAG_NAME, --issue-tag-name ISSUE_TAG_NAME
                            Comma-separated string; Returns only results that are associated with the provided tag names.
      -ica ISSUE_CREATED_AFTER, --issue-created-after ISSUE_CREATED_AFTER
                            Returns only results created after the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).
      -icb ISSUE_CREATED_BEFORE, --issue-created-before ISSUE_CREATED_BEFORE
                            Returns only results created before the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).
      -ima ISSUE_MODIFIED_AFTER, --issue-modified-after ISSUE_MODIFIED_AFTER
                            Returns only results modified after the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).
      -imb ISSUE_MODIFIED_BEFORE, --issue-modified-before ISSUE_MODIFIED_BEFORE
                            Returns only results modified before the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).
      -isort ISSUE_SORT, --issue_sort ISSUE_SORT
                            Sort by specified properties. ['created', '-created', 'modified', '-modified', 'assigneeUsername', '-assigneeUsername', 'priority', '-priority', 'progressStatus', '-progressStatus', 'activityStatus', '-activityStatus', 'headline', '-headline']
      -icf ISSUE_CSV_FILENAME, --issue-csv-filename ISSUE_CSV_FILENAME
                            The name of the returned CSV file
    
    Exposures API Interface Endpoints:
      Methods to interact with the Exposures API
    
      -let, --list-exposure-types
                            List exposure types and exit. The results can be filtered by -es, --exposure-severity
      -les, --list-exposure-summaries
                            List exposures summaries and exit. The results can be filtered by the options shown below.
      -le, --list-exposures
                            List exposures and exit. The results can be filtered by the options shown below.
    
    Exposures API Interface Endpoint Options:
      Arguments to methods that interact with the Exposures and Summaries API. Use these options with '-le', '--list-exposures', '-les', '--list-exposure-summaries'
    
      -el EXPOSURE_LIMIT, --exposure-limit EXPOSURE_LIMIT
                            How many items to return at one time (default 100, max 10,000). Note that this parameter will be ignored when requesting CSV data.
      -eo EXPOSURE_OFFSET, --exposure-offset EXPOSURE_OFFSET
                            How many items to skip before beginning to return results. Note that this parameter will be ignored when requesting CSV data.
      -et EXPOSURE_TYPE, --exposure-type EXPOSURE_TYPE
                            Returns only results that have an exposure type that is in the given list. The values which can be used in this parameter should be retrieved from -let, --list-exposure-types.
      -ei EXPOSURE_INET, --exposure-inet EXPOSURE_INET
                            Search for given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*). Returns only results whose IP address overlaps with the passed IP Address or CIDR.
      -ec EXPOSURE_CONTENT, --exposure-content EXPOSURE_CONTENT
                            Returns only results whose contents match the given query
      -eas {active,inactive}, --exposure-activity-status {active,inactive}
                            Filter results by exposure activity status
      -elet EXPOSURE_LAST_EVENT_TIME, --exposure-last-event-time EXPOSURE_LAST_EVENT_TIME
                            Returns only results whose last scanned or last disappearance were after the given timestamp
      -elew {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}, --exposure-last-event-window {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}
                            Filter results by exposure last event window
      -es {ROUTINE,WARNING,CRITICAL}, --exposure-severity {ROUTINE,WARNING,CRITICAL}
                            Filter results by exposure severity
      -eet {appearance,reappearance,disappearance}, --exposure-event-type {appearance,reappearance,disappearance}
                            Filter results by exposure event type
      -etag EXPOSURE_TAG, --exposure-tag EXPOSURE_TAG
                            Comma-separated string with no spaces after the comma; Returns only results that have ips corresponding to the given set of tags.
      -ebu EXPOSURE_BUSINESS_UNIT, --exposure-business-unit EXPOSURE_BUSINESS_UNIT
                            Comma-separated string; Returns only results associated with the given businessUnit ids, provided that the requesting user has permissions to view results associated with the given business unit.
      -epn EXPOSURE_PORT_NUMBER, --exposure-port-number EXPOSURE_PORT_NUMBER
                            Comma-separated string; Returns only results that have port numbers corresponding to the given port numbers.
      -esort EXPOSURE_SORT, --exposure-sort EXPOSURE_SORT
                            Comma-separated string; orders results by the given fields. If the field name is prefixed by a -, then the ordering will be descending for that field. Use a dotted notation to order by fields that are nested. This values which can be used in this parameter should be retrieved from /configurations/exposures.

### Examples

#### Get Help
    python3 eagle-eye.py -h
    python3 eagle-eye.py -u
    python3 eagle-eye.py -e

#### Test Connectivity
    python3 eagle-eye.py -t

#### Get a JSON Web Token (JWT)
    python3 eagle-eye.py -a

#### List business units
    python3 eagle-eye.py -lbu -o JSON
    python3 eagle-eye.py -lbu -o CSV

#### List exposure types
    python3 eagle-eye.py -let -o JSON
    python3 eagle-eye.py -let -o CSV

#### List exposure summaries
    python3 eagle-eye.py -les -o JSON
    python3 eagle-eye.py -les -o CSV
    python3 eagle-eye.py -les -et TELNET_SERVER -o CSV
    python3 eagle-eye.py -les -es CRITICAL -o CSV

#### List exposures - Insecure protocols
    python3 eagle-eye.py -le -o JSON -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN
    
    python3 eagle-eye.py -le -o CSV -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN -esort businessUnit.name,severity,port,ip 

#### List exposures - Insecure certificates
    python3 eagle-eye.py -le -o JSON -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT
    
    python3 eagle-eye.py -le -o CSV -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT -esort businessUnit.name,severity,port,ip 

#### List exposures - Web domains
    python3 eagle-eye.py -le -o CSV -et SERVER_SOFTWARE,APPLICATION_SERVER_SOFTWARE

#### List issue types
    python3 eagle-eye.py -lit -o JSON
    python3 eagle-eye.py -lit -o CSV

#### Get issue count
    python3 eagle-eye.py -gic -ibu ebbd0ef3-ed86-4020-b7c8-a55aa73efe60 -ip Critical,High,Medium,Low -ias Active -o JSON
    python3 eagle-eye.py -gic -ibu ebbd0ef3-ed86-4020-b7c8-a55aa73efe60 -ip Critical,High,Medium,Low -ias Active -o CSV

#### Get issues
    python3 eagle-eye.py -gi -ibu ebbd0ef3-ed86-4020-b7c8-a55aa73efe60 -ip Critical,High,Medium,Low -ias Active -o JSON
    python3 eagle-eye.py -gi -ibu ebbd0ef3-ed86-4020-b7c8-a55aa73efe60 -ip Critical,High,Medium,Low -ias Active -o CSV
    
#### Get issue
    python3 eagle-eye.py -gissue -iid 3df7a930-3ec3-3a61-804c-c4e28fce972f -o JSON
    python3 eagle-eye.py -gissue -iid 3df7a930-3ec3-3a61-804c-c4e28fce972f -o CSV
