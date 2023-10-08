class ExampleUsage:

    @staticmethod
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
        Get Issues
        --------------------------------
        spider-web -igi -pn 1 -ps 200
        spider-web --get-issues --page-number 1 --page-size 200

        spider-web -igi -pn 1 -ps 200 -wn "www.acme.com" -wgn "SDG: Acme"
        spider-web --get-issues --page-number 1 --page-size 200 --website-name "www.acme.com" --website-group-name "SDG: Acme"

        spider-web -idi -of netsparker.csv -os Comma
        spider-web --download-issues --output-filename netsparker.csv --output-separator Comma

        spider-web -idi -of netsparker.csv -os Comma --website-name "www.acme.com" --website-group-name "SDG: Acme"
        spider-web --download-issues --output-filename netsparker.csv --output-separator Comma  --website-name "www.acme.com" --website-group-name "SDG: Acme"

        --------------------------------
        Get Role
        --------------------------------
        spider-web -rgr -rid 6994ec49-6045-447d-9169-aa044466f201
        spider-web --get-role --role-id 6994ec49-6045-447d-9169-aa044466f201

        --------------------------------
        Get Roles
        --------------------------------
        spider-web -rgrs -pn 1 -ps 200
        spider-web --get-roles --page-number 1 --page-size 200

        spider-web -rgp
        spider-web --get-permissions

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
        Get Scan Results
        --------------------------------
        spider-web -srgsr -sid 8babd486-02da-4ecd-ba24-ace601ce041b
        spider-web --get-scan-results --scan-id 8babd486-02da-4ecd-ba24-ace601ce041b

        --------------------------------
        Get Teams
        --------------------------------
        spider-web -tgt -pn 1 -ps 200
        spider-web --get-teams --page-number 1 --page-size 200

        spider-web -tgt -pn 1 -ps 200 -of teams.txt
        spider-web --get-teams --page-number 1 --page-size 200 ---output-file teams.txt

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
        spider-web --get-account-owners --page-number 1 --page-size 200

        spider-web -tmgwm -pn 1 -ps 200 -of account-owners.txt
        spider-web --get-account-owners --page-number 1 --page-size 200 ---output-file account-owners.txt

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

        spider-web -tmgua -pn 1 -ps 200
        spider-web --get-unused-accounts --page-number 1 --page-size 200

        spider-web -tmgua -pn 1 -ps 200 -of unused-accounts.txt
        spider-web --get-unused-accounts --page-number 1 --page-size 200 ---output-file unused-accounts.txt

        --------------------------------
        Create Team Members
        --------------------------------
        spider-web -tmctm -tmn "John Doe" -tme "jdoe@acme.com" -tmsso "100000@acme.com" -tmg "SDG: Airline, Fleet & Freight (AFF)" 
        spider-web --create-team-member --team-member-name "John Doe" --team-member-email "jdoe@acme.com" --team-member-sso-email "100000@acme.com" --team-member-groups "SDG: Airline, Fleet & Freight (AFF)"

        spider-web -tmctm -tmn "John Doe" -tme "jdoe@acme.com" -tmsso "100000@acme.com" -tmg "SDG: Airline, Fleet & Freight (AFF)|SDG: Customer and Billing (CAB)" 
        spider-web --create-team-member --team-member-name "John Doe" --team-member-email "jdoe@acme.com" --team-member-sso-email "100000@acme.com" --team-member-groups "SDG: Airline, Fleet & Freight (AFF)|SDG: Customer and Billing (CAB)"

        spider-web -tmuptm -if new-team-members.csv
        spider-web --upload-team-members --input-file new-team-members.csv

        --------------------------------
        Delete Team Member
        --------------------------------
        spider-web -tmdtm -tmid f18e1179-56fb-41e7-e3b7-acbf0450fe37
        spider-web --delete-team-member --team-member-id f18e1179-56fb-41e7-e3b7-acbf0450fe37

        --------------------------------
        Get Technologies
        --------------------------------
        spider-web -techgt -pn 1 -ps 200 -wn www.acme.com
        spider-web --get-technologies --page-number 1 --page-size 200 --website-name www.acme.com

        spider-web -techgt -pn 1 -ps 200 -tn jQuery
        spider-web --get-technologies --page-number 1 --page-size 200 --technology-name jQuery

        spider-web -techgt -pn 1 -ps 200 -of technologies.txt -wn www.acme.com
        spider-web --get-technologies --page-number 1 --page-size 200 --website-name www.acme.com --output-file technologies.txt

        spider-web -techgot -pn 1 -ps 200 -wn www.acme.com
        spider-web --get-obsolete-technologies --page-number 1 --page-size 200 --website-name www.acme.com

        spider-web -techgot -pn 1 -ps 200 -tn jQuery
        spider-web --get-obsolete-technologies --page-number 1 --page-size 200 --technology-name jQuery

        spider-web -techgot -pn 1 -ps 200 -of technologies.txt
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
        Reports: Issues
        ----------------------------------------------------------------        
        spider-web -ri -ribc -ribi -v
        spider-web --report-issues --report-issues-by-cvss --report-issues-by-issue --verbose

        ----------------------------------------------------------------
        Reports: Balanced Scorecard
        ----------------------------------------------------------------        
        spider-web -rbsc -if false.csv -of report.csv
        spider-web --report-bsc --input-file false.csv --output-file report.csv
        
        spider-web -rbsc -rbai -if false.csv -of report.csv
        spider-web --report-bsc --report-bsc-all-issues --input-file false.csv --output-file report.csv
    """)

