     ----------------    Python CVE Searcher    ----------------
  Downloads and searches through the National Vulnerability Database

  ./CVEsearch.py <name> [options]


positional arguments:
  name                  Name of software you are researching

optional arguments:
  -h, --help            show this help message and exit

  -d DATE, --date DATE  Earliest date of CVEs you want to find Default is 2010

  -s SEVERITY, --severity SEVERITY
                        Lowest severity score to display. Default is 0.0
                        Highest is 10.0

  -t TERMS, --terms TERMS
                        Search terms that must be present in the description
                        of the CVE. Terms must be enclosed by quotations and
                        seperated by spaces Example: "remote code execution"

  -v VERSIONNUMBER, --versionNumber VERSIONNUMBER
                        | version of software you want to find.
                        