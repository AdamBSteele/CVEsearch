     ----------------    Python CVE Searcher    ----------------
  Downloads and searches through the National Vulnerability Database

  ./CVEsearch.py <name> [options]


positional argument:

 | name | Name of software you are researching |

Optional Arguments:


| Flag | Name     |       Description          |
|:----:|:------   | -------------------------- |
|  -h  | Help     | Show help message and exit |
|  -d  | Date     | Earliest date of CVEs you want to find Default is 2010 |
|  -s  | Severity | Lowest severity score to display. |
|	   |          |		Default is 0.0  |
|	   |          |		highest is 10.0 |
|  -t  | Terms    | Search terms that must be present in the description |
|	   |          |	    of the CVE. Terms must be enclosed by quotations and |
|	   |          |	    seperated by spaces |
|	   |          |	Example: "remote code execution" |
|  -v  | Version  | Version of software you want to find |