#!/usr/bin/python3
import os
import sys
import xml.etree.ElementTree as ET
from urllib.request import urlretrieve
import argparse

SOFTWARELIST = "{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list"

usage = """
     ---------   Python CVE Searcher    --------
        Downloads and searches through the
          National Vulnerability Database

     ./CVEsearch.py <name> [options]
"""


def main():
    args = parseArgs(sys.argv)

    print("\nSearching for CVEs...")
    print("Software: " + args.name)
    print("Date: " + str(args.date) + " - present")
    print("Version: " + str(args.versionNumber))
    print("Extra Terms: " + str(args.termList))

    downloadDatabaseFiles(args.date)
    print('')

    for year in range(args.date, 2014):
        try:
            tree = ET.parse(str(year) + "_CVEs.xml")
            root = tree.getroot()
        except:
            print("Database for year " + str(year) + " was corrupt")
            print("Redownloading")
            os.unlink(str(year) + "_CVEs.xml")
            downloadDatabaseFiles(year)
            tree = ET.parse(str(year) + "_CVEs.xml")
            root = tree.getroot()
        for CVE in root:
            searchThrough(CVE, args)

    if len(sys.argv) == 1:
        print(usage)
        print("Use '-h' flag for help")
        exit(0)


def parseArgs(arguments):
    args = arguments[1:]
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument('name', help="Name of software you are researching\n")

    parser.add_argument(
        '-d', '--date',
        type=int,
        default=2010,
        help="Earliest date of CVEs you want to find \
              Default is 2010\n""")

    parser.add_argument(
        '-s', '--severity',
        type=float,
        dest="severity",
        default=0.0,
        help="""
             Lowest severity score to display.\n
             Default is 0.0
             Highest is 10.0\n""")

    parser.add_argument(
        '-t', '--terms',
        default="",
        help="""Search terms that must be present in the
             description of the CVE.  Terms must be
             enclosed by quotations and seperated by spaces
             Example:
             "remote code execution"\n""")

    parser.add_argument(
        '-v', '--versionNumber',
        default="",
        help="| version of software you want to find.\n")

    args = parser.parse_args(args)

    if(len(args.terms) > 1):
        args.termList = args.terms.split(' ')
    else:
        args.termList = []

    return args


def dlProgress(count, blockSize, totalSize):
    percent = int(count*blockSize*100/totalSize)
    sys.stdout.write("%2d%%" % percent)
    sys.stdout.write("\b\b\b")
    sys.stdout.flush()


def downloadDatabaseFiles(year):
    for x in range(year, 2015):
        x = str(x)
        destFileName = x + "_CVEs.xml"
        if os.path.isfile(destFileName):
            continue

        print("Downloading database for year " + x)
        dbUrl = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-" + x + ".xml"
        destFileName = x + "_CVEs.xml"
        dbFile = urlretrieve(dbUrl, destFileName, reporthook=dlProgress)


def searchThrough(CVE, args):
    # Does software list exist?
    SOFTWARELISTIterable = CVE.find(SOFTWARELIST)
    if SOFTWARELISTIterable is None:
        return

    # Is your software/version affected?
    isAffected = 0
    for software in SOFTWARELISTIterable:
        if args.name in software.text:
            if args.versionNumber == 0 or str(args.versionNumber) in software.text:
                isAffected = 1
    if isAffected == 0:
        return

    # Is the score high enough?
    basic_attributes = "{http://scap.nist.gov/schema/vulnerability/0.4}cvss"
    ba = CVE.find(basic_attributes)
    score = float(ba[0][0].text)
    if score < args.severity:
        return

    # Are terms in description?
    description = CVE[-1].text
    for term in args.termList:
        if term not in description:
            return

    print(CVE.attrib['id'], score)
    print(description)
    print("--------------------------------------")
    return

if __name__ == '__main__':
    main()
