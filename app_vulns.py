#!/usr/bin/python3

# App vulns
# Using app db - vulners.com
# For free API, rate limit is 10 requests / sec and maximum of 1000 requests / month on a free license.
# API key to be stored in app_vulns.conf file as api_key parameter
# Cheers to Vulners team for extending their support in testing the APIs
# Vulners twitter: @VulnersCom
# Vulners GitHub: vulnersCom


import optparse, sys, re, urllib.parse, unicodedata
import vulners
import xlrd

comment_re = re.compile(r"^\#")
xlsx_re = re.compile(r"\.xls(x)?")

class Conf:

    api_key = ""
    conf_filename = ""

    def __init__(self, conf_file = "app_vulns.conf"):
        self.conf_filename = conf_file
        print("[+] Using configuration file '{}'".format(conf_file))
        self.__loadConf__()

    def __loadConf__(self):
        try:
            conf_file = open(self.conf_filename, "r")
            confs = conf_file.readlines()
            conf_file.close()

            for conf in confs:
                if not comment_re.match(conf):
                    [key, value] = conf.split("=")
                    api_key_conf = value if key == "api_key" else ""
                    print ("[*] Configuration Loaded Succssfully.")
            self.api_key = api_key_conf    
    
        except:
            print ("[-] Unable to load the configuration.")


def search_vulners(query_term = "", api_key = ""):
    vulners_api = vulners.Vulners(api_key)
    results = vulners_api.search(urllib.parse.quote(query_term), limit=5)
    return results


def gen_query_term(sw_info = "", ver = ""):
    if ver != "":
        ver_re = re.compile(re.escape(ver))
        if  not ver_re.search(sw_info):
            query_term = sw_info + " " + ver
        else:
            query_term = sw_info
    else:
        query_term = sw_info

    return query_term


def parse_xls(input_filename = ""):
    workbook = xlrd.open_workbook(input_filename)
    worksheet = workbook.sheet_by_index(0)

    first_row = []
    for col in range(worksheet.ncols):
        first_row.append(worksheet.cell_value(0, col))

    data = []

    for row in range(1, worksheet.nrows):
        elm = {}
        for col in range(worksheet.ncols):
            elm[first_row[col]] = worksheet.cell_value(row, col)
        data.append(elm)
    
    return data


def get_severity(cvss=0.0):
    if cvss >= 9.0:
        return "Critical"
    if cvss < 9.0 and cvss >= 7.0:
        return "High"
    if cvss < 7.0 and cvss >= 3.0:
        return "Medium"
    if cvss < 3.0 and cvss >= 0.1:
        return "Low"
    if cvss == 0.0:
        return "Info"


def parse_results_to_csv(input_filename = "", api_key=""):
    
    xlsx = parse_xls(input_filename)

    output_filename = xlsx_re.sub(".csv", input_filename)
    csv_data = "Sr. No., Application, Vulnerability Title, Severity, Family, Type, ID, CVSS Score, CVSS Vector, Published, Reference\n"
    counter = 1
    row_counter = 1

    for row in xlsx:
        sw_info = row["Software Information"]
        ver = str(row["Version"])
        query_term = gen_query_term(sw_info, ver)

        print(" "*119, end='\r')
        print("[*] Processing record {} - {}".format(row_counter, query_term), end = "\r")

        results = search_vulners(query_term, api_key)
        if len(results) > 0:
            for result in results:
                title = re.sub(",", "", result["title"])
                family = result["bulletinFamily"]
                vtype = result["type"]
                vid = result["id"]
                cvss_score = result["cvss"]["score"]
                severity = get_severity(cvss_score)
                cvss_vector = result["cvss"]["vector"]
                published = result["published"]
                ref = result["href"]
                csv_data += "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(counter, query_term, title, severity, family, vtype, vid, cvss_score, cvss_vector, published, ref)
                counter += 1
        else:
            csv_data += "{},{},NONE,,,,,,,\n".format(counter, query_term)
            counter += 1
        
        row_counter += 1
        
    csv_data = unicodedata.normalize("NFKD", csv_data).encode('ascii', 'ignore')
    csv_file = open(output_filename, "wb")
    csv_file.write(csv_data)
    csv_file.close()

    print("[*] Data written to '{}'".format(output_filename))

def main():
    parser = optparse.OptionParser()
    parser.add_option("-x", "--xlsx", dest="xlsx_filename", help="Excel Spreedsheet with following table headers (Software Information, Version)")

    (options, args) = parser.parse_args()

    if not options.xlsx_filename:
        print("[-] Excel filename required.")
        parser.print_help()
        sys.exit(2)
    
    c = Conf()
    parse_results_to_csv(input_filename=options.xlsx_filename, api_key=c.api_key)


if __name__ == "__main__":
    main()
