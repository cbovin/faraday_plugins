import re
import warnings

import nvdlib as nvdlib
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

from faraday_plugins.plugins.plugin import PluginHTMLFormat

__author__ = "Cristian Bovino"
__copyright__ = "Copyright (c) 2022, ETHz"
__credits__ = ["Cristian Bovino"]
__license__ = ""
__version__ = "1.0.0"
__status__ = "Development"

warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

class OpenScapOvalHTMLParser:

    def __init__(self, xml_output):
        self.vulns = self.parse_xml(xml_output)

    def parse_xml(self, xml_output):
        vulns = []
        soup = BeautifulSoup(xml_output, 'lxml')
        trs = soup.find_all('tr', {'class': re.compile(r'resultbad.')})
        ip = re.findall(r'192\.168\.\d{1,3}\.\d{1,3}', str(xml_output))  # Match with 192.168.*.*

        if len(ip) != 1:
            raise Exception(f"The IPs found in the report does not match the pattern {ip}")

        ip = ip[0]
        for i in trs:
            tds = i.find_all('td')
            cves = re.sub('\[|]|\s', '', tds[3].text).split(',')
            for cve in cves:
                if not cve.startswith('USN'):  # Avoid to have Ubuntu Security Notice
                    cve_details = nvdlib.searchCVE(cveId=cve, key='81620624-e03f-4ba0-9b62-48e87254a2a2', delay=0.6)
                    if len(cve_details) == 1:  # Only one CVE
                        cve_details = cve_details[0]
                        ref = 'https://nvd.nist.gov/vuln/detail/' + cve
                        vulns.append({
                            'ip': ip,
                            #'os': 'Ubuntu 20.04 LTS',
                            'name': cve,
                            'description': cve_details.descriptions[0].value,
                            'severity': cve_details.v31severity,
                            'score': cve_details.v31score,
                            'reference': {'name': ref, 'type': 'other'}
                        })
                        # print(cve_details)
                    else:
                        vulns.append({
                            'ip': ip,
                            # 'os': 'Ubuntu 20.04 LTS',
                            'name': cve,
                            'description': '',
                            'severity': 'unclassified',
                            'score': 0,
                            'reference': {'name': '', 'type': 'other'}
                        })
                        print(f'CVE not in the database: {cve}')

        # print(vulns)
        return vulns


class OpenScapOvalXMLPlugin(PluginHTMLFormat):
    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "Benchmark"
        self.id = "OpenScapHTML"
        self.name = "OpenScap HTML Reader Plugin"
        self.plugin_version = "0.0.1"

    def parseOutputString(self, output, debug=False):
        parser = OpenScapOvalHTMLParser(output)
        for vuln in parser.vulns:
            h_id = self.createAndAddHost(vuln['ip'])
            v_id = self.createAndAddVulnToHost(host_id=h_id, name=vuln['name'], desc=vuln['description'],
                                               severity=vuln['severity'])


def createPlugin(*args, **kwargs):
    return OpenScapOvalXMLPlugin(*args, **kwargs)