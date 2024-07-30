import vulners
from prettytable.colortable import ColorTable, Themes


class CVEcheck:
    def __init__(self) -> None:
        self.api_status = self._api_validator()

    def _api_validator(self):

        # code to check if api is available
        try:
            # vuln_api file is not on the git repo for security reason. go to https://vulners.com/docs/apikey/
            # and learn how to get a free api key
            with open("vuln_api", "r") as file:
                self.api = file.readline()
            try:
                self.api = vulners.VulnersApi(api_key=self.api)
                return True
            except:
                print(
                    f"API key {self.api} is not working. please check it again")
                return False

        except FileNotFoundError:
            print(f"Go to https://vulners.com/ or https://vulners.com/docs/apikey/, "
                  f"and request for a free api. paste it into a file called vuln_api")
            return False

    def vulnerability_check(self, ip, port, text):
        self.ip = ip
        self.port = port
        self.text_check = text
        res = self.api.find_exploit(str(self.text_check), limit=2)
        self.__PrintVulnRes__(res)
        return res

    def __PrintVulnRes__(self, results):
        l = len(results)
        table = ColorTable(theme=Themes.OCEAN)
        table.field_names = ["IP Address : Port",
                             'CVE Code(s)', "Title", "Family", "CVSS", "Link"]

        if len(results) == 0:
            print(f"No known exploit was found for {self.port}. This may be as a result of the port banner used."
                  f"Check exploitdb.")
            return

        print(
            f"\nVulnerability search results for {self.ip}:{self.port} -> {self.text_check}")
        count = 0
        for res in results:
            count += 1
            if count == 1:
                row = [
                    f"{self.ip}: {self.port}", ", ".join(
                        res['cvelist']), res['title'], res['bulletinFamily'],
                    res['cvss']['score'], res['href']
                ]
            else:

                row = [
                    "", ", ".join(
                        res['cvelist']), res['title'], res['bulletinFamily'], res['cvss']['score'], res['href']
                ]
            table.add_row(row)
        print(table)


def scan_vulns(res):
    cve = CVEcheck()
    if not cve.api_status:
        return
    for ip, port, text in res:
        if len(text) == 0:
            continue
        cve.vulnerability_check(ip, port, text)
