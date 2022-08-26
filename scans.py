from printer import Printer, Level, Force
from scan import Scan
from datetime import datetime
from dateutil import parser

class Scans():

     __mPrinter: Printer = Printer
     __m_scans: dict = {}

     def scans(self) -> dict:
         return self.__m_scans

     def count(self) -> int:
         return len(self.__m_scans)

     def is_excluded(self, p_candidate_scan: dict) -> bool:
        l_scan_tags = p_candidate_scan["Tags"] 
        l_profile_tags = p_candidate_scan.get("ScanTaskProfile", {}).get("Tags")
        l_tags = l_scan_tags + l_profile_tags
        if ("Not for BSC" in l_tags):
            l_scan_id = p_candidate_scan["ScanTaskProfileId"]
            self.__mPrinter.print(f"Excluded Scan Id: {l_scan_id} \t Tags: {l_tags}", Level.INFO)
            return True
        return False

     def is_complete(self, p_candidate_scan: dict) -> bool:
        if (p_candidate_scan["IsCompleted"]
                and p_candidate_scan["State"] == "Complete"
                and (p_candidate_scan["ScanType"] == "Full" 
                    or p_candidate_scan["ScanType"] == "Incremental")
                and p_candidate_scan["ScanTaskProfileId"]):
            return True
        return False

     def append_if_better(self, p_candidate_scan: dict) -> None:
         try:
             if self.is_complete(p_candidate_scan) and not self.is_excluded(p_candidate_scan):
                 l_scan_profile_id: str = p_candidate_scan["ScanTaskProfileId"]
                 if l_scan_profile_id in self.__m_scans:
                     l_new_scan_create_datetime: datetime = parser.parse(p_candidate_scan["InitiatedAt"])
                     l_current_scan_create_datetime: datetime = self.__m_scans[l_scan_profile_id].initiated_at_datetime
                     if l_new_scan_create_datetime > l_current_scan_create_datetime:
                         self.__m_scans[l_scan_profile_id] = Scan(p_candidate_scan)
                 else:
                     self.__m_scans[l_scan_profile_id] = Scan(p_candidate_scan)
         except Exception as e:
             self.__mPrinter.print("append_if_better() - {0}".format(str(e)), Level.ERROR)
