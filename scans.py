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

     def append_if_better(self, p_candidate_scan: dict) -> None:
         try:
             if p_candidate_scan["IsCompleted"]:
                 l_scan_matched: bool = False
                 l_scan_profile_id: str = p_candidate_scan["ScanTaskProfileId"]
                 if l_scan_profile_id in self.__m_scans:
                     l_scan_matched = True
                     l_new_scan_create_datetime: datetime = parser.parse(p_candidate_scan["InitiatedAt"])
                     l_current_scan_create_datetime: datetime = self.__m_scans[l_scan_profile_id].initiated_at_datetime
                     if l_new_scan_create_datetime > l_current_scan_create_datetime:
                         self.__m_scans[l_scan_profile_id] = Scan(p_candidate_scan)
                 if not l_scan_matched:
                     self.__m_scans[l_scan_profile_id] = Scan(p_candidate_scan)
         except Exception as e:
             self.__mPrinter.print("append_if_better() - {0}".format(str(e)), Level.ERROR)
