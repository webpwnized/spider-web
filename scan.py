from datetime import datetime
from dateutil import parser

class Scan():

    _m_scan_id: str = ""
    _m_initiated_at: str = ""
    _m_initiated_at_datetime: datetime = None
    _m_target_url: str = ""
    _m_total_vulnerability_count: int = 0
    _m_scan_profile_id: str = ""
    _m_is_completed: bool = False
    _m_vulnerability_critical_count: int = 0
    _m_vulnerability_high_count: int = 0
    _m_vulnerability_medium_count: int = 0
    _m_vulnerability_low_count: int = 0
    _m_vulnerability_best_practice_count: int = 0
    _m_vulnerability_info_count: int = 0
    _m_website_id: str = ""

    def __init__(self, p_scan: dict) -> None:
        self._m_scan_id = p_scan["Id"]
        self._m_initiated_at = p_scan["InitiatedAt"]
        self._m_initiated_at_datetime = parser.parse(p_scan["InitiatedAt"])
        self._m_target_url = p_scan["TargetUrl"]
        self._m_scan_profile_id = p_scan["ScanTaskProfileId"]
        self._m_is_completed = p_scan["IsCompleted"]
        self._m_total_vulnerability_count = p_scan["TotalVulnerabilityCount"]
        self._m_vulnerability_critical_count = p_scan["VulnerabilityCriticalCount"]
        self._m_vulnerability_high_count = p_scan["VulnerabilityHighCount"]
        self._m_vulnerability_info_count = p_scan["VulnerabilityInfoCount"]
        self._m_vulnerability_best_practice_count = p_scan["VulnerabilityBestPracticeCount"]
        self._m_vulnerability_low_count = p_scan["VulnerabilityLowCount"]
        self._m_vulnerability_medium_count = p_scan["VulnerabilityMediumCount"]
        self._m_website_id = p_scan["WebsiteId"]

    @property  # getter method
    def scan_id(self) -> str:
        return self._m_scan_id

    @property  # getter method
    def initiated_at(self) -> str:
        return self._m_initiated_at

    @property  # getter method
    def initiated_at_datetime(self) -> datetime:
        return self._m_initiated_at_datetime

    @property  # getter method
    def target_url(self) -> str:
        return self._m_target_url

    @property  # getter method
    def scan_profile_id(self) -> str:
        return self._m_scan_profile_id

    @property  # getter method
    def is_completed(self) -> bool:
        return self._m_is_completed

    @property  # getter method
    def total_vulnerability_count(self) -> int:
        return self._m_total_vulnerability_count

    @property  # getter method
    def vulnerability_critical_count(self) -> int:
        return self._m_vulnerability_critical_count

    @property  # getter method
    def vulnerability_high_count(self) -> int:
        return self._m_vulnerability_high_count

    @property  # getter method
    def vulnerability_info_count(self) -> int:
        return self._m_vulnerability_info_count

    @property  # getter method
    def vulnerability_best_practice_count(self) -> int:
        return self._m_vulnerability_best_practice_count

    @property  # getter method
    def vulnerability_low_count(self) -> int:
        return self._m_vulnerability_low_count

    @property  # getter method
    def vulnerability_medium_count(self) -> int:
        return self._m_vulnerability_medium_count

    @property  # getter method
    def website_id(self) -> str:
        return self._m_website_id
