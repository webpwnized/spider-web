from datetime import datetime
from dateutil import parser

class Scan():

    __m_scan_id: str = ""
    __m_initiated_at: str = ""
    __m_initiated_at_datetime: datetime = None
    __m_target_url: str = ""
    __m_total_vulnerability_count: int = 0
    __m_scan_profile_id: str = ""
    __m_scan_profile_name: str = ""
    __m_scan_profile_tags: str = ""
    __m_is_completed: bool = False
    __m_vulnerability_critical_count: int = 0
    __m_vulnerability_high_count: int = 0
    __m_vulnerability_medium_count: int = 0
    __m_vulnerability_low_count: int = 0
    __m_vulnerability_best_practice_count: int = 0
    __m_vulnerability_info_count: int = 0
    __m_website_id: str = ""
    __m_website_name: str = ""
    __m_scan_duration: str = ""
    __m_scan_scope: str = ""
    __m_scan_state: str = ""
    __m_scan_phase: str = ""
    __m_scan_percentage: int = 0
    __m_scan_failure_reason: str = ""
    __m_scan_tags: str = ""

    def __init__(self, p_scan: dict) -> None:
        self.__m_scan_id = p_scan["Id"]
        self.__m_initiated_at = p_scan["InitiatedAt"]
        self.__m_initiated_at_datetime = parser.parse(p_scan["InitiatedAt"])
        self.__m_target_url = p_scan["TargetUrl"]
        self.__m_scan_profile_id = p_scan["ScanTaskProfileId"]
        self.__m_scan_profile_name = p_scan.get("ScanTaskProfile", {}).get("Name")
        self.__m_scan_profile_tags = p_scan.get("ScanTaskProfile", {}).get("Tags")
        self.__m_is_completed = p_scan["IsCompleted"]
        self.__m_total_vulnerability_count = p_scan["TotalVulnerabilityCount"]
        self.__m_vulnerability_critical_count = p_scan["VulnerabilityCriticalCount"]
        self.__m_vulnerability_high_count = p_scan["VulnerabilityHighCount"]
        self.__m_vulnerability_info_count = p_scan["VulnerabilityInfoCount"]
        self.__m_vulnerability_best_practice_count = p_scan["VulnerabilityBestPracticeCount"]
        self.__m_vulnerability_low_count = p_scan["VulnerabilityLowCount"]
        self.__m_vulnerability_medium_count = p_scan["VulnerabilityMediumCount"]
        self.__m_website_id = p_scan["WebsiteId"]
        self.__m_website_name = p_scan["WebsiteName"]
        self.__m_scan_duration = p_scan["Duration"]
        self.__m_scan_scope = p_scan["Scope"]
        self.__m_scan_state = p_scan["State"]
        self.__m_scan_phase = p_scan["Phase"]
        self.__m_scan_percentage = p_scan["Percentage"]
        self.__m_scan_failure_reason = p_scan["FailureReason"]
        self.__m_scan_tags = p_scan["Tags"]

    @property  # getter method
    def scan_id(self) -> str:
        return self.__m_scan_id

    @property  # getter method
    def initiated_at(self) -> str:
        return self.__m_initiated_at

    @property  # getter method
    def initiated_at_datetime(self) -> datetime:
        return self.__m_initiated_at_datetime

    @property  # getter method
    def target_url(self) -> str:
        return self.__m_target_url

    @property  # getter method
    def scan_profile_id(self) -> str:
        return self.__m_scan_profile_id

    @property  # getter method
    def scan_profile_name(self) -> str:
        return self.__m_scan_profile_name

    @property  # getter method
    def scan_profile_tags(self) -> str:
        return "|".join(self.__m_scan_profile_tags)

    @property  # getter method
    def is_completed(self) -> bool:
        return self.__m_is_completed

    @property  # getter method
    def total_vulnerability_count(self) -> int:
        return self.__m_total_vulnerability_count

    @property  # getter method
    def vulnerability_critical_count(self) -> int:
        return self.__m_vulnerability_critical_count

    @property  # getter method
    def vulnerability_high_count(self) -> int:
        return self.__m_vulnerability_high_count

    @property  # getter method
    def vulnerability_info_count(self) -> int:
        return self.__m_vulnerability_info_count

    @property  # getter method
    def vulnerability_best_practice_count(self) -> int:
        return self.__m_vulnerability_best_practice_count

    @property  # getter method
    def vulnerability_low_count(self) -> int:
        return self.__m_vulnerability_low_count

    @property  # getter method
    def vulnerability_medium_count(self) -> int:
        return self.__m_vulnerability_medium_count

    @property  # getter method
    def website_id(self) -> str:
        return self.__m_website_id

    @property  # getter method
    def website_name(self) -> str:
        return self.__m_website_name

    @property  # getter method
    def scan_duration(self) -> str:
        return self.__m_scan_duration

    @property  # getter method
    def scan_scope(self) -> str:
        return self.__m_scan_scope

    @property  # getter method
    def scan_percentage(self) -> int:
        return self.__m_scan_percentage

    @property  # getter method
    def scan_state(self) -> str:
        return self.__m_scan_state

    @property  # getter method
    def scan_phase(self) -> str:
        return self.__m_scan_phase

    @property  # getter method
    def scan_failure_reason(self) -> str:
        return self.__m_scan_failure_reason

    @property  # getter method
    def scan_tags(self) -> str:
        return "|".join(self.__m_scan_tags)

    @property  # getter method
    def tags(self) -> str:
        if len(self.scan_profile_tags):
            return self.scan_profile_tags
        else:
            return self.scan_tags

    @property  # getter method
    def is_compliant(self) -> bool:
        if self.__m_total_vulnerability_count == 0:
            return True
        elif self.__m_vulnerability_critical_count == 0 and self.__m_vulnerability_high_count == 0 and self.__m_vulnerability_medium_count == 0:
            return True
        else:
            return False