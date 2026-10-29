"""
Configuration management for Cloud Posture Scanner.
Loads environment variables from .env if present.
"""
import os
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
HISTORY_DIR = DATA_DIR / "history"
HISTORY_DIR.mkdir(exist_ok=True)

# Initial load of .env file
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Application settings and AWS scanner configuration."""

    def __init__(self):
        self._custom_bucket: Optional[str] = None
        self._custom_profile: Optional[str] = None
        self._custom_region: Optional[str] = None
        self._custom_scan_regions: Optional[List[str]] = None
        self._custom_mock: Optional[bool] = None

    def reload(self):
        """Reloads settings from .env file."""
        load_dotenv(BASE_DIR / ".env", override=True)

    @property
    def AWS_PROFILE(self) -> str:
        if self._custom_profile is not None:
            return self._custom_profile
        return os.getenv("AWS_PROFILE", "")

    @AWS_PROFILE.setter
    def AWS_PROFILE(self, value: str):
        self._custom_profile = value.strip() if value else ""

    @AWS_PROFILE.deleter
    def AWS_PROFILE(self):
        self._custom_profile = None

    @property
    def AWS_ACCESS_KEY_ID(self) -> str:
        return os.getenv("AWS_ACCESS_KEY_ID", "")

    @property
    def AWS_SECRET_ACCESS_KEY(self) -> str:
        return os.getenv("AWS_SECRET_ACCESS_KEY", "")

    @property
    def AWS_SESSION_TOKEN(self) -> str:
        return os.getenv("AWS_SESSION_TOKEN", "")

    @property
    def AWS_DEFAULT_REGION(self) -> str:
        if self._custom_region is not None:
            return self._custom_region
        return os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "ap-south-1"))

    @AWS_DEFAULT_REGION.setter
    def AWS_DEFAULT_REGION(self, value: str):
        self._custom_region = value.strip() if value else None

    @AWS_DEFAULT_REGION.deleter
    def AWS_DEFAULT_REGION(self):
        self._custom_region = None

    @property
    def SCAN_REGIONS(self) -> List[str]:
        if self._custom_scan_regions is not None:
            return self._custom_scan_regions
        raw = os.getenv("AWS_SCAN_REGIONS", self.AWS_DEFAULT_REGION)
        parsed = [r.strip() for r in raw.split(",") if r.strip()]
        return parsed if parsed else [self.AWS_DEFAULT_REGION]

    @SCAN_REGIONS.setter
    def SCAN_REGIONS(self, value: List[str]):
        self._custom_scan_regions = value

    @SCAN_REGIONS.deleter
    def SCAN_REGIONS(self):
        self._custom_scan_regions = None

    @property
    def AWS_POSTURE_BUCKET(self) -> str:
        if self._custom_bucket is not None:
            return self._custom_bucket
        return os.getenv("AWS_POSTURE_BUCKET", "")

    @AWS_POSTURE_BUCKET.setter
    def AWS_POSTURE_BUCKET(self, value: str):
        self._custom_bucket = value.strip() if value else ""

    @AWS_POSTURE_BUCKET.deleter
    def AWS_POSTURE_BUCKET(self):
        self._custom_bucket = None

    @property
    def USE_MOCK(self) -> bool:
        if self._custom_mock is not None:
            return self._custom_mock
        return os.getenv("USE_MOCK", "false").lower() in ("true", "1", "yes")

    @USE_MOCK.setter
    def USE_MOCK(self, value: bool):
        self._custom_mock = bool(value)

    @USE_MOCK.deleter
    def USE_MOCK(self):
        self._custom_mock = None

    # Server configuration
    @property
    def HOST(self) -> str:
        return os.getenv("HOST", "0.0.0.0")

    @property
    def PORT(self) -> int:
        return int(os.getenv("PORT", "8000"))

    APP_NAME: str = "Cloud Posture Scanner"
    APP_VERSION: str = "1.0.0"

    # Local development storage paths
    DATA_PATH: Path = DATA_DIR
    LATEST_REPORT_FILE: Path = DATA_DIR / "latest_scan.json"
    HISTORY_PATH: Path = HISTORY_DIR


settings = Settings()
