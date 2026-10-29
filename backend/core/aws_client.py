"""
AWS Session and Client Manager.
Handles authentication, credential resolution, connectivity testing, and client provisioning.
Seamlessly falls back to mock mode when credentials are missing or invalid.
"""
import os
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import boto3
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    EndpointConnectionError,
    ProfileNotFound,
)
from backend.config import settings

logger = logging.getLogger("cloud_posture.aws_client")


class AWSClientManager:
    """Manages Boto3 sessions, STS verification, and client instantiation."""

    def __init__(self):
        self._session: Optional[boto3.Session] = None
        self._custom_credentials: Optional[Dict[str, str]] = None
        self._cached_account_id: Optional[str] = None
        self._cached_arn: Optional[str] = None
        self._forced_mock: Optional[bool] = None
        self._cached_verify_result: Optional[Tuple[bool, str, Optional[str]]] = None

    def reset_session(self):
        """Clears cached session and verification state."""
        self._session = None
        self._cached_account_id = None
        self._cached_arn = None
        self._cached_verify_result = None

    def set_custom_credentials(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
        use_mock: Optional[bool] = None,
    ):
        """Allows dynamic configuration of AWS credentials at runtime."""
        self.reset_session()

        if use_mock is not None:
            self._forced_mock = use_mock

        if access_key and secret_key:
            self._custom_credentials = {
                "aws_access_key_id": access_key.strip(),
                "aws_secret_access_key": secret_key.strip(),
                "aws_session_token": session_token.strip() if session_token else None,
                "region_name": region.strip() if region else settings.AWS_DEFAULT_REGION,
            }
            self._custom_credentials = {
                k: v for k, v in self._custom_credentials.items() if v is not None
            }
            self._forced_mock = False

    def force_mock_mode(self, enabled: bool = True):
        """Forces the scanner into offline simulation mode."""
        self._forced_mock = enabled
        self.reset_session()

    def has_configured_credentials(self) -> bool:
        """
        Fast check to see if AWS credentials exist locally before attempting network calls.
        Supports:
        - Named CLI profile (AWS_PROFILE)
        - Environment variables (AWS_ACCESS_KEY_ID, AWS_CONTAINER_CREDENTIALS_*, etc.)
        - ~/.aws/credentials or ~/.aws/config
        """
        if self._custom_credentials and self._custom_credentials.get("aws_access_key_id"):
            return True
        if settings.AWS_PROFILE:
            return True
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            return True
        if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
            return True
        if os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
            return True
        if os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"):
            return True
        aws_dir = Path.home() / ".aws"
        if (aws_dir / "credentials").exists() or (aws_dir / "config").exists():
            return True
        return False

    def is_mock_mode(self) -> bool:
        """Determines if the scanner should operate in mock simulation mode."""
        if self._forced_mock is True:
            return True
        if self._forced_mock is False:
            return False
        if settings.USE_MOCK:
            return True
        if not self.has_configured_credentials():
            return True
        connected, _, _ = self.verify_credentials()
        return not connected

    def get_session(self) -> boto3.Session:
        """Creates or returns the active Boto3 session using standard credential chain."""
        if self._session is not None:
            return self._session

        if self._custom_credentials:
            self._session = boto3.Session(**self._custom_credentials)
            return self._session

        kwargs: Dict[str, Any] = {}
        if settings.AWS_PROFILE:
            kwargs["profile_name"] = settings.AWS_PROFILE
        elif settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
            if settings.AWS_SESSION_TOKEN:
                kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN

        if settings.AWS_DEFAULT_REGION:
            kwargs["region_name"] = settings.AWS_DEFAULT_REGION

        try:
            self._session = boto3.Session(**kwargs)
        except ProfileNotFound as e:
            logger.error(f"AWS CLI profile '{settings.AWS_PROFILE}' not found: {e}")
            # Fall back to default session
            self._session = boto3.Session(region_name=settings.AWS_DEFAULT_REGION)

        return self._session

    def verify_credentials(self, force_refresh: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Tests connection to AWS using STS GetCallerIdentity.
        Returns: (is_connected: bool, message: str, account_id: Optional[str])
        """
        if not force_refresh and self._cached_verify_result is not None:
            return self._cached_verify_result

        if self._forced_mock is True:
            self._cached_verify_result = (False, "Simulation mode enabled by user or configuration.", "123456789012")
            return self._cached_verify_result

        if not self.has_configured_credentials():
            self._cached_verify_result = (False, "No AWS credentials found on host. Simulation mode active.", "123456789012")
            return self._cached_verify_result

        try:
            session = self.get_session()
            sts = session.client("sts", region_name=settings.AWS_DEFAULT_REGION)
            identity = sts.get_caller_identity()
            account_id = identity.get("Account")
            arn = identity.get("Arn")
            self._cached_account_id = account_id
            self._cached_arn = arn
            msg = f"Connected to AWS as {arn} (Account: {account_id})"
            self._cached_verify_result = (True, msg, account_id)
            return self._cached_verify_result
        except (NoCredentialsError, PartialCredentialsError) as e:
            self._cached_verify_result = (False, f"AWS credentials not configured or incomplete: {e}", None)
            return self._cached_verify_result
        except ProfileNotFound as e:
            self._cached_verify_result = (False, f"AWS CLI profile not found: {e}", None)
            return self._cached_verify_result
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            self._cached_verify_result = (False, f"AWS Authentication failed ({code}): {msg}", None)
            return self._cached_verify_result
        except EndpointConnectionError as e:
            self._cached_verify_result = (False, f"Could not connect to AWS endpoints (offline or network error): {e}", None)
            return self._cached_verify_result
        except Exception as e:
            self._cached_verify_result = (False, f"Unexpected error checking AWS credentials: {e}", None)
            return self._cached_verify_result

    def get_client(self, service_name: str, region_name: Optional[str] = None):
        """Returns a Boto3 service client for the requested service and region."""
        session = self.get_session()
        region = region_name or settings.AWS_DEFAULT_REGION
        return session.client(service_name, region_name=region)

    def get_account_id(self) -> str:
        """Returns the connected AWS account ID, or the simulation default."""
        if self._cached_account_id:
            return self._cached_account_id
        connected, _, account_id = self.verify_credentials()
        if connected and account_id:
            return account_id
        return "123456789012"  # Demo account fallback

    def get_arn(self) -> Optional[str]:
        """Returns the connected IAM ARN."""
        return self._cached_arn


# Global singleton instance
aws_manager = AWSClientManager()
