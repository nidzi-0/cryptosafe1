from __future__ import annotations

import platform
from dataclasses import dataclass, field
from enum import Enum


class PlatformFeatureStatus(str, Enum):
    IMPLEMENTED = "implemented"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PLATFORM_DEPENDENT = "platform_dependent"
    DOCUMENTED = "documented"


@dataclass
class PlatformFeature:
    name: str
    status: PlatformFeatureStatus
    note: str


@dataclass
class PlatformSecurityReport:
    platform_name: str
    features: list[PlatformFeature] = field(default_factory=list)

    def feature_names(self) -> list[str]:
        return [feature.name for feature in self.features]

    def has_feature(self, name: str) -> bool:
        return name in self.feature_names()


class PlatformSecurityManager:

    def __init__(self, platform_name: str | None = None):
        self.platform_name = platform_name or platform.system()

    def get_report(self) -> PlatformSecurityReport:
        normalized = self.platform_name.lower()

        if normalized == "windows":
            return self._windows_report()

        if normalized == "darwin":
            return self._macos_report()

        if normalized == "linux":
            return self._linux_report()

        return PlatformSecurityReport(
            platform_name=self.platform_name,
            features=[
                PlatformFeature(
                    name="generic_secure_memory",
                    status=PlatformFeatureStatus.IMPLEMENTED,
                    note="Generic secure memory fallback is used.",
                )
            ],
        )

    def _windows_report(self) -> PlatformSecurityReport:
        return PlatformSecurityReport(
            platform_name="Windows",
            features=[
                PlatformFeature(
                    name="Credential Guard API",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Credential Guard is managed by Windows policy; app detects/document support.",
                ),
                PlatformFeature(
                    name="Windows Hello integration",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Bonus feature documented as platform-dependent.",
                ),
                PlatformFeature(
                    name="Secure Desktop for password entry",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Secure Desktop requires Windows-specific UI isolation; documented as platform policy.",
                ),
                PlatformFeature(
                    name="VirtualLock",
                    status=PlatformFeatureStatus.IMPLEMENTED,
                    note="Used by SecureMemory when available.",
                ),
            ],
        )

    def _macos_report(self) -> PlatformSecurityReport:
        return PlatformSecurityReport(
            platform_name="macOS",
            features=[
                PlatformFeature(
                    name="Touch ID integration",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Bonus feature documented as platform-dependent.",
                ),
                PlatformFeature(
                    name="Keychain Services",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Secure storage integration documented; fallback remains encrypted local vault.",
                ),
                PlatformFeature(
                    name="Gatekeeper notarization",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Deployment/build pipeline requirement documented.",
                ),
                PlatformFeature(
                    name="mlock",
                    status=PlatformFeatureStatus.IMPLEMENTED,
                    note="Used by SecureMemory when available.",
                ),
            ],
        )

    def _linux_report(self) -> PlatformSecurityReport:
        return PlatformSecurityReport(
            platform_name="Linux",
            features=[
                PlatformFeature(
                    name="kernel keyring service",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Kernel keyring integration documented as platform-dependent.",
                ),
                PlatformFeature(
                    name="systemd service management",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Background service integration documented for deployment.",
                ),
                PlatformFeature(
                    name="SELinux/AppArmor policies",
                    status=PlatformFeatureStatus.DOCUMENTED,
                    note="Mandatory access control profiles documented for deployment.",
                ),
                PlatformFeature(
                    name="mlock/MAP_LOCKED",
                    status=PlatformFeatureStatus.IMPLEMENTED,
                    note="Used by SecureMemory/MMapLockedBuffer when available.",
                ),
            ],
        )

    def secure_desktop_required(self) -> bool:
        return self.platform_name.lower() == "windows"

    def fail_secure_if_feature_missing(self, feature_available: bool) -> bool:
        return bool(feature_available)