from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum


class PhysicalMitigationStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PLATFORM_DEPENDENT = "platform_dependent"
    DOCUMENTED_NOT_APPLICABLE = "documented_not_applicable"


@dataclass
class PowerAnalysisConfig:
    random_delay_enabled: bool = True
    min_delay_ms: int = 1
    max_delay_ms: int = 5
    blinding_enabled: bool = True
    constant_power_mode_requested: bool = False


@dataclass
class ElectromagneticProtectionConfig:
    filtered_power_supply_required: bool = False
    shielded_environment_required: bool = False
    no_plaintext_on_external_devices: bool = True
    documentation_note: str = (
        "Electromagnetic emanation protection is a physical hardware-level "
        "control. CryptoSafe Manager documents the requirement and avoids "
        "plaintext export to external devices by default, but filtered power "
        "supplies and shielding must be provided by deployment environment."
    )


@dataclass
class PhysicalSecurityReport:
    power_random_delay: PhysicalMitigationStatus
    power_blinding: PhysicalMitigationStatus
    constant_power_mode: PhysicalMitigationStatus
    electromagnetic_filtering: PhysicalMitigationStatus
    electromagnetic_plaintext_policy: PhysicalMitigationStatus
    notes: list[str] = field(default_factory=list)


class PowerAnalysisMitigator:

    def __init__(self, config: PowerAnalysisConfig | None = None):
        self.config = config or PowerAnalysisConfig()
        self.config_validate()

    def config_validate(self) -> None:
        if self.config.min_delay_ms < 0:
            raise ValueError("min_delay_ms must be non-negative")

        if self.config.max_delay_ms < self.config.min_delay_ms:
            raise ValueError("max_delay_ms must be >= min_delay_ms")

    def random_delay(self) -> None:
        if not self.config.random_delay_enabled:
            return

        span = self.config.max_delay_ms - self.config.min_delay_ms + 1
        delay_ms = self.config.min_delay_ms + secrets.randbelow(span)
        time.sleep(delay_ms / 1000)

    def blind_bytes(self, data: bytes) -> tuple[bytes, bytes]:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        if not self.config.blinding_enabled:
            return data, b"\x00" * len(data)

        mask = os.urandom(len(data))
        blinded = bytes(a ^ b for a, b in zip(data, mask))
        return blinded, mask

    def unblind_bytes(self, blinded: bytes, mask: bytes) -> bytes:
        if len(blinded) != len(mask):
            raise ValueError("blinded data and mask must have equal length")

        return bytes(a ^ b for a, b in zip(blinded, mask))


class ElectromagneticEmanationPolicy:

    def __init__(self, config: ElectromagneticProtectionConfig | None = None):
        self.config = config or ElectromagneticProtectionConfig()

    def plaintext_external_export_allowed(self, explicit_user_approval: bool) -> bool:
        if self.config.no_plaintext_on_external_devices and not explicit_user_approval:
            return False

        return True

    def deployment_requirements(self) -> list[str]:
        requirements = []

        if self.config.filtered_power_supply_required:
            requirements.append("Use filtered power supply for critical sections.")

        if self.config.shielded_environment_required:
            requirements.append("Use shielded environment for high-risk deployments.")

        requirements.append(self.config.documentation_note)
        return requirements


class PhysicalSecurityManager:
    def __init__(
        self,
        power_config: PowerAnalysisConfig | None = None,
        em_config: ElectromagneticProtectionConfig | None = None,
    ):
        self.power = PowerAnalysisMitigator(power_config)
        self.em_policy = ElectromagneticEmanationPolicy(em_config)

    def report(self) -> PhysicalSecurityReport:
        return PhysicalSecurityReport(
            power_random_delay=PhysicalMitigationStatus.IMPLEMENTED,
            power_blinding=PhysicalMitigationStatus.IMPLEMENTED,
            constant_power_mode=PhysicalMitigationStatus.PLATFORM_DEPENDENT,
            electromagnetic_filtering=PhysicalMitigationStatus.DOCUMENTED_NOT_APPLICABLE,
            electromagnetic_plaintext_policy=PhysicalMitigationStatus.IMPLEMENTED,
            notes=self.em_policy.deployment_requirements(),
        )