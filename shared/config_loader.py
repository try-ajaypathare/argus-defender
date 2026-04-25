"""
Config loader for Argus.
Parses config.yaml into a typed Pydantic model.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


class AppSettings(BaseModel):
    name: str = "Argus"
    version: str = "1.0.0"
    environment: str = "development"
    log_level: str = "INFO"


class MonitoringSettings(BaseModel):
    interval_seconds: int = 5
    retention_days: int = 30
    warmup_samples: int = 3


class ThresholdRule(BaseModel):
    warning: float
    critical: float
    sustained_seconds: int = 0


class NetworkThresholds(BaseModel):
    connection_warning: int = 100
    connection_critical: int = 300


class ProcessThresholds(BaseModel):
    warning: int = 300
    critical: int = 500


class ThresholdsSettings(BaseModel):
    cpu: ThresholdRule
    memory: ThresholdRule
    disk: ThresholdRule
    processes: ProcessThresholds
    network: NetworkThresholds


class ActionsSettings(BaseModel):
    auto_kill_enabled: bool = True
    auto_clear_temp: bool = True
    kill_confirmation_required: bool = False
    cooldown_seconds: int = 30
    ai_advisor_enabled: bool = True
    ai_verify_after_action: bool = True


class AISettings(BaseModel):
    enabled: bool = True
    engine: str = "isolation_forest"
    auto_retrain_hours: int = 72
    min_samples_for_training: int = 1000
    anomaly_threshold: float = 0.7
    contamination: float = 0.05
    use_shap_explanations: bool = True


class SecuritySettings(BaseModel):
    process_genealogy: bool = True
    network_watcher: bool = True
    file_integrity: bool = True
    registry_watcher: bool = True
    usb_monitor: bool = True
    watched_folders: list[str] = Field(default_factory=list)
    suspicious_ports: list[int] = Field(default_factory=list)
    suspicious_chains: list[list[str]] = Field(default_factory=list)


class DashboardsSettings(BaseModel):
    defender_port: int = 8000
    attacker_port: int = 8001
    host: str = "127.0.0.1"
    auth_enabled: bool = False
    auth_token: str = "change-me"


class AttacksSettings(BaseModel):
    max_duration_seconds: int = 300
    max_ram_mb: int = 2000
    max_disk_mb: int = 1000
    max_cpu_cores: int = 4
    max_threads: int = 500
    max_sockets: int = 500
    max_file_handles: int = 500
    max_processes_fork_bomb: int = 30
    kill_switch_hotkey: str = "ctrl+shift+q"
    workspace_folder: str = "attacker/attack_workspace"


class TelegramSettings(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


class DiscordSettings(BaseModel):
    enabled: bool = False
    webhook_url: str = ""


class EmailSettings(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    recipients: list[str] = Field(default_factory=list)


class NotificationsSettings(BaseModel):
    windows_toast: bool = True
    console_output: bool = True
    log_file: str = "logs/argus.log"
    telegram: TelegramSettings = TelegramSettings()
    discord: DiscordSettings = DiscordSettings()
    email: EmailSettings = EmailSettings()


class FeedbackSettings(BaseModel):
    enabled: bool = True
    min_feedback_for_retrain: int = 20


class ArgusConfig(BaseModel):
    app: AppSettings
    monitoring: MonitoringSettings
    thresholds: ThresholdsSettings
    actions: ActionsSettings
    safety_list: list[str] = Field(default_factory=list)
    ai: AISettings
    security: SecuritySettings
    dashboards: DashboardsSettings
    attacks: AttacksSettings
    notifications: NotificationsSettings
    feedback: FeedbackSettings


_cached: ArgusConfig | None = None


def load_config(force_reload: bool = False) -> ArgusConfig:
    global _cached
    if _cached is not None and not force_reload:
        return _cached

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    _cached = ArgusConfig(**raw)
    return _cached


def get_config() -> ArgusConfig:
    return load_config()
