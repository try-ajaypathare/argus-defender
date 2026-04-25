"""
Attack registry — 10 curated simulations that each demonstrate a distinct pattern.

All attacks are PURE SIMULATION. They register impact with the SimulationEngine;
no real resources are consumed.
"""
from __future__ import annotations

from typing import Type

from attacker.base_attack import BaseAttack
from attacker.attacks.cpu_spike import CPUSpike
from attacker.attacks.ram_flood import RAMFlood
from attacker.attacks.disk_fill import DiskFill
from attacker.attacks.traffic_flood import TrafficFlood
from attacker.attacks.combo import ComboAttack
from attacker.attacks.fork_bomb import ForkBomb
from attacker.attacks.slow_creep import SlowCreep
from attacker.attacks.memory_leak import MemoryLeak
from attacker.attacks.cryptomining_sim import CryptominingSim
from attacker.attacks.ransomware_sim import RansomwareSim


REGISTRY: dict[str, Type[BaseAttack]] = {
    # Direct resource attacks
    "cpu_spike":      CPUSpike,
    "ram_flood":      RAMFlood,
    "disk_fill":      DiskFill,
    "traffic_flood":  TrafficFlood,
    # Mixed
    "combo":          ComboAttack,
    # Resource exhaustion
    "fork_bomb":      ForkBomb,
    # AI-evasion tests
    "slow_creep":     SlowCreep,
    "memory_leak":    MemoryLeak,
    # Real-world malware simulations
    "cryptomining_sim": CryptominingSim,
    "ransomware_sim":   RansomwareSim,
}


def get_attack_list() -> list[dict]:
    return [
        {
            "type": key,
            "name": cls.name,
            "category": cls.category,
            "description": cls.description,
        }
        for key, cls in REGISTRY.items()
    ]
