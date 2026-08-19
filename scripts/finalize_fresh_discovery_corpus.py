#!/usr/bin/env python3
"""Freeze the preselected Fresh Discovery ELF corpus and its provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


PROJECTS: dict[str, dict[str, Any]] = {
    "contiki": {
        "name": "Contiki-NG",
        "release": "release/v5.1",
        "commit": "2b87baf3ebdde3c8e37ca791d2bc84bfd76c49a4",
        "acquisition": "F2",
        "url": "https://github.com/contiki-ng/contiki-ng/releases/tag/release%2Fv5.1",
        "target_input": "CC2538 / Contiki-NG / IEEE 802.15.4, IPv6, UDP, CoAP, or serial",
        "real_application": True,
        "ids": [
            "6tisch-6p", "6tisch-channel-selection", "6tisch-custom-schedule",
            "6tisch-etsi-plugtest", "6tisch-simple-node", "6tisch-sixtop",
            "6tisch-timesync", "6tisch-tsch-stats", "coap-client",
            "coap-server", "coap-plugtest", "mqtt-client", "multicast-root",
            "multicast-intermediate", "multicast-sink", "nullnet-unicast",
            "nullnet-broadcast", "rpl-border-router", "rpl-udp-client",
            "rpl-udp-server", "sensniff", "slip-radio", "snmp-server",
            "websocket-http", "websocket-client",
        ],
    },
    "riot": {
        "name": "RIOT",
        "release": "2026.04.01",
        "commit": "4a70282b1f1ac6e004138b4ada684a4dc4639653",
        "acquisition": "F2",
        "url": "https://github.com/RIOT-OS/RIOT/releases/tag/2026.04.01",
        "target_input": "CC2538 / RIOT / IEEE 802.15.4, IPv6, UDP, CoAP, MQTT, or UART",
        "real_application": True,
        "ids": [
            "basic-default", "guide-coap-client", "guide-coap-server",
            "coap-gcoap", "coap-block-server", "coap-dtls", "coap-fileserver",
            "coap-nanocoap-server", "coap-unicoap", "cord-endpoint",
            "cord-endpoint-sim", "cord-location-client", "dtls-echo", "dtls-sock",
            "gnrc-border-router", "gnrc-minimal", "gnrc-networking",
            "gnrc-networking-subnets", "benchmark-udp", "posix-sockets",
            "sock-tcp-echo", "telnet-server", "mqtt-asymcute", "mqtt-emcute",
            "mqtt-paho",
        ],
    },
    "zephyr": {
        "name": "Zephyr",
        "release": "v4.4.1",
        "commit": "1f6485eca25431b5ff27ce9a754218c9e559bbbb",
        "acquisition": "F2",
        "url": "https://github.com/zephyrproject-rtos/zephyr/releases/tag/v4.4.1",
        "target_input": "nRF52840 / Zephyr / BLE",
        "real_application": False,
        "ids": [
            "beacon", "broadcaster", "broadcaster-multiple", "central",
            "central-gatt-write", "central-hr", "central-ht", "central-multilink",
            "direct-adv", "eddystone", "encrypted-adv-central",
            "encrypted-adv-peripheral", "extended-adv-advertiser",
            "extended-adv-scanner", "ibeacon", "l2cap-coc-acceptor",
            "l2cap-coc-initiator", "observer", "periodic-adv", "periodic-sync",
            "peripheral", "peripheral-gatt-write", "peripheral-hr", "peripheral-ht",
            "scan-adv",
        ],
    },
    "nuttx": {
        "name": "Apache NuttX",
        "release": "nuttx-13.0.0",
        "commit": "273c77128b6698f0c95f0d7cde1d0bb803782021",
        "apps_commit": "20ffb1a3a3b590d52890ee865a28442390e5d16c",
        "acquisition": "F2",
        "url": "https://github.com/apache/nuttx/releases/tag/nuttx-13.0.0",
        "target_input": "STM32F4 / NuttX / UART, Ethernet, USB, SPI, CAN, or sensor input",
        "real_application": False,
        "ids": [
            "stm32f4discovery-nsh", "stm32f4discovery-netnsh",
            "stm32f4discovery-ipv6", "stm32f4discovery-ether_w5500",
            "stm32f4discovery-wifi", "stm32f4discovery-rndis",
            "stm32f4discovery-usbnsh", "stm32f4discovery-usbmsc",
            "stm32f4discovery-composite", "stm32f4discovery-adb",
            "stm32f4discovery-modbus_slave", "stm32f4discovery-canard",
            "stm32f4discovery-audio", "stm32f4discovery-mmcsdspi",
            "stm32f4discovery-pseudoterm", "stm32f4discovery-nxscope_cdcacm",
            "stm32f4discovery-st7789", "stm32f4discovery-st7567",
            "stm32f4discovery-lcd1602", "stm32f4discovery-max31855",
            "stm32f4discovery-max7219", "stm32f4discovery-mpr121_keypad",
            "stm32f4discovery-sbutton", "stm32f4discovery-mt6816",
            "stm32f4discovery-xen1210",
        ],
    },
    "mbed": {
        "name": "Mbed CE BLE Examples",
        "release": "main@70af9b9",
        "commit": "70af9b97958f682e2b79c7f26db22e3fe839134d",
        "mbed_os_commit": "7fd6fdd79f977815fc78a2d2e8adf9e0dda20638",
        "acquisition": "F3",
        "url": "https://github.com/mbed-ce/mbed-os-example-ble",
        "target_input": "nRF52840 / Mbed CE / BLE",
        "real_application": True,
        "ids": [
            "ble-advertising", "ble-gap", "ble-gattclient-characteristicupdates",
            "ble-gattclient-characteristicwrite", "ble-gattserver-addservice",
            "ble-gattserver-characteristicupdates",
            "ble-gattserver-experimentalservices", "ble-periodicadvertising",
            "ble-securityandprivacy", "ble-supportedfeatures",
        ],
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_arm_elf(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, "missing_build_output"
    proc = subprocess.run(
        ["readelf", "-h", str(path)], text=True, capture_output=True
    )
    if proc.returncode != 0:
        return False, "readelf_failed"
    if "ELF32" not in proc.stdout or "Machine:" not in proc.stdout:
        return False, "not_complete_elf"
    if "ARM" not in proc.stdout:
        return False, "not_arm_elf"
    return True, ""


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--import-root",
        type=Path,
        default=ROOT / "datasets/imported/fresh_discovery_v1",
    )
    parser.add_argument(
        "--build-log-root",
        type=Path,
        default=ROOT / "artifacts/fresh_discovery_v1_build/logs",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=ROOT / "datasets/fresh_discovery_candidates.v1.json",
    )
    parser.add_argument(
        "--selection",
        type=Path,
        default=ROOT / "datasets/fresh_discovery_selection.v1.json",
    )
    parser.add_argument(
        "--table",
        type=Path,
        default=ROOT / "docs/FRESH_DISCOVERY_CORPUS_V1.md",
    )
    args = parser.parse_args()

    rows: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    hash_owner: dict[str, str] = {}
    project_success = Counter()
    real_app_success = 0

    for project_id, project in PROJECTS.items():
        for image_id in project["ids"]:
            binary = args.import_root / project_id / f"{image_id}.elf"
            valid, reason = is_arm_elf(binary)
            binary_hash = sha256(binary) if valid else ""
            duplicate_of = hash_owner.get(binary_hash, "") if binary_hash else ""
            if binary_hash and not duplicate_of:
                hash_owner[binary_hash] = f"fresh_{project_id}_{image_id}"
            status = "ELIGIBLE" if valid and not duplicate_of else "BUILD_FAILED"
            if duplicate_of:
                status = "DUPLICATE_ELF"
                reason = "duplicate_sha256"
            sample_id = f"fresh_{project_id}_{image_id}"
            row = {
                "sample_id": sample_id,
                "project_id": project_id,
                "project": project["name"],
                "release": project["release"],
                "commit": project["commit"],
                "acquisition": project["acquisition"],
                "official_url": project["url"],
                "target_input": project["target_input"],
                "real_application": bool(project["real_application"]),
                "status": status,
                "failure_reason": reason,
                "duplicate_of": duplicate_of,
                "binary_path": str(binary.resolve()) if binary.exists() else str(binary),
                "binary_sha256": binary_hash,
                "build_log": str(
                    (args.build_log_root / project_id / f"{image_id}.log").resolve()
                ),
                "freshness_internal": "NOT_ASSESSED_FOR_EXACT_IMAGE",
            }
            rows.append(row)
            if status == "ELIGIBLE":
                project_success[project_id] += 1
                if project["real_application"]:
                    real_app_success += 1
                selected.append(
                    {
                        "sample_id": sample_id,
                        "provider": project["acquisition"],
                        "project_id": project_id,
                        "release": project["release"],
                        "binary_path": str(binary.resolve()),
                        "binary_sha256": binary_hash,
                        "target_input": project["target_input"],
                    }
                )

    total = len(selected)
    max_share = max(project_success.values(), default=0) / max(total, 1)
    gates = {
        "unique_elfs_gt_100": total > 100,
        "projects_at_least_5": len(project_success) >= 5,
        "project_share_at_most_25_percent": max_share <= 0.25,
        "real_applications_at_least_40": real_app_success >= 40,
        "all_selected_are_unique_arm_elf": len(hash_owner) == total,
    }
    catalog = {
        "schema_version": "ct-mini-fresh-acquisition-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selection_policy": "predeclared application list; build failures retained; no CopperTrace output consulted",
        "candidate_count": len(rows),
        "eligible_unique_elfs": total,
        "project_success": dict(sorted(project_success.items())),
        "real_application_elfs": real_app_success,
        "maximum_project_share": max_share,
        "gates": gates,
        "candidates": rows,
    }
    selection = {
        "schema_version": "ct-mini-fresh-selection-v1",
        "description": "Frozen fresh ARM Cortex-M Monolithic firmware ELF selection.",
        "selection_policy": catalog["selection_policy"],
        "catalog": str(args.catalog.resolve()),
        "samples": selected,
    }
    write_json(args.catalog, catalog)
    write_json(args.selection, selection)

    table = [
        "# Fresh Discovery Corpus v1",
        "",
        f"Eligible unique ELF images: **{total}**",
        "",
        "| Firmware | Acquisition | Target/Input |",
        "|---|---|---|",
    ]
    for project_id, count in sorted(project_success.items()):
        project = PROJECTS[project_id]
        table.append(
            f"| {project['name']} {project['release']} ({count} ELFs) "
            f"| {project['acquisition']} + {project['url']} "
            f"| {project['target_input']} |"
        )
    table.extend(
        [
            "",
            "Build failures and duplicate hashes remain in `fresh_discovery_candidates.v1.json`.",
            "The selection was frozen before CopperTrace analysis.",
            "",
        ]
    )
    args.table.parent.mkdir(parents=True, exist_ok=True)
    args.table.write_text("\n".join(table))
    print(json.dumps({"eligible_unique_elfs": total, "gates": gates, "project_success": dict(project_success)}, indent=2))
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
