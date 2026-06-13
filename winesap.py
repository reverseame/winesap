#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Winesap - Volatility 3 plugin
#
# Searches for all Autostart Extensibility Points (ASEPs): the subset of OS and
# application extensibility points that allow a program to auto-start without
# any explicit user invocation. This is the Volatility 3 port of the original
# Volatility 2 plugin.
#
# Licensed under the GNU AGPLv3 license.
import logging
import re
from typing import Iterator, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry as registry_layer
from volatility3.framework.symbols.windows.extensions import registry
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class Winesap(interfaces.plugins.PluginInterface):
    """Search for all Autostart Extensibility Points (ASEPs)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # Path components that, combined with a file extension, flag a value as a
    # suspicious persistence location.
    _SUSPICIOUS_PATHS = ["AppData", "Roaming", "Temp", "Application Data"]

    _STRING_TYPES = (
        registry.RegValueTypes.REG_SZ,
        registry.RegValueTypes.REG_EXPAND_SZ,
        registry.RegValueTypes.REG_LINK,
        registry.RegValueTypes.REG_MULTI_SZ,
    )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="match",
                description="Only show suspicious entries",
                default=False,
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------ #
    # Hive helpers                                                        #
    # ------------------------------------------------------------------ #

    def _all_hives(self) -> List[registry_layer.RegistryHive]:
        """Enumerate every hive exactly once.

        ``list_hives`` constructs (and registers in the context) a layer per
        hive, so it must be called a single time; calling it again would try to
        recreate existing layers and raise "Layer already exists". We cache the
        result and filter it by basename in memory instead.
        """
        return list(
            hivelist.HiveList.list_hives(
                context=self.context,
                base_config_path=self.config_path,
                kernel_module_name=self.config["kernel"],
            )
        )

    @staticmethod
    def _hives_by_basename(
        hives: List[registry_layer.RegistryHive], basename: str
    ) -> Iterator[registry_layer.RegistryHive]:
        """Yield hives whose file name (last path component) matches
        ``basename`` case-insensitively.

        Matching on the basename rather than a substring of the full path
        avoids false matches such as the ``SOFTWARE`` hive (stored under
        ``...\\System32\\Config\\SOFTWARE``) when looking for ``SYSTEM``.
        """
        target = basename.casefold()
        for hive in hives:
            name = (hive.get_name() or "").replace("/", "\\")
            if name.split("\\")[-1].casefold() == target:
                yield hive

    @staticmethod
    def _get_key(
        hive: registry_layer.RegistryHive, key_path: str
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Return the key node at ``key_path`` in ``hive`` or ``None``."""
        try:
            return hive.get_key(key_path)
        except (
            KeyError,
            registry_layer.RegistryException,
            exceptions.InvalidAddressException,
        ) as excp:
            vollog.debug(f"Key '{key_path}' unavailable in {hive.get_name()}: {excp}")
            return None

    @staticmethod
    def _hkcu_root(hive: registry_layer.RegistryHive) -> str:
        """Build a per-user HKCU label from the NTUSER.DAT path so entries from
        different user profiles are distinguishable."""
        parts = [p for p in (hive.get_name() or "").replace("/", "\\").split("\\") if p]
        user = parts[-2] if len(parts) >= 2 else "?"
        return f"HKCU [{user}]\\"

    # ------------------------------------------------------------------ #
    # ASEP locations                                                      #
    # ------------------------------------------------------------------ #

    def _locations(
        self,
    ) -> Iterator[Tuple[str, str, Optional[List[str]], interfaces.objects.ObjectInterface]]:
        """Yield ``(root_label, key_path, value_filter, key_node)`` for every
        ASEP location. ``value_filter`` restricts which value names are
        reported (``None`` means all values)."""

        hives = self._all_hives()

        # --- HKCU: one NTUSER.DAT per user profile, scan them all --------
        hkcu_simple = [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ]
        hkcu_runonceex = [
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        ]
        for hive in self._hives_by_basename(hives, "ntuser.dat"):
            root = self._hkcu_root(hive)
            for path in hkcu_simple:
                key = self._get_key(hive, path)
                if key:
                    yield (root, path, None, key)
            for path in hkcu_runonceex:
                yield from self._subkeys(hive, root, path, None)

        # --- HKLM\Software ----------------------------------------------
        for hive in self._hives_by_basename(hives, "software"):
            root = "HKLM\\Software\\"
            for path in [
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]:
                key = self._get_key(hive, path)
                if key:
                    yield (root, path, None, key)
            yield from self._subkeys(
                hive, root, "Microsoft\\Windows\\CurrentVersion\\RunOnceEx", ["RunMyApp"]
            )
            yield from self._subkeys(
                hive, root, "Microsoft\\Active Setup\\Installed Components", ["StubPath"]
            )
            yield from self._subkeys(
                hive,
                root,
                "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                ["Debugger"],
            )
            winlogon = self._get_key(
                hive, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
            )
            if winlogon:
                yield (
                    root,
                    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    ["Shell", "Userinit"],
                    winlogon,
                )
            for path in [
                "Microsoft\\Windows NT\\CurrentVersion\\Windows",
                "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            ]:
                key = self._get_key(hive, path)
                if key:
                    yield (root, path, ["AppInit_DLLs"], key)

        # --- HKLM\System: services --------------------------------------
        for hive in self._hives_by_basename(hives, "system"):
            root = "HKLM\\System\\"
            services = self._get_key(hive, "CurrentControlSet\\Services")
            base = "CurrentControlSet\\Services"
            if services is None:
                services = self._get_key(hive, "ControlSet001\\Services")
                base = "ControlSet001\\Services"
            if services:
                for sub in services.get_subkeys():
                    yield (root, f"{base}\\{self._name(sub)}", ["ImagePath"], sub)

    def _subkeys(
        self,
        hive: registry_layer.RegistryHive,
        root: str,
        key_path: str,
        value_filter: Optional[List[str]],
    ) -> Iterator[Tuple[str, str, Optional[List[str]], interfaces.objects.ObjectInterface]]:
        """Yield a location tuple for each subkey of ``key_path`` (one level
        down), as several ASEPs (RunOnceEx, services, IFEO, ...) store their
        entries one key below the anchor."""
        key = self._get_key(hive, key_path)
        if key is None:
            return
        for sub in key.get_subkeys():
            yield (root, f"{key_path}\\{self._name(sub)}", value_filter, sub)

    # ------------------------------------------------------------------ #
    # Value evaluation                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _name(node: interfaces.objects.ObjectInterface) -> str:
        try:
            return str(node.get_name())
        except (exceptions.InvalidAddressException, registry_layer.RegistryException):
            return "-"

    def _evaluate(
        self, value: interfaces.objects.ObjectInterface
    ) -> Tuple[str, str, List[str]]:
        """Return ``(type_name, display_value, reasons)`` for a value node."""
        try:
            vtype = registry.RegValueTypes(value.Type)
            type_name = vtype.name
        except (ValueError, exceptions.InvalidAddressException):
            return "REG_UNKNOWN", "", []

        try:
            raw = value.decode_data()
        except (
            ValueError,
            exceptions.InvalidAddressException,
            registry_layer.RegistryException,
        ) as excp:
            # Data unreadable (e.g. paged out); report the entry without data.
            vollog.debug(excp)
            return type_name, "", []

        if isinstance(raw, int):
            return type_name, str(raw), []
        if vtype in self._STRING_TYPES:
            text = " ".join(
                p for p in raw.decode("utf-16-le", errors="replace").split("\x00") if p
            )
            return type_name, text, self.is_string_suspicious(text)
        if vtype in (registry.RegValueTypes.REG_BINARY, registry.RegValueTypes.REG_NONE):
            return type_name, self._hex_preview(raw), self.is_bin_suspicious(raw)
        return type_name, self._hex_preview(raw), []

    @staticmethod
    def _hex_preview(data: bytes, length: int = 0x40) -> str:
        if not data:
            return ""
        return " ".join("{:02x}".format(b) for b in data[:length])

    def is_string_suspicious(self, string: str) -> List[str]:
        ret: List[str] = []
        if not string:
            return ret

        paths = "|".join(self._SUSPICIOUS_PATHS)
        if re.search(r".+\\(%s).+\..+" % paths, string, flags=re.IGNORECASE):
            ret.append("Suspicious path file")

        if re.search(r'.*regsvr32\.exe /s (?!(\\/:*?"<>|)).+:.+', string, flags=re.IGNORECASE):
            ret.append("Suspicious Alternate Data Stream (ADS)")

        if re.search(r'.*rundll32\.exe (?!(\\/:*?"<>|)).+:.+', string, flags=re.IGNORECASE):
            ret.append("Suspicious Alternate Data Stream (ADS)")

        if re.search(r".*rundll32\.exe.+shell32\.dll.*", string, flags=re.IGNORECASE):
            ret.append("Suspicious shell execution")

        return ret

    def is_bin_suspicious(self, data: bytes) -> List[str]:
        if self.is_pe(data):
            return ["Suspicious PE file"]
        return []

    @staticmethod
    def is_pe(data: bytes) -> bool:
        try:
            if data[:0x2] == b"\x4d\x5a":  # MZ
                pe_offset = data[0x3c]  # bytes index yields an int in Python 3
                if data[pe_offset:pe_offset + 0x2] == b"\x50\x45":  # PE
                    return True
        except (IndexError, TypeError):
            pass
        return False

    # ------------------------------------------------------------------ #
    # Output                                                              #
    # ------------------------------------------------------------------ #

    def _generator(self):
        match_only = self.config.get("match", False)

        for root, key_path, value_filter, key_node in self._locations():
            try:
                values = list(key_node.get_values())
            except (
                exceptions.InvalidAddressException,
                registry_layer.RegistryException,
            ) as excp:
                vollog.debug(excp)
                continue

            for value in values:
                name = self._name(value) or "(Default)"
                if value_filter and name not in value_filter:
                    continue
                type_name, display, reasons = self._evaluate(value)
                if match_only and not reasons:
                    continue
                yield (
                    0,
                    (type_name, name, root + key_path, display, ", ".join(reasons)),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("RegType", str),
                ("RegName", str),
                ("RegKey", str),
                ("RegValue", str),
                ("Warning", str),
            ],
            self._generator(),
        )
