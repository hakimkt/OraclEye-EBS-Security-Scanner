"""
Plugin Registry - Central registry for all scanner modules.
Add new vulnerability checks by creating a class in scanner/plugins/
and registering it here, or use auto-discovery.
"""

import importlib
import pkgutil
import os
import sys


class PluginRegistry:
    _plugins = {}

    def __init__(self):
        self._discover_plugins()

    def _discover_plugins(self):
        plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
        if not os.path.exists(plugins_dir):
            return
        sys.path.insert(0, os.path.dirname(__file__))
        for _, module_name, _ in pkgutil.iter_modules([plugins_dir]):
            try:
                mod = importlib.import_module(f"scanner.plugins.{module_name}")
                for attr_name in dir(mod):
                    cls = getattr(mod, attr_name)
                    if (isinstance(cls, type) and
                            hasattr(cls, "PLUGIN_ID") and
                            hasattr(cls, "run") and
                            cls.__name__ != "BasePlugin"):
                        self._plugins[cls.PLUGIN_ID] = cls
            except Exception as e:
                print(f"[registry] Failed to load plugin {module_name}: {e}")

    def list_plugins(self):
        return [
            {
                "id": cls.PLUGIN_ID,
                "name": cls.PLUGIN_NAME,
                "description": cls.PLUGIN_DESC,
                "category": cls.CATEGORY,
                "min_intrusivity": cls.MIN_INTRUSIVITY,
                "cve_refs": getattr(cls, "CVE_REFS", []),
                "severity": getattr(cls, "BASE_SEVERITY", "medium"),
            }
            for cls in self._plugins.values()
        ]

    def get_plugins_for_intrusivity(self, level, selected=None):
        order = ["passive", "low", "medium", "aggressive"]
        level_idx = order.index(level) if level in order else 0
        result = []
        for cls in self._plugins.values():
            min_idx = order.index(cls.MIN_INTRUSIVITY) if cls.MIN_INTRUSIVITY in order else 0
            if min_idx <= level_idx:
                if selected is None or cls.PLUGIN_ID in selected:
                    result.append(cls)
        return result

    def get(self, plugin_id):
        return self._plugins.get(plugin_id)
