## Winesap - Volatility Plugin

`Winesap` for Volatility 3 aims to search for all Autostart Extensibility Points (AESPs), the subset of OS and application extensibility points that allow a program to auto-start without any explicit user invocation.

> This is the Volatility 3 port. The Volatility 2.6 version lives on the `volatility2-latest` branch.

Specifically, it tries to search AESPs according to this taxonomy:

![Taxonomy of Windows ASEPs](img/taxonomy.png "A taxonomy of Windows ASEPs and a summary of their characteristics")

**NOTE**: you can read more about this taxonomy in this [paper](https://drive.google.com/file/d/1GiGc4Eei4oCvk-5uglWMjblX6yUpI3Lg/view?usp=sharing).

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Usage

```
---------------------------------
Module Winesap
---------------------------------

Search for all Autostart Extensibility Points (AESPs)

    Options:
        --match: only shows suspicious entries
```

Add this project path to Volatility 3 with the `-p` (plugin directory) option. The plugin is then available as `winesap.Winesap`:

```
$ python3 vol.py -p /path/to/winesap -f /path/to/memory.dump winesap.Winesap --match
Volatility 3 Framework 2.28.1

RegType  RegName     RegKey                                                          RegValue                                            Warning
REG_SZ   ALINAhuahs  HKCU [Usuario]\Software\Microsoft\Windows\CurrentVersion\Run    C:\Users\Usuario\AppData\Roaming\ALINA_CJLXYJ.exe   Suspicious path file
```

The output is a `TreeGrid`, so it also works with the standard Volatility 3 renderers (`-r csv`, `-r json`, `-r pretty`). Per-user `HKCU` entries are labelled with the originating profile (e.g. `HKCU [Usuario]`) because every `NTUSER.DAT` hive is scanned, not just one.

## License

Licensed under the [GNU AGPLv3](LICENSE) license.
