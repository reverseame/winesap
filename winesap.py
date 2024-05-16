import re
import itertools

import volatility.utils as utils
import volatility.debug as debug
import volatility.win32.rawreg as rawreg
import volatility.plugins.registry.registryapi as registryapi

from volatility.plugins.common import AbstractWindowsCommand
from volatility.obj import NoneObject

class Winesap(AbstractWindowsCommand):
    """
    Search for all Autostart Extensibility Points (AESPs)
    
    Options:
        --match: only shows suspicious entries
    """
    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('MATCH', help='Only shows suspicious entries', action='store_true')
        self.addr_space = utils.load_as(self._config)
        self.regapi = registryapi.RegistryApi(self._config)

    def calculate(self):
        yield self.get_run()
        yield self.get_installed_components()
        yield self.get_services()
        yield self.get_image_file_execution_options()
        yield self.get_winlogon()
        yield self.get_appinit_dlls()

    def get_run(self):
        self.regapi.set_current('ntuser.dat')
        yield {'root': 'HKCU\\', 'key': self.regapi.reg_get_key('ntuser.dat', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'), 'value': []}
        yield {'root': 'HKCU\\', 'key': self.regapi.reg_get_key('ntuser.dat', 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), 'value': []}
        for k in self.regapi.reg_get_all_subkeys('ntuser.dat', 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'):
            yield {'root': 'HKCU\\', 'key': k, 'value': []}

        yield {'root': 'HKCU\\', 'key': self.regapi.reg_get_key('ntuser.dat', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), 'value': []}
        yield {'root': 'HKCU\\', 'key': self.regapi.reg_get_key('ntuser.dat', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), 'value': []}
        for k in self.regapi.reg_get_all_subkeys('ntuser.dat', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'):
            yield {'root': 'HKCU\\', 'key': k, 'value': ['RunMyApp']}

        self.regapi.set_current('software')
        yield {'root': 'HKLM\\Software\\', 'key': self.regapi.reg_get_key('software', 'Microsoft\\Windows\\CurrentVersion\\Run'), 'value': []}
        yield {'root': 'HKLM\\Software\\', 'key': self.regapi.reg_get_key('software', 'Microsoft\\Windows\\CurrentVersion\\RunOnce'), 'value': []}
        for k in self.regapi.reg_get_all_subkeys('software', 'Microsoft\\Windows\\CurrentVersion\\RunOnceEx'):
            yield {'root': 'HKLM\\Software\\', 'key': k, 'value': ['RunMyApp']}

    def get_installed_components(self):
        self.regapi.set_current('software')
        for k in self.regapi.reg_get_all_subkeys('software', 'Microsoft\\Active Setup\\Installed Components'):
            yield {'root': 'HKLM\\Software\\', 'key': k, 'value': ['StubPath']}

    def get_services(self):
        self.regapi.set_current('system')
        currentcontrolset = self.regapi.reg_get_currentcontrolset(fullname=True)
        if currentcontrolset is None:
            currentcontrolset = 'ControlSet001'

        for k in self.regapi.reg_get_all_subkeys('system', '{0}\\Services'.format(currentcontrolset)):
            yield {'root': 'HKLM\\System\\', 'key': k, 'value': ['ImagePath']}

    def get_image_file_execution_options(self):
        self.regapi.set_current('software')
        for k in self.regapi.reg_get_all_subkeys('software', 'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'):
            yield {'root': 'HKLM\\Software\\', 'key': k, 'value': ['Debugger']}

    def get_winlogon(self):
        self.regapi.set_current('software')
        yield {'root': 'HKLM\\Software\\', 'key': self.regapi.reg_get_key('software', 'Microsoft\\Windows NT\\CurrentVersion\\Winlogon'), 'value': ['Shell', 'Userinit']}

    def get_appinit_dlls(self):
        self.regapi.set_current('software')
        yield {'root': 'HKLM\\Software\\', 'key': self.regapi.reg_get_key('software', 'Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'value': ['AppInit_DLLs']}
        yield {'root': 'HKLM\\Software\\', 'key': self.regapi.reg_get_key('software', 'Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), 'value': ['AppInit_DLLs']}

    def render_text(self, outfd, data):
        for gen in data:
            for key in gen:
                root = key['root']
                filtered_keys = self.filter_key(key['key'], key['value'])
                for filtered_key in filtered_keys:
                    if not self._config.MATCH or (self._config.MATCH and filtered_key['reason']):
                        outfd.write('-' * 30)
                        if filtered_key['reason']:
                            outfd.write('\nWARNING: {0}'.format(warning_message(', '.join(filtered_key['reason']))))
                        outfd.write('\n{0}{1}\n'.format(root, self.regapi.reg_get_key_path(filtered_key['key'])))

                        tp, dt = rawreg.value_data(filtered_key['value'])
                        if tp == 'REG_BINARY' or tp == 'REG_NONE':
                            dt = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dt[:0x40])])
                        outfd.write('{0}: {1}: {2}\n'.format(self.get_value_name(filtered_key['value']), tp, dt))

    def filter_key(self, key, value):
        ret = []
        if key:
            for v in rawreg.values(key):
                if not value or (value and self.get_value_name(v) in value):
                    tp, dat = rawreg.value_data(v)
                    if tp == 'REG_BINARY' or tp == 'REG_NONE':
                        reason = self.is_bin_suspicious(dat)
                        ret += [{'key': key, 'value': v, 'reason': reason}]
                    elif tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        reason = self.is_string_suspicious(dat)
                        ret += [{'key': key, 'value': v, 'reason': reason}]
        return ret

    def is_string_suspicious(self, string):
        ret = []
        PATHS = ['AppData', 'Roaming', 'Temp', 'Application Data']

        # avoid errors when the value data is unreadable, it can be caused by various reasons (e.g., paging)
        if type(string) == NoneObject:
            return ret

        if re.search(r'.+\\({0}).+\..+'.format('|'.join(PATHS)), string, flags=re.IGNORECASE):
            ret += ['Suspicious path file']

        if re.search(r'.*regsvr32\.exe /s (?!(\\/:*?"<>|)).+:.+', string, flags=re.IGNORECASE):
            ret += ['Suspicious Alternate Data Stream (ADS)']

        if re.search(r'.*rundll32\.exe (?!(\\/:*?"<>|)).+:.+', string, flags=re.IGNORECASE):
            ret += ['Suspicious Alternate Data Stream (ADS)']

        if re.search(r'.*rundll32\.exe.+shell32\.dll.*', string, flags=re.IGNORECASE):
            ret += ['Suspicious shell execution']

        return ret

    def is_bin_suspicious(self, data):
        if self.is_pe(data):
            return 'Suspicious PE file'

        return ''

    def is_pe(self, data):
        try:
            if data[:0x2] == b'\x4d\x5a': # MZ
                pe_offset = ord(data[0x3c])
                if data[pe_offset:pe_offset+0x2] == b'\x50\x45': # PE
                    return True
        except IndexError:
            pass

        return False

    def get_value_name(self, value):
        return str(value.dereference().Name)

def warning_message(message):
    return '{0}{1}{2}'.format('\033[93m', message, '\033[0m')
