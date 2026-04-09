import base64
import hashlib
import ipaddress
import re
import urllib
from globals.logger_manager import LoggerManager


logger = LoggerManager.get_logger(__name__)


LOLBIN_PATTERNS = [
    (r'certutil(?:\.exe)?\s+.*?(?:-decode|-urlcache\s+-f|-verifyctl)',  "<CERTUTIL_DOWNLOAD_OR_DECODE>"),
    (r'mshta(?:\.exe)?\s+\S+',                                          "<MSHTA_EXEC>"),
    (r'regsvr32(?:\.exe)?\s+.*?(?:/s|/u|/i:)\s*\S+.*?scrobj',          "<REGSVR32_SQUIBLYDOO>"),
    (r'rundll32(?:\.exe)?\s+.*?(?:javascript:|vbscript:|\.dll,)',        "<RUNDLL32_ABUSE>"),
    (r'rundll32(?:\.exe)?\s+.*?comsvcs.*?minidump',                     "<RUNDLL32_COMSVCS_DUMP>"),
    (r'msiexec(?:\.exe)?\s+.*?/[iq]\s+https?://',                       "<MSIEXEC_REMOTE>"),
    (r'bitsadmin(?:\.exe)?\s+.*?/transfer',                             "<BITSADMIN_TRANSFER>"),
    (r'wmic(?:\.exe)?\s+.*?process\s+call\s+create',                    "<WMIC_EXEC>"),
    (r'csc(?:\.exe)?\s+.*?/out:',                                        "<CSC_COMPILE_LIVE>"),
    (r'msbuild(?:\.exe)?',                                               "<MSBUILD_INLINE_EXEC>"),
    (r'installutil(?:\.exe)?',                                           "<INSTALLUTIL_EXEC>"),
    (r'regasm(?:\.exe)?',                                                "<REGASM_EXEC>"),
    (r'regsvcs(?:\.exe)?',                                               "<REGSVCS_EXEC>"),
    (r'cmstp(?:\.exe)?\s+.*?(?:/s|/ns)',                                 "<CMSTP_BYPASS>"),
    (r'forfiles(?:\.exe)?\s+.*?/c\s+',                                  "<FORFILES_EXEC>"),
    (r'pcalua(?:\.exe)?\s+-a',                                           "<PCALUA_EXEC>"),
    (r'syncappvpublishingserver(?:\.vbs|\.ps1)?',                        "<SYNCAPPV_EXEC>"),
]

class FilePathNormalizer:
    ENV_VAR_MAP = [
        (r'[a-z]:\\users\\[^\\]+\\appdata\\local\\microsoft\\windows\\inetcache', '%INETCACHE%'),
        (r'[a-z]:\\users\\[^\\]+\\appdata\\local\\temp',                          '%TEMP%'),
        (r'[a-z]:\\users\\[^\\]+\\appdata\\local',                                '%LOCALAPPDATA%'),
        (r'[a-z]:\\users\\[^\\]+\\appdata\\roaming',                              '%APPDATA%'),
        (r'[a-z]:\\users\\[^\\]+',                                                 '%USERPROFILE%'),
        (r'[a-z]:\\windows\\system32',                                             '%SYSTEM32%'),
        (r'[a-z]:\\windows\\syswow64',                                             '%SYSWOW64%'),
        (r'[a-z]:\\windows\\sysnative',                                            '%SYSNATIVE%'),
        (r'[a-z]:\\windows',                                                        '%WINDIR%'),
        (r'[a-z]:\\program files \(x86\)',                                          '%PROGRAMFILES_X86%'),
        (r'[a-z]:\\program files',                                                  '%PROGRAMFILES%'),
        (r'[a-z]:\\programdata',                                                    '%PROGRAMDATA%'),
        (r'[a-z]:\\users\\public',                                                  '%PUBLIC%'),
    ]


    @staticmethod
    def _resolve_traversal(path: str) -> str:
        """Resolve path traversal pattern for anti evasion skills"""
        parts = path.replace('/', '\\').split('\\') 
        resolved_parts = []
        for part in parts:
            if part == '..':
                if resolved_parts:
                    resolved_parts.pop() 
            elif part and part != '.':
                resolved_parts.append(part)
        return '\\'.join(resolved_parts)


    @staticmethod
    def normalize(path: str) -> str:
        if not path:
            return ""
        
        p = path.strip().lower().replace('/', '\\') 

        # 1. Resolve directory traversal patterns
        p = FilePathNormalizer._resolve_traversal(p)

        # 2. Abstract env vars 
        for pattern, replacement in FilePathNormalizer.ENV_VAR_MAP:
            p = re.sub(pattern, replacement, p, count=1)

        # 3. Normalize UNC paths: E.g. \\hostname\share\path -> \\<UNC_HOST>\<UNC_SHARE>\path, and handle admin$, c$, ipc$ as special cases
        p = re.sub(r'\\\\[^\\]+\\(admin\$|c\$|ipc\$)', r'\\\\<UNC_HOST>\\\1', p)
        p = re.sub(r'\\\\[^\\]+\\[^\\]+',              r'\\\\<UNC_HOST>\\<UNC_SHARE>', p)

        p = re.sub(r'__psscriptpolicytest_.*?\.ps1','<PSPolicy_Test>', p)
        p = re.sub(r'%temp%\\[a-f0-9]{8,32}\.(dll|exe|tmp|ps1|bat|vbs|js)',
                   r'%TEMP%\\<RANDOM_PAYLOAD>.\1', p)
        p = re.sub(r'%temp%\\[a-z0-9]+\.ni\.(dll|exe)',
                   r'%TEMP%\\<NI_COMPILED>.\1', p)
        p = re.sub(r'\{[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\}',
                   '<GUID_ARTIFACT>', p)
        
        return p.lower()


class RegistryNormalizer:
    # PERSISTENCE_KEY_PATTERNS = [
    #     (r'.*\\currentversion\\run$',            '<REG_AUTORUN>'),
    #     (r'.*\\currentversion\\runonce$',        '<REG_RUNONCE>'),
    #     (r'.*\\currentversion\\runonceex$',      '<REG_RUNONCE_EX>'),
    #     (r'.*\\currentversion\\runservices$',    '<REG_RUNSERVICES>'),
    #     (r'.*\\winlogon\\userinit$',             '<REG_WINLOGON_HIJACK>'),
    #     (r'.*\\winlogon\\shell$',                '<REG_WINLOGON_HIJACK>'),
    #     (r'.*\\image file execution options\\',  '<REG_IFEO>'),
    #     (r'.*\\appcertdlls$',                    '<REG_APPCERTDLL>'),
    #     (r'.*\\appinit_dlls$',                   '<REG_APPINITDLL>'),
    #     (r'.*\\inprocserver32$',                 '<REG_COM_HIJACK>'),
    #     (r'.*\\shell\\open\\command$',           '<REG_SHELL_OPEN_CMD>'),
    #     (r'hklm\\system\\currentcontrolset\\services\\', '<REG_SERVICES>'),
    # ]


    HIVE_REPLACEMENTS = [
        ("REGISTRY\\MACHINE\\",  "HKLM\\"),
        ("REGISTRY\\USER\\",     "HKU\\"),
        ("HKEY_LOCAL_MACHINE\\", "HKLM\\"),
        ("HKEY_CURRENT_USER\\",  "HKCU\\"),
        ("HKEY_USERS\\",         "HKU\\"),
        ("HKEY_CLASSES_ROOT\\",  "HKCR\\"),
        ("HKEY_CURRENT_CONFIG\\","HKCC\\"),   
    ]

    @staticmethod
    def normalize(key_path: str) -> str:
        if not key_path:
            return ""
        
        k = key_path.strip().upper() 

        for raw, canonical in RegistryNormalizer.HIVE_REPLACEMENTS:
            k = k.replace(raw, canonical) 

        k = k.replace("\\WOW6432NODE", "")

        # Abstract Users ID main hive
        k = re.sub(r'HKU\\S-1-5-18(?:\\|$)', r'HKU\\%SYSTEM_SID%\\',         k)
        k = re.sub(r'HKU\\S-1-5-19(?:\\|$)', r'HKU\\%LOCAL_SERVICE_SID%\\',  k)
        k = re.sub(r'HKU\\S-1-5-20(?:\\|$)', r'HKU\\%NETWORK_SERVICE_SID%\\',k)
        k = re.sub(r'HKU\\S-1-5-21-[0-9\-]+(?:\\|$)', r'HKU\\%SID%\\',       k)

        # Normalize CLSID GUIDs 
        k = re.sub(r'\{[A-F0-9]{8}-(?:[A-F0-9]{4}-){3}[A-F0-9]{12}\}', '<CLSID>', k)

        return k 
    

class CommandLineNormalizer:
    PS_BYPASS_FLAGS = re.compile(
        r'-(?:executionpolicy|ep|exec)\s+(?:bypass|unrestricted|remotesigned)'
        r'|-nop(?:rofile)?'
        r'|-noninteractive'
        r'|-windowstyle\s+hidden'
        r'|-w(?:indowstyle)?\s+h(?:idden)?',
        re.IGNORECASE
    )

    DOWNLOAD_EXEC_PATTERN = re.compile(
        r'(?:downloadstring|downloadfile|webclient|invoke-webrequest|iwr|curl|wget)'
        r'.*(?:iex|invoke-expression)',
        re.IGNORECASE
    )


    @staticmethod
    def _decode_all_layers(cmd: str, depth: int) -> str:
        if depth > 5:
            return cmd 
        
        result = cmd 
        
        try:
            # Match base64 powershell
            b64_match = re.search(
                r'(?i)-(?:e|en|enc|ec|encodedcommand)\s+([A-Za-z0-9+/=]{20,})',
                result
            )

            if b64_match:
                try:
                    decoded = base64.b64decode(b64_match.group(1)).decode('utf-16-le', errors='ignore')
                    decoded = CommandLineNormalizer._decode_all_layers(decoded, depth + 1)
                    result = result.replace(b64_match.group(0), f"<DECODED_B64: {decoded}>")
                except Exception:
                    pass 

            # Match URL encoding
            url_decoded = urllib.parse.unquote(result)
            if url_decoded != result:
                result = CommandLineNormalizer._decode_all_layers(url_decoded, depth + 1) 

            # Match hex encoding
            result = re.sub(
                r'(?:\\x|0x)([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                result
            )

            # Gzip/Deflate payload
            if re.search(r'\[io\.compression|gzipstream|deflate', result, re.IGNORECASE):
                result = re.sub(r'\[io\.compression[^\]]*\].*', '<COMPRESSED_PAYLOAD>', result, flags=re.IGNORECASE)

            # AMSI bypass pattern
            if re.search(r'amsi(?:scanb|initf)', result, re.IGNORECASE):
                result += ' <AMSI_BYPASS_ATTEMPT>'

            return result 
        
        except Exception as e:
            logger.error(f"Error occurred while normalizing command line: {e}")
            return result

    @staticmethod
    def _deobfuscate_cmd(cmd: str) -> str:
        # remove case c^m^d
        cmd = cmd.replace('^', '')

        # remove case empty string c""md
        cmd = re.sub(r'""', '', cmd)
        cmd = re.sub(r"''", '', cmd)

        # replace env vars 
        env_subs = {
            '%comspec%':    'cmd.exe',
            '%systemroot%': '%windir%',
            '%windir%':     '%windir%',
        }

        for var, replacement in env_subs.items():
            cmd = cmd.replace(var, replacement) 

        cmd = re.sub(r'%\w+:~\d+,\d+%', '<CMD_SUBSTRING_OBFUSC>', cmd)

        return cmd 
    
    @staticmethod
    def _deobfuscate_powershell(cmd: str) -> str:
        cmd = cmd.replace('`', '')

        def join_concat(m: re.Match) -> str:
            parts = re.findall(r'["\']([^"\']*)["\']', m.group(0))
            return ''.join(parts)
        
        cmd = re.sub(r'(?:["\'][^"\']*["\'])\s*\+\s*(?:["\'][^"\']*["\'](?:\s*\+\s*["\'][^"\']*["\'])*)', join_concat, cmd)

        def resolve_format(m: re.Match) -> str:
            try:
                template = m.group(1)
                args = re.findall(r'["\']([^"\']*)["\']', m.group(2))
                result = re.sub(r'\{(\d+)\}', lambda x: args[int(x.group(1))]
                                if int(x.group(1)) < len(args) else x.group(0), template)
                return result
            except Exception:
                return m.group(0)
            
        cmd = re.sub(r'["\']([^"\']*\{[0-9]+\}[^"\']*)["\'].*?-f\s+((?:["\'][^"\']*["\'](?:,\s*)?)+)',
                     resolve_format, cmd, flags=re.IGNORECASE)
        
        alias_map = {
            r'\biex\b':  'invoke-expression',
            r'\bsal\s+\w+\s+iex\b': 'invoke-expression',
            r'\bgcm\b':  'get-command',
            r'\bgal\b':  'get-alias',
            r'\biwr\b':  'invoke-webrequest',
        }
        for pattern, replacement in alias_map.items():
            cmd = re.sub(pattern, replacement, cmd, flags=re.IGNORECASE)

        if CommandLineNormalizer.PS_BYPASS_FLAGS.search(cmd):
            cmd += ' <PS_BYPASS_FLAG>'

        if re.search(r'[a-z\*\?]{3,}\*[a-z\*\?]+', cmd, re.IGNORECASE):
            cmd = re.sub(r'\b\w*[\*\?]\w+\b', '<GLOB_OBFUSC>', cmd)

        if re.search(r'\[char\]', cmd, re.IGNORECASE):
            cmd = re.sub(r'(?:\[char\]\d+\s*\+?\s*)+', '<CHAR_CAST_OBFUSC>', cmd, flags=re.IGNORECASE)

        if CommandLineNormalizer.DOWNLOAD_EXEC_PATTERN.search(cmd):
            cmd += ' <DOWNLOAD_EXECUTE_PATTERN>'

        return cmd 
    
    @staticmethod
    def _tag_lolbins(cmd: str) -> str:
        """Tag các LOLBin patterns đã biết"""
        for pattern, tag in LOLBIN_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                cmd += f' {tag}'
        return cmd

    @staticmethod
    def get_threat_tags(cmd: str) -> list[str]:
        """Trả về list các threat tag không làm thay đổi cmdline gốc"""
        tags = []
        normalized = CommandLineNormalizer.normalize(cmd)
        for tag in ['<PS_BYPASS_FLAG>', '<AMSI_BYPASS_ATTEMPT>',
                    '<DOWNLOAD_EXECUTE_PATTERN>', '<COMPRESSED_PAYLOAD>',
                    '<GLOB_OBFUSC>', '<CHAR_CAST_OBFUSC>']:
            if tag.lower() in normalized:
                tags.append(tag)
        for _, lolbin_tag in LOLBIN_PATTERNS:
            if lolbin_tag.lower() in normalized:
                tags.append(lolbin_tag)
        return tags

    @staticmethod
    def normalize(cmd: str) -> str:
        if not cmd:
            return ""
        
        c = cmd.strip() 
        c = re.sub(r'^"|"$', '', c)

        # decode encoded layers, max 5 tries
        c = CommandLineNormalizer._decode_all_layers(c, depth=0)

        # Deobfuscate common patterns
        c = CommandLineNormalizer._deobfuscate_cmd(c)
        c = CommandLineNormalizer._deobfuscate_powershell(c)

        c = CommandLineNormalizer._tag_lolbins(c)
        return c.lower()
    
    @staticmethod 
    def hash_command(cmd: str) -> str | None:
        if not cmd:
            return None
        return hashlib.sha256(cmd.encode('utf-8')).hexdigest()

class NetworkNormalizer:
    @staticmethod
    def normalize_ip (ip: str) -> str:
        if not ip:
            return ""
        
        try: 
            addr = ipaddress.ip_address(ip.strip())
            if addr.is_loopback:         return "<LOOPBACK_IP>"
            if addr.is_private:          return "<PRIVATE_IP>"
            if addr.is_link_local:       return "<LINKLOCAL_IP>"
            if addr.is_multicast:        return "<MULTICAST_IP>"
            if addr.is_unspecified:      return "<UNSPECIFIED_IP>"
            return str(addr)
        except ValueError:
            return ip 
        

    @staticmethod
    def normalize_domain(domain: str) -> str:
        if not domain:
            return ""

        d = domain.strip().lower().rstrip('.')  

        # # Decode Punycode 
        # if d.startswith('xn--') or '.xn--' in d:
        #     try:
        #         d = d.encode('ascii').decode('idna')
        #         d += ' <PUNYCODE_DOMAIN>'
        #     except Exception:
        #         pass

        # # DGA detection based on Shannon entropy
        # if NetworkNormalizer._is_high_entropy(d.split('.')[0]):
        #     d += ' <DGA_SUSPECTED>'

        # # Check random-looking for dns exfil
        # subdomain = '.'.join(d.split('.')[:-2]) if d.count('.') >= 2 else ''
        # if len(subdomain) > 50:
        #     d += ' <DNS_EXFIL_SUSPECTED>'

        return d

        
class DataNormalizer:
    def __init__(self):
        pass

    file = FilePathNormalizer
    registry = RegistryNormalizer
    command_line = CommandLineNormalizer
    network = NetworkNormalizer

    @staticmethod 
    def normalize_file_path(path: str) -> str:
        return DataNormalizer.file.normalize(path) 
    
    @staticmethod
    def normalize_registry(key_path: str) -> str:
        return DataNormalizer.registry.normalize(key_path)
    
    @staticmethod
    def normalize_command_line(cmd: str) -> str:
        return DataNormalizer.command_line.normalize(cmd)   
    
    @staticmethod
    def normalize_ip(ip: str) -> str:
        return DataNormalizer.network.normalize_ip(ip)
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        return DataNormalizer.network.normalize_domain(domain)
    
    @staticmethod
    def normalize(normalize_type : list, value: any) -> str:
        if not isinstance(normalize_type, list):
            normalize_type = [normalize_type] 

        for type in normalize_type:
            if type == 'file_path':
                value = DataNormalizer.normalize_file_path(value)
            elif type == 'registry':
                value = DataNormalizer.normalize_registry(value)
            elif type == 'command_line':
                value = DataNormalizer.normalize_command_line(value)
            elif type == 'ip':
                value = DataNormalizer.normalize_ip(value)
            elif type == 'domain':
                value = DataNormalizer.normalize_domain(value) 
            elif type == 'hash_command':
                value = DataNormalizer.command_line.hash_command(value)

        return value
