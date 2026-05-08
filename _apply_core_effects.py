"""Write core_effect to all technique configs. Only patterns that are substrings of existing patterns."""
import json, sys
sys.path.insert(0, '.')
from pathlib import Path
from inspect_log_gui.backend.storage import PatternStore

DATA_DIR = Path('D:/NCKH_new/muilti-graph/inspect_log_gui/data')

# fmt: off
# Rules: pick the direct attack tool/artifact (NOT launcher like powershell/cmd/winrshost)
# Value must be a substring or exact match of an existing pattern in that technique's config.
CORE_EFFECTS: dict[str, list[str]] = {
    # Credential Dumping
    "T1003.001": ["mimikatz.exe", "procdump.exe", "outflank-dumpert.exe", "pypykatz", "wce.exe"],
    "T1003.002": ["esentutl.exe", "mimikatz", "pypykatz", "reg save"],
    "T1003.003": ["ntdsutil", "ntds.dit"],
    "T1003.004": ["DisableRestrictedAdmin", "NoLMHash"],
    "T1003.008": ["file_shadow", "file_passwd"],
    "T1003":     ["mimikatz.exe", "wdigest"],
    # Defense Evasion / Rootkit
    "T1014":     ["libdsx.so", ".backup_ld.so", ".logpam"],
    # Discovery
    "T1016":     ["nslookup", "ping.exe"],
    "T1018":     ["nltest.exe", "dsquery.exe"],
    "T1033":     ["whoami.exe", "quser.exe"],
    "T1049":     ["netstat.exe", "get-nettcpconnection"],
    "T1057":     [],  # only WMI queries, no specific tool
    "T1069.001": ["get-localgroup", "localgroup"],
    "T1069.002": ["ldifde", "get-adgroup"],
    "T1082":     ["systeminfo"],
    "T1087.001": ["Get-LocalUser", "net  user"],
    "T1087.002": [],  # patterns empty
    "T1135":     ["Invoke-ShareFinder", "Get-NetShare"],
    # Exfiltration
    "T1020":     ["rclone.exe"],
    "T1048.003": ["exfil.js", "evil.com"],
    "T1560.001": ["rar", "zip"],
    # Execution
    "T1047":     ["Invoke-WmiMethod", "Win32_Process"],
    "T1053.002": ["at.exe"],
    "T1053.003": ["crontab"],
    "T1053.005": ["schtasks.exe", "asyncrat.exe"],
    "T1053.006": ["hello_evil.service"],
    "T1059.001": ["EncodedCommand", "FromBase64String", "DownloadString"],
    "T1059.003": ["xp_cmdshell", "sqlcmd.exe"],
    "T1059.005": ["1.vbs", "dynwrapx.dll"],
    "T1059":     ["AutoIt3.exe"],
    "T1569.002": ["sa.dat", "MULTI_FILE.exe"],
    # Impact
    "T1485":     ["shred", ".wcry", ".enigma"],
    "T1486":     ["dcrypt", "dcinst"],
    "T1489":     ["stop apache2", "disable apache2"],
    "T1490":     ["vssadmin", "bcdedit", "wbadmin"],
    "T1561.002": ["whispergate_mbr.exe", "diskpart"],
    # Impair Defenses
    "T1562.001": ["Set-MpPreference", "amsiPatch.py"],
    "T1562.002": ["auditpol"],
    "T1562.004": ["Set-NetFirewallProfile", "Remove-NetFirewallRule"],
    # Indicator Removal
    "T1070.001": ["wevtutil cl System", "Clear-EventLog"],
    "T1070.005": ["net use /delete", "Remove-SmbMapping"],
    "T1070":     ["wevtutil", "delete shadows", "lockbit.exe"],
    # Lateral Movement
    "T1021.001": ["mstsc.exe"],
    "T1021.002": ["PSEXESVC.exe"],
    "T1021.003": ["evil.dll"],
    "T1021.004": ["/usr/bin/ssh", "-oStrictHostKeyChecking=no"],
    "T1021.006": ["winrshost.exe", "winrs.exe"],
    "T1570":     ["remcom"],
    # Masquerading
    "T1036.003": ["C:\\\\lsm.exe", "mshta", "wscript"],
    "T1036":     ["msbtc.exe"],
    # Obfuscation / Evasion
    "T1140":     ["certutil.exe", "clop"],
    "T1202":     ["pcalua.exe"],
    "T1216":     ["syncappvpublishingserver"],
    "T1218.001": ["hh.exe"],
    "T1218.002": ["processid:"],
    "T1218.004": ["installutil.exe"],
    "T1218.005": ["mshta"],
    "T1218.007": ["msiexec.exe"],
    "T1218.008": ["odbcconf.exe"],
    "T1218.009": ["regsvcs", "regasm"],
    "T1218.010": ["regsvr32", "squiblydoo"],
    "T1218.011": ["rundll32"],
    "T1218.012": ["verclsid"],
    "T1218.013": ["mavinject"],
    "T1218":     ["diskshadow.exe"],
    "T1220":     ["msxsl", "wmicscript"],
    # Persistence
    "T1037.001": ["userinitmprlogonscript"],
    "T1098.004": ["authorized_keys", "ssh-keygen"],
    "T1098":     ["DSRMAdmin"],
    "T1112":     ["UseLogonCredential", "nouaccheck"],
    "T1136.001": ["net user"],
    "T1197":     ["bitsadmin", "start-bitstransfer"],
    "T1505.001": ["sqlservr"],
    "T1505.003": ["human2.aspx", "spinstall0.aspx", "postex_"],
    "T1505.004": ["appcmd", "gacutil"],
    "T1543.003": ["qbzgludy", "discovercachedata.dat"],
    "T1546.001": ["txtfile"],
    "T1546.002": ["DeleteValue"],
    "T1546.003": ["covenant.exe", "sandcat.exe"],
    "T1546.004": ["MULTI_FILE.sh", "mal_boot.sh"],
    "T1546.008": ["image file execution options"],
    "T1546.011": ["sdbinst", "atomicshim"],
    "T1546.012": ["image file execution options", "debugger"],
    "T1546.015": ["InProcServer32", "CLSID"],
    "T1547.001": ["EstsoftAutoUpdate", "RunOnce", "StartUp"],
    "T1547.003": ["TimeProviders"],
    "T1547.005": ["Security Packages"],
    "T1547.006": ["kextload", "rootkit", ".ko"],
    "T1547.008": ["sspisrv.dll", "LsaDbExtPt"],
    "T1547.010": ["AddMonitor", "Monitors"],
    "T1547.012": ["Print Processors", "UDPrint", "pipemon"],
    "t1547.014": ["active setup", "ucmDccwCOMMethod"],
    # Privilege Escalation
    "T1068":     ["combo2.sys", "dccuac.ps1", "/usr/bin/pkexec"],
    "T1548.001": ["setcap", "cap_setuid", "evil_bin.c"],
    "T1548.002": ["fodhelper.exe", "sdclt.exe", "uacme_exe"],
    "T1548.003": ["lesspipe", "doas", "sudo visudo"],
    "T1548":     ["ucmDccwCOMMethod"],
    # Privilege Escalation - Run Keys
    "T1222.001": ["icacls", "takeown"],
    # Command & Control
    "T1071.004": ["dnscat", "iodine"],
    "T1090.001": ["portproxy", "netsh  interface portproxy add v4tov4"],
    "T1090.003": ["tor.exe"],
    "T1219":     ["screenconnect", "anydesk", "teamviewer"],
    "T1572":     ["plink.exe", "ngrok"],
    # Initial Access
    "T1189":     ["caldera", "sandcat"],
    "T1190":     ["crushftpservice", "bash -i"],
    "T1195.001": ["malicious-pkg", "shai-hulud"],
    "T1195.002": ["3cxdesktopapp"],
    "T1204.002": ["\\\\desktop\\\\n.exe"],
    "T1566.001": ["officesetup.exe", "atomic.doc"],
    "T1566.002": ["griffon_recon.vbs"],
    "T1566":     ["add hkcr\\\\clsid"],
    # Collection
    "T1115":     ["xclip"],
    # Credential Access
    "T1110.001": ["rdp_brute"],
    "T1482":     ["adfind", "nltest"],
    "T1542.003": ["aurora-agent-util"],
    "T1550.002": ["mimikatz"],
    "T1550.003": ["rubeus.exe", "mimikatz"],
    "T1550":     ["rubeus"],
    "T1552.002": ["SystemCertificates", "\\\\WINLOGON"],
    "T1553.003": ["SIP"],
    "T1553.004": ["add-trusted-cert", "certutil"],
    "T1555":     ["webbrowserpassview.exe"],
    "T1558.003": ["Invoke-Kerberoast", "setspn.exe"],
    "T1558":     ["rubeus.exe"],
    "T1649":     ["certify.exe", "certipy.exe"],
    # Defense Evasion - DLL hijack
    "T1574.001": ["iscsicpl.exe"],
    "T1574.002": ["shakeitoff.exe"],
    "T1574.006": ["evil_preload.c", "dll_hook.sh"],
    "T1574.009": ["program.exe"],
    "T1574.011": ["imagepath", "binpath=", "win32calc.exe"],
    # Reconnaissance
    "T1201":     ["get-addefaultdomainpasswordpolicy"],
    "T1590.002": ["dnscmd"],
    "t1592":     ["remcos", "dxdiag"],
    # Resource Development
    "T1587.002": ["sigcheck64.exe"],
    "T1588.002": ["advancedrun.exe"],
    # Tool Transfer
    "T1105":     ["certutil", "bitsadmin.exe"],
    # Misc
    "T1127.001": ["msbuild.exe"],
    "T1127":     ["microsoft.workflow.compiler.exe", "ngen.exe"],
    "T1531":     ["adfind.exe", "qakbot.bat"],
    "T1564.004": ["test_ads_abuse.ps1"],
    "T1598.002": ["mstsc.exe", ".rdp"],
    "T1620":     ["nimplant.exe", "nimplat"],
    "T1595":     ["discovery", "recon"],
}
# fmt: on

SKIP_REASONS = {
    "T1027":     "Patterns are obfuscated strings/command arguments — no clear single tool",
    "T1078":     "JSON parse error in config file — skipped",
    "T1078.002": "Patterns are generic terms (credentials, domain account) — no specific direct tool",
    "T1087.002": "Pattern list is empty",
    "T1200":     "Pattern 'lsassy' may be misassigned — T1200 is Hardware Additions",
    "T1204":     "Only pattern is winrshost.exe (framework launcher) — not a direct attack artifact",
    "T1497.003": "Mixed patterns (evasion checks + payload names) — unclear direct tool",
    "T1531":     "(included — adfind.exe + qakbot.bat)",
    "T1556":     "Patterns are generic registry operations (DeleteValue, reg.exe)",
    "T1563.002": "Pattern is generic 'rdp'",
    "T1564":     "Pattern is generic 'sc.exe'",
    "T1590.005": "Pattern is wermgr.exe (Windows Error Reporting) — unclear direct attack role",
}

ps = PatternStore(data_dir=DATA_DIR)
applied = 0
skipped = 0

for technique, core_effect in sorted(CORE_EFFECTS.items()):
    if not core_effect:
        skipped += 1
        continue
    try:
        # Verify each pattern is a substring of at least one existing pattern
        existing = ps.get_patterns(technique)
        existing_lower = [p.lower() for p in existing]

        valid = []
        invalid = []
        for ce in core_effect:
            ce_lower = ce.lower()
            # Check if ce_lower is substring of any existing pattern (lowercased)
            if any(ce_lower in ep for ep in existing_lower):
                valid.append(ce)
            else:
                invalid.append(ce)

        if invalid:
            print(f"  WARN {technique}: patterns not found in existing → {invalid}")
        if valid:
            ps.save_core_effect(technique, valid)
            applied += 1
            print(f"  OK   {technique}: {valid}")
        else:
            skipped += 1
            print(f"  SKIP {technique}: no valid patterns matched existing")
    except Exception as e:
        print(f"  ERR  {technique}: {e}")
        skipped += 1

print(f'\nApplied: {applied}, Skipped: {skipped}')
print('\nSkip reasons for techniques not in list:')
for tech, reason in SKIP_REASONS.items():
    if tech not in CORE_EFFECTS or not CORE_EFFECTS.get(tech):
        print(f'  {tech}: {reason}')
