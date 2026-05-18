rule Suspicious_PE_Header
{
    meta:
        description = "Detects MZ executable header"
        author = "System"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule Suspicious_Powershell
{
    meta:
        description = "Detects powershell commands"
    strings:
        $ps1 = "powershell.exe" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "Hidden -Command" nocase
    condition:
        any of them
}
