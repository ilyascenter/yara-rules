rule MAL_Remcos_Requisitions_2026
{
    meta:
        author = "ilyasrifai"
        description = "Detect Remcos RAT from Requisitions sample"
        date = "2026-04-27"
        malware_family = "Remcos"

    strings:
        $mutex = "Rmc-MUUVXQ" ascii wide
        $path1 = "ProgramData\\Remcos\\remcos.exe" ascii wide
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $c2 = "192.227.135.240" ascii

    condition:
        uint16(0) == 0x5A4D and
        $mutex and
        1 of ($path*, $reg*) and
        $c2
}
