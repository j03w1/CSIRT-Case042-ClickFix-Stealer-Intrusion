rule CRIME_Stealer_LummaC2_Stage2_Loader_Case042
{
    meta:
        description = "Detects Stage-2 LummaC2 Stealer loader binary and LSASS dump strings observed in CSIRT Case 042"
        author = "CSIRT Portfolio Analyst"
        date = "2026-10-16"
        incident_id = "CSIRT-CASE-042"
        mitre_attack = "T1003.001, T1053.005, T1071.001"
        sha256 = "8b1a9953c4611296a827abf8c47804d7e6c49c6b104372185c52b912a9881b21"

    strings:
        $s_c2_domain = "cdn-telemetry-sync.example" ascii wide nocase
        $s_task_name = "EdgeUpdateSync" ascii wide
        $s_minidump  = "comsvcs.dll, MiniDump" ascii wide nocase
        $s_drop_path = "\\AppData\\Local\\Temp\\sync_helper.exe" ascii wide nocase
        $s_stealer_1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
        $s_stealer_2 = "moz_logins" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s_c2_domain or $s_minidump) or
            (2 of ($s_task_name, $s_drop_path, $s_stealer_1, $s_stealer_2))
        )
}
