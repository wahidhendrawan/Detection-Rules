rule YAR_063_Suspicious_Pattern
{
  meta:
    author = "Wahid Hendrawan"
    description = "Auto-generated YARA rule #063 for suspicious string matching"
    date = "2026-05-21"
    severity = "medium"
  strings:
    $s1 = "powershell -enc" nocase
    $s2 = "vssadmin delete shadows" nocase
    $s3 = "rundll32 comsvcs.dll,MiniDump" nocase
    $h1 = { 4D 5A }
  condition:
    uint16(0) == 0x5A4D and 1 of ($s*) and $h1
}
