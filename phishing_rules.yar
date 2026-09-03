/*
    Phishing Investigation Platform - baseline YARA rule set
    Scope: detects common phishing-delivery patterns in email attachments
    (malicious macros, HTML credential-harvesting pages, script droppers,
    and obfuscated PowerShell/JS). Extend this file with rules tuned to
    your own telemetry -- these are intentionally broad starting points.
*/

rule Suspicious_Office_Macro
{
    meta:
        description = "Office document containing VBA macro auto-exec keywords"
        severity = "high"
        mitre_technique = "T1566.001"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "AutoExec" nocase
        $shell1 = "Shell(" nocase
        $shell2 = "WScript.Shell" nocase
        $download = "URLDownloadToFile" nocase
    condition:
        (any of ($auto*)) and (any of ($shell*, $download))
}

rule HTML_Credential_Harvesting_Form
{
    meta:
        description = "HTML file containing a login-style form posting to an external host"
        severity = "high"
        mitre_technique = "T1566.002"
    strings:
        $form = "<form" nocase
        $pw = "type=\"password\"" nocase
        $pw2 = "type='password'" nocase
        $action = "action=\"http" nocase
    condition:
        $form and ($pw or $pw2) and $action
}

rule Obfuscated_PowerShell_Dropper
{
    meta:
        description = "Encoded/obfuscated PowerShell command patterns typical of phishing droppers"
        severity = "high"
        mitre_technique = "T1059.001"
    strings:
        $enc = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $iex = "IEX(" nocase
        $webclient = "Net.WebClient" nocase
    condition:
        2 of them
}

rule Suspicious_JS_WSF_Dropper
{
    meta:
        description = "Script attachment (.js/.wsf/.hta) with download-and-execute behaviour"
        severity = "high"
        mitre_technique = "T1204.002"
    strings:
        $xhr = "ActiveXObject" nocase
        $run = ".Run(" nocase
        $save = "SaveToFile" nocase
        $adodb = "ADODB.Stream" nocase
    condition:
        2 of them
}

rule Suspicious_Double_Extension
{
    meta:
        description = "Filename embeds a double extension commonly used to mask executables"
        severity = "medium"
        mitre_technique = "T1036.007"
    strings:
        $a = ".pdf.exe" nocase
        $b = ".doc.exe" nocase
        $c = ".xls.exe" nocase
        $d = ".jpg.exe" nocase
        $e = ".txt.vbs" nocase
    condition:
        any of them
}

rule Generic_Password_Protected_Zip_Lure
{
    meta:
        description = "ZIP local file header combined with phishing-lure keywords (password-protected archives evade AV/sandboxing)"
        severity = "medium"
        mitre_technique = "T1027.006"
    strings:
        $ziphdr = { 50 4B 03 04 }
        $lure1 = "invoice" nocase
        $lure2 = "password" nocase
        $lure3 = "extract" nocase
    condition:
        $ziphdr at 0 and any of ($lure*)
}
