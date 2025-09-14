rule suspicious_php_external_enhanced_v3
{
    meta:
        description = "Enhanced detection for PHP suspicious outbound communication and reverse shell, with improved false positive suppression and optimized performance"
        author = "chaoyang, optimized by GPT"
        last_modified = "2025-06-12"
        note = "Fixed invalid regex (no \\b and no negative lookahead); compatible with YARA regex engine"

    strings:
        $php_tag = "<?php"

        $curl_exec_ip = /curl_exec\s*\(\s*["']https?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}[^"']{0,100}\?[a-zA-Z0-9_]+=[^"']{1,300}["']/
        $file_get_ip  = /file_get_contents\s*\(\s*["']https?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}[^"']{0,100}\?[a-zA-Z0-9_]+=[^"']{1,300}["']/

        $rev_shell = /(bash|nc|perl|python|sh|telnet|powershell)[^\n]{0,100}([0-9]{1,3}\.){3}[0-9]{1,3}[^\n]{0,100}/ nocase

        $eval_ip       = /eval\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase
        $system_ip     = /system\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase
        $shell_exec_ip = /shell_exec\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase
        $passthru_ip   = /passthru\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase
        $proc_open_ip  = /proc_open\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase
        $popen_ip      = /popen\s*\([^)]*([0-9]{1,3}\.){3}[0-9]{1,3}[^)]*\)/ nocase

        $base64_decode = "base64_decode"
        $gzinflate     = "gzinflate"
        $str_rot13     = "str_rot13"
        $gzuncompress  = "gzuncompress"

    condition:
        $php_tag and (
            any of ($rev_shell, $eval_ip, $system_ip, $shell_exec_ip, $passthru_ip, $proc_open_ip, $popen_ip)
            or (
                (all of ($base64_decode, $gzinflate) or all of ($base64_decode, $str_rot13) or all of ($base64_decode, $gzuncompress)) and
                any of ($eval_ip, $system_ip, $shell_exec_ip, $passthru_ip, $proc_open_ip, $popen_ip)
            )
            or (
                1 of ($curl_exec_ip, $file_get_ip) and
                ($base64_decode or $str_rot13)
            )
        )
}
