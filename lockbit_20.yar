import "pe"

rule lockbit20_exfil {
   meta:
      description = "detects lockbit 2.0 exfiltration samples"
      author = "Jeff Beley"
      date = "2021-08-13"
      hash1 = "7c7317c7f036c00d4c55d00ba36cb2a58a39a72fe24a4b8d11f42f81b062f80b"
      hash2 = "a7cf0f72bb6f1e0a61fbf39e3a3a36db6540250caeef35b47fb51a8959f40984"
      hash3 = "0d7358a3c04d860883da564d51c983e262d5b3057da29a3804d5e8f67644e02e"
      hash4 = "8ea24457df1459297503237411594b734794ee0d2654b22c66d3a976e2e6ff4f"
      hash5 = "8cfd554a936bd156c4ea29dfd54640d8f870b1ae7738c95ee258408eef0ab9e6"
   strings:
      $x1 = "powershell.exe -nop -w hidden -C \"$ppid = (gwmi win32_process | ? processid -eq  $PID).parentprocessid; $proc = Get-Process -Fi" ascii
      $x2 = "Content-Type: application/x-www-form-urlencoded" fullword wide
      $s1 = "Path $proc.FileName -Force -Confirm:0 -Value $buff; Remove-Item -Path $proc.FileName -Force -Confirm:0 \"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) and 1 of them ))  or
      ( all of them ) or
      pe.imphash() == "8f0110f74e1c5fb12854968c302df418"
}
