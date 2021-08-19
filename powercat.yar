
rule powercat_ps1 {
   meta:
      description = "malware - file powercat.ps1.txt"
      author = "Jeff Beley"
      reference = "Accenture CIFR"
      date = "2021-01-03"
      hash1 = "f209a3b44eb3b095ad80c1b8a1da905f06f04fca86a1441f97b57b3ca14591ba"
   strings:
      $x1 = "powercat" fullword ascii
      $x2 = "ExecutePowershell" fullword ascii
      $x3 = "dnscat2" fullword ascii
      $x4 = "AsciiEncoding" fullword ascii
      $x5 = "DNSFailureThreshold" fullword ascii
      $x6 = "Select-String" fullword ascii
      $x7 = "github" fullword ascii
      $x8 = "SendPacket" fullword ascii
      $x9 = "PacketsData" fullword ascii
   condition:
      filesize < 100KB and
      4 of them
}

