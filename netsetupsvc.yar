
import "pe"

rule NetSetupSvc {
   meta:
      description = "malware - file NetSetupSvc.dll"
      author = "Jeff Beley"
      date = "2020-10-06"
      hash1 = "118189f90da3788362fe85eafa555298423e21ec37f147f3bf88c61d4cd46c51"
   strings:
      $s1 = "vmpkguo.dll" fullword ascii
      $s2 = "NETSETUPSVC.DLL" fullword wide
      $s3 = "Network Setup Service" fullword wide
      $s4 = "confident_promotion.jpg" fullword ascii
      $s5 = "NetSetupServiceMain" fullword ascii
      $s6 = " Microsoft Corporation. All rights reserved.  " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      ( pe.imphash() == "b983068e4288240f368968f1c8ef9e7a" and pe.exports("NetSetupServiceMain") or 6 of them )
}

rule NetSetupSvc_broad {
   meta:
      description = "malware - file NetSetupSvc.dll"
      author = "Jeff Beley"
      date = "2020-10-06"
      hash1 = "118189f90da3788362fe85eafa555298423e21ec37f147f3bf88c61d4cd46c51"
   strings:
        $s1 = "GCC: (GNU) 6.6.4" fullword ascii wide
        $s2 = "RegOpenKeyA"
        $s3 = "QueryPerformanceCounter"
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB  and all of them
}
