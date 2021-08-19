
rule zero_exe {
   meta:
      description = "zero.exe"
      author = "Jeff Beley"
      reference = "Accenture CIFR"
      date = "2021-01-18"
      hash1 = "6866e82d0f6f6d8cf5a43d02ad523f377bb0b374d644d2f536ec7ec18fdaf576"
   strings:
      $x1 = "powershell.exe -c Reset-ComputerMachinePassword" fullword wide
      $s2 = "COMMAND - command that will be executed on domain controller" fullword ascii
      $s3 = "ZERO.EXE IP DC DOMAIN ADMIN_USERNAME [-c] COMMAND :" fullword ascii
      $s4 = "-c - optional, use it when command is not binary executable itself" fullword ascii
      $s5 = "S:\\kali\\zerologon\\zero\\Release\\zero.pdb" fullword ascii
      $s6 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
      $s7 = "COMMAND - %ws" fullword ascii
      $s8 = "rpc_drsr_ProcessGetNCChangesReply" fullword wide
      $s9 = "IP - ip address of domain controller" fullword ascii
      $s10 = "rpcbindingsetauthinfo fail" fullword ascii
      $s11 = "ADMIN_USERNAME - %ws" fullword ascii
      $s12 = "x** SAM ACCOUNT **" fullword wide
      $s13 = "%COMSPEC% /C " fullword wide
      $s14 = "have no admin rights on target, exiting" fullword ascii
      $s15 = "EXECUTED SUCCESSFULLY" fullword ascii
      $s16 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
      $s17 = "  Hash %s: " fullword wide
      $s18 = "DC - domain controller name" fullword ascii
      $s19 = "DOMAIN - %ws" fullword ascii
      $s20 = "cant open scmmanager on target" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 8 of them
}

