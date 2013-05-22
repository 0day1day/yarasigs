rule Intel_Virtualization_Wizard {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL abuse executable"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "7787757ae851f4a162f46f794be1532ab78e1928185212bdab83b3106f28c708"

  strings:
    $a = {4C 6F 61 64 53 54 52 49 4E 47}
    $b = {49 6E 69 74 69 61 6C 69 7A 65 4B 65 79 48 6F 6F 6B}
    $c = {46 69 6E 64 52 65 73 6F 75 72 63 65 73}
    $d = {4C 6F 61 64 53 54 52 49 4E 47 46 72 6F 6D 48 4B 43 55}
    $e = {68 63 63 75 74 69 6C 73 2E 44 4C 4C}
  condition:
    all of them
}
