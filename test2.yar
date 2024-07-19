rule TestRule2 {
    meta:
        author = "Wes Lambert"
        description = "Test file rule 2"
    strings:
        $a = "test"
        $b = "this"
        $c = "file rule"
        $d = "again"
        $e = "2"
    condition:
        all of them
}
