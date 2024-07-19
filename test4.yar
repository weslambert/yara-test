rule TestRule4 {
    meta:
        author = "Wes Lambert"
        description = "Test rule 4"
    strings:
        $a = "test"
        $b = "this"
        $c = "rule"
        $d = "again"
        $e = "3"
    condition:
        all of them
}
