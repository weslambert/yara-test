rule TestRule {
    meta:
        author = "Wes Lambert"
        description = "Test rule new"
    strings:
        $a = "test"
        $b = "this"
        $c = "rule"
        $d = "again"
        $e = "1"
    condition:
        all of them
}
