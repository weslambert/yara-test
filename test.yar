rule TestRule {
    meta:
        author = "Wes Lambert"
        description = "Test rule"
    strings:
        $a = "test"
        $b = "this"
        $c = "rule"
    condition:
        all of them
}
