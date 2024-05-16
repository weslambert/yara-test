rule TestRule {
    meta:
        author = "Wes Lambert"
        description = "Test rule"
    strings:
        $a = "test"
        $b = "this"
        $c = "rule2"
    condition:
        all of them
}
