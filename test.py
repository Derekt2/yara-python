import yara

rule = yara.compile(
    source=(
        'rule foo: bar {strings: $a = "dsfsd" condition: $a} rule foo1: bar {strings:'
        ' $a = "dsfsd" condition: $a}'
    )
)
matches = rule.match(data="abcdefgjiklmnoprstuvwxyz")
print(rule.stats())
