# `dash-pow` fuzzing recipes, imported into `fuzz/mod.just`

# Fuzz a `dash-pow` `target` against sphlib; extra arguments go to `afl-fuzz`
pow target *args: (run "pow" target args)
