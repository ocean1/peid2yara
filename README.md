peid2yara
=========

An improved version of the peid to yara script,
still fail to avoid inserting
signatures which seems to be not valid
(need some rework of the regexps - was a quick and dirty experiment)

To be done:

+ better regexp to avoid invalid signature
+ count the number of ?? in rules that start with wildcards, take them out and add the offset to the entrypoint
