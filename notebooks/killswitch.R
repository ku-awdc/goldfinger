## Generate a killswitch file

library("sodium")
key <- keygen()

fn <- paste("GF21002ks_", paste(sample(c(0:9,letters,LETTERS), 8, replace=TRUE), collapse=""), sep="")

cat("# Killswitch file for GF21-002\n# Expiry: 2025-03-31\n# Exclude: \nkey <-", capture.output(dput(key)), "\n", sep="\n", file=fn)

readLines(fn)
oldkey <- key
rm(key)
source(fn)
stopifnot(identical(key, eval(oldkey)))
