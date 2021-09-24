library('goldfinger')

## Encrypt for local user only:

gf_saveRDS(iris, file="iris.rgd")
test <- gf_readRDS("iris.rgd")
stopifnot(identical(test,iris))


## Encrypt for md as well as the local user:

gf_saveRDS(iris, user="md", local_user=TRUE, file="iris.rgd", overwrite=TRUE)
test <- gf_readRDS("iris.rgd")


## Encrypt for nobody (file is locked permanently!):

gf_saveRDS(iris, user=character(0), local_user=FALSE, file="iris.rgd", overwrite=TRUE)
try( gf_readRDS("iris.rgd") )


## Use save/load:

gf_save(test, letters, file="iris.rgd", overwrite=TRUE)
rm(test)
stopifnot(!"test" %in% ls())

gf_load("iris.rgd")
stopifnot(all(c("letters","test") %in% ls()))


## TODO: direct encryption of files using base64enc (unencryption into temp directory??)


unlink("iris.rgd")
