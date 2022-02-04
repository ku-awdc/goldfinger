## TODO: cleanup and make into function

# Users and pwd must already be available
user_info <- goldfinger:::gf_all_keys(TRUE, TRUE)
user_info <- user_info[!names(user_info)=="local_user"]
pwd

library(sodium)
library(cyphr)
library(goldfinger)

# TODO: back to working on new user setup...

weblink <- paste0("https://www.costmodds.org/rsc/goldeneye/goldfinger.gyu", "#", pwd, "#", "md")
# Save an upgrade file for md/makg/mossa:
# weblinfo <- lapply(user_info, function(x) simple_encrypt(serialize(weblink, NULL), x$public_key))
# saveRDS(weblinfo, "upgrade0.2.rds", compress=FALSE)


## Note:  usernames may also include previous (no longer valid) usernames to avoid clashes
usernames <- names(user_info)

## There are two types of public key, neither of which need to be encrypted:
public_curve <- lapply(user_info, function(x) x$public_key)
public_ed <- lapply(user_info, function(x) NA_real_)
public_ed$md <- readRDS('~/Documents/Personal/goldfinger_md.gyp')$public_ed
stopifnot(identical(readRDS('~/Documents/Personal/goldfinger_md.gyp')$public_curve, public_curve$md))

user_info <- lapply(user_info, function(x) x[!names(x)%in%c("public_key","public_ed","public_curve")])

users <- list(usernames=usernames, user_info=data_encrypt(serialize(user_info, NULL), hash(charToRaw(pwd))), public_curve=public_curve, public_ed=public_ed)
verification <- gy_sign(users)
stopifnot(gy_verify(users, verification, silent=TRUE))
attr(verification, "user") <- NULL

keys <- list(group="goldfinger", package_version=goldfinger:::goldfinger_env$version, minimum_version="0.3.0", date_time = Sys.time(), users=users, verification=verification)

saveRDS(keys, "goldfinger.gyu", compress=FALSE)

stop()


gtp <- readRDS("/Users/matthewdenwood/Documents/Resources/Goldeneye/goldfinger/goldfinger_test_public.gyp")
gtp

library(sodium)
unserialize(data_decrypt(gtp, hash(charToRaw(pwd))))
