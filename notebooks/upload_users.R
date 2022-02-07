## TODO: cleanup and make into function

library(sodium)
library(cyphr)
library(goldfinger)

weblink <- readRDS(getOption("goldeneye_path"))$groups$goldfinger$weblink
webinfo <- goldfinger:::refresh_users(weblink)
user_info <- webinfo$users
names(user_info)

## Add new users:
newusers <- list.files("/Users/matthewdenwood/Documents/Resources/Goldeneye/goldfinger/incoming", full.names=TRUE)
ssn <- readRDS(newusers)
ssn$version <- as.character(ssn$versions["actual"])
ssn$date_time <- as.character(ssn$versions["date_time"])
ssn <- ssn[names(user_info$md)]

## Note:  usernames may also include previous (no longer valid) usernames to avoid clashes
usernames <- c(webinfo$usernames, ssn$user)

user_info <- c(user_info, list(saxmose=ssn))

## There are two types of public key, neither of which need to be encrypted:
public_curve <- lapply(user_info, function(x) x$public_curve)
public_ed <- lapply(user_info, function(x) x$public_ed)
#public_ed$md <- readRDS('~/Documents/Personal/goldfinger_md.gyp')$public_ed
#stopifnot(identical(readRDS('~/Documents/Personal/goldfinger_md.gyp')$public_curve, public_curve$md))

user_info <- lapply(user_info, function(x) x[!names(x)%in%c("public_key","public_ed","public_curve")])

users <- list(usernames=usernames, user_info=data_encrypt(serialize(user_info, NULL), hash(charToRaw(webinfo$webpwd))), public_curve=public_curve, public_ed=public_ed)

verification <- gy_sign(users)

# Note: this is used for checking the download and the verification separately:
versions <- attr(verification, "versions")
versions["type"] <- "generic"
versions["minimum"] <- "0.4.1-0"
attr(verification, "versions") <- versions
stopifnot(gy_verify(users, verification, silent=TRUE))
attr(verification, "user") <- NULL

keys <- list(group="goldfinger", users=users, verification=verification)

saveRDS(keys, "goldfinger.gyu", compress=FALSE)

stop()


gtp <- readRDS("/Users/matthewdenwood/Documents/Resources/Goldeneye/goldfinger/goldfinger_test_public.gyp")
gtp

library(sodium)
unserialize(data_decrypt(gtp, hash(charToRaw(pwd))))
