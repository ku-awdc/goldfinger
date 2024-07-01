## TODO: cleanup and make into function

library(sodium)
library(cyphr)
library(goldfinger)

weblink <- readRDS(getOption("goldeneye_path"))$groups$goldfinger$weblink
webinfo <- goldfinger:::refresh_users(weblink)
user_info <- webinfo$users
names(user_info)

## Add new users:
list.files("~/Documents/Resources/Goldeneye/goldfinger/incoming", full.names=TRUE) %>%
  lapply(function(x){
    enc <- readRDS(x)
    usr <- unserialize(data_decrypt(enc, hash(charToRaw(webinfo$webpwd))))
    usr$version <- as.character(usr$versions["actual"])
    usr$date_time <- as.character(usr$versions["date_time"])
    usr[names(user_info[[1]])]
  }) ->
  newusers
names(newusers) <- sapply(newusers, function(x) x$user)

user_info <- c(user_info, newusers)
stopifnot(all(table(names(user_info))==1))

## Note:  usernames may also include previous (no longer valid) usernames to avoid clashes
usernames <- unique(c(webinfo$usernames, names(user_info)))

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
versions["minimum"] <- "0.4.2-2"
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
