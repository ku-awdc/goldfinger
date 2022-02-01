## TODO: cleanup and make into function

# Users and pwd must already be available
users
pwd

library(sodium)
library(cyphr)


# Where did I get to:
# Working on gy_serialise (choose between qs::qserialize and base::serialize, arguments are not important to save)


# TODO: online users file should contain:
# 1. A temporary setup password (changed frequently) that just gets a list of current user names
# 2. A permanent password secured for public keys of all current users, signed with private key of admin user
# And also the name and version of the package used to create it, for messages about updates

# For now we will just use the temporary setup password

weblink <- str_c("https://ku-awdc.github.io/rsc/goldfinger/users.gfp", "#", pwd, "#", "md")

users

keys_encr <- goldfinger:::gy_encrypt(serialize(users, NULL), "all")
stopifnot(all(names(users) %in% names(keys_encr$decrypt)))
stopifnot(all(table(names(keys_encr$decrypt))==1))
admin_public <- keys_encr$metadata$public_key

usernames <- data_encrypt(serialize(list(users = names(users), confirmation = str_c(hash(serialize(str_c(names(users), collapse="-"), NULL)), collapse=""), admin_public = admin_public), NULL), sha256(charToRaw(pwd)))

keys_encr
newusers <- list(group="goldfinger", usernames=usernames, keys_encr = keys_encr, package_version=c("goldfinger", goldfinger:::goldfinger_env$version), date_time = Sys.time())
