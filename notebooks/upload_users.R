## TODO: cleanup and make into function

# Users and pwd must already be available
users <- goldfinger:::gf_all_keys(TRUE, TRUE)
users <- users[!names(users)=="local_user"]
pwd

library(sodium)
library(cyphr)

# TODO: back to working on new user setup...

# TODO: online users file should contain:
# 1. A temporary setup password (changed frequently) that just gets a list of current user names
# 2. A permanent password secured for public keys of all current users, signed with private key of admin user
# And also the name and version of the package used to create it, for messages about updates

# For now we will just use the temporary setup password

weblink <- str_c("https://ku-awdc.github.io/rsc/goldfinger/users.gyu", "#", pwd, "#", "md")

keys_encr <- gy_encrypt(gy_serialise(users, method="base"), "all")
stopifnot(all(names(users) %in% names(keys_encr$decrypt)))
stopifnot(all(table(names(keys_encr$decrypt))==1))
admin_public <- keys_encr$metadata$public_key

usernames <- data_encrypt(gy_serialise(list(group = "goldfinger", users = names(users), confirmation = str_c(hash(serialize(str_c(names(users), collapse="-"), NULL)), collapse=""), admin_public = admin_public), method="base"), sha256(charToRaw(pwd)))

keys_encr
newusers <- list(usernames=usernames, keys_encr = keys_encr, package_version=goldfinger:::goldfinger_env$version, date_time = Sys.time())

saveRDS(newusers, "users.gyu", compress=FALSE)
