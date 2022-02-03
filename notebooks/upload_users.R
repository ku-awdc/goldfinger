## TODO: cleanup and make into function

# Users and pwd must already be available
users <- goldfinger:::gf_all_keys(TRUE, TRUE)
users <- users[!names(users)=="local_user"]
pwd

library(sodium)
library(cyphr)
library(goldfinger)

# TODO: back to working on new user setup...

weblink <- paste0("https://ku-awdc.github.io/rsc/goldfinger/users.gyu", "#", pwd, "#", "md")

## Note:  usernames may also include previous (no longer valid) usernames
usernames <- names(users)

keys <- list(group="goldfinger", package_version=goldfinger:::goldfinger_env$version, date_time = Sys.time(), usernames=usernames, users=users)
keys_encr <- data_encrypt(gy_serialise(keys, method="base"), sha256(charToRaw(pwd)))

saveRDS(keys_encr, "users.gyu", compress=FALSE)


stop("old from here - using key pairs causes big files and is unnecessary")

# OLD: online users file should contain:
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


# This function only gets called to set up a new user for a group:
setup_users <- function(weblink){

  stopifnot(is.character(weblink), length(weblink)==1, !is.na(weblink))
  if(!str_detect(weblink, "#")) stop("Invalid setup link provided (no #)", call.=FALSE)
  if(!str_detect(weblink, "^https://")) stop("Invalid setup link provided (not a URL)", call.=FALSE)

  weblink <- str_split(weblink, "#")[[1]]
  if(!length(weblink)==3) stop("Invalid setup link provided (cannot split twice on #)", call.=FALSE)

  tmpfl <- tempdir(check=TRUE)
  download.file(weblink[1], file.path(tmpfl, "users.gyu"), quiet=TRUE, mode="wb")
  on.exit(unlink(file.path(tmpfl, "users.gyu")))

  users_enc <- readRDS(file.path(tmpfl, "users.gyu"))
  group <- users_enc$group
  usernames <- unserialize(data_decrypt(users_enc$usernames, sha256(charToRaw(weblink[2]))))

  return(usernames)
}

# This function gets called to refresh users (typically once per R session) after joining the group:
refresh_users <- function(weblink, admin_user, admin_public){

  stopifnot(is.character(weblink), length(weblink)==1, !is.na(weblink))
  if(!str_detect(weblink, "^https://")) stop("Invalid setup link provided (not a URL)", call.=FALSE)

  tmpfl <- tempdir(check=TRUE)
  download.file(weblink[1], file.path(tmpfl, "users.gyu"), quiet=TRUE, mode="wb")
  on.exit(unlink(file.path(tmpfl, "users.gyu")))
  users_enc <- readRDS(file.path(tmpfl, "users.gyu"))

  ## TODO: got to here
  stop("TODO: check validity of public key")
  if(!all(users_enc$keys_encr$metadata$user == admin_user)){
    stop()
  }
  if(!all(users_enc$keys_encr$metadata$public_key == admin_public)){
    stop()
  }

  users <- gy_deserialise(gy_decrypt(users_enc$keys_encr))
  return(users)
}

# Function called repeatedly in a session:
get_users <- function(all=FALSE, refresh=FALSE){
  stop("TODO")
}
