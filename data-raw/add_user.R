
## OLD VERSION:

## Script to add a user to the public key list

library("goldfinger")
library("sodium")
library("keyring")
library("cyphr")
library("getPass")

current_users <- goldfinger:::gf_all_keys(fallback=FALSE, refresh=TRUE, all_users = TRUE)
current_users$md <- current_users$local_user
current_users$local_user <- NULL
current_users$md$salt <- NULL
current_users$md$private_encr <- NULL

attr(current_users, "live_data") <- NULL

## Protect the users file to prevent tampering:
pass <- tryCatch(
  key_get("goldfinger","user_regen"),
  error=function(e){
    tryCatch(key_delete("goldfinger", username="user_regen"), error=function(e) { })
    pass <- getPass(msg="Password (user_regen):  ")
    key_set_with_value("goldfinger", "user_regen", pass)
    return(pass)
  }
)

private_key <- sha256(charToRaw(str_c("007",pass)))
public_key <- pubkey(private_key)
stopifnot(identical(public_key, goldfinger:::users_sigkey))

# Not intended to prevent any real security, but will prevent web scraping:
fake_private <- sha256(charToRaw("goldfinger"))
fake_public <- pubkey(fake_private)

kp_u <- keypair_sodium(fake_public, private_key, authenticated=FALSE)

new_users <- list.files("data-raw", pattern='.gfp$')
for(nuf in new_users){

  nu_enc <- readRDS(file.path("data-raw", nuf))
  nu <- decrypt_object(nu_enc, kp_u)

  stopifnot(! nu$user %in% names(current_users))

  updated_users <- c(current_users, list(nu))
  names(updated_users) <- c(names(current_users), nu$user)
  current_users <- updated_users

  stopifnot(all(names(current_users[[nuf]])==names(current_users[["md"]])))

  file.rename(file.path("data-raw", nuf), file.path("local", "imported_users", nuf))

}
stopifnot(all(sapply(current_users, length)==length(current_users[[1]])))

kp_e <- keypair_sodium(fake_public, private_key)
kp_d <- keypair_sodium(public_key, fake_private)

users_enc <- encrypt_object(current_users, kp_e)
stopifnot(identical(current_users, decrypt_object(users_enc, kp_d)))

saveRDS(users_enc, file="inst/goldfinger_users.gfp")
file.copy("inst/goldfinger_users.gfp",  "~/Documents/GitHub/ku-awdc.github.io/rsc/goldfinger/goldfinger_users.gfp", overwrite=TRUE)

