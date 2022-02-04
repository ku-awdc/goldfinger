upgrade_user <- function(local, path){

  # Major change from version <=2 to version 3:
  if(numeric_version(local[["version"]]) < 0.3){

    if(!local$user %in% c("md","mossa","makg")){
      stop("The upgrade function is not configured for you - please contact Matt for help", call.=FALSE)
    }

    oldpath <- path

    cat("#### Upgrading goldfinger to goldeneye... ####\n")

    ## Get name/email/user/salt:
    name <- local[["name"]]
    email <- local[["email"]]
    user <- local[["user"]]
    salt <- local[["salt"]]

    # Get old password format:
    pass <- tryCatch(
      key_get("goldfinger", username=local$user),
      error=function(e){
        tryCatch(key_delete("goldfinger", username=local$user), error=function(e) { })
        pass <- getPass(msg="Password:  ")
        # Check the password works:
        sym_key <- cyphr::key_sodium(sodium::sha256(charToRaw(str_c(local$salt,pass))))
        private_key <- cyphr::decrypt_object(local$private_encr, sym_key)
        key_set_with_value("goldfinger", local$user, pass)
        return(pass)
      }
    )

    sym_key <- cyphr::key_sodium(sodium::sha256(charToRaw(str_c(local$salt,pass))))
    private_key <- cyphr::decrypt_object(local$private_encr, sym_key)
    public_key <- local$public_key

    ## Validate with the public key:
    public_test <- pubkey(private_key)
    if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)


    ## Generate the updated user profile

    # Encrypted path/password info for the 3 users on goldfinger v0.2:
    weblinfo <- readRDS(system.file("legacy", "upgrade0.2.rds", package="goldfinger"))
    stopifnot(local$user %in% names(weblinfo))
    weblink <- unserialize(simple_decrypt(weblinfo[[local$user]], private_key))

    # Test validity and obtain current user information:
    keys <- refresh_users(weblink, setup=TRUE)

    # Store the new password format:
    key_set_with_value("goldeneye", str_c(keys$group, ":", user), pass)
    # Convert to symmetric encryption key:
    sym_key <- hash(charToRaw(str_c(salt,pass)), size=32)

    ## Set up asymmetric curve25519 key pair for encryption:
    private_curve <- private_key
    public_curve <- pubkey(private_curve)
    stopifnot(identical(public_curve, public_key))
    # Then encrypt the private curve key:
    encr_curve <- data_encrypt(private_curve, sym_key)
    stopifnot(identical(private_curve, data_decrypt(encr_curve, sym_key)))

    ## Set up new asymmetric ed25519 key pair for signing:
    private_ed <- sig_keygen()
    # For testing purposes only:
    if("encr_ed" %in% names(local)){
      private_ed <- data_decrypt(local[["encr_ed"]], sym_key)
    }
    public_ed <- sig_pubkey(private_ed)
    # Then encrypt the private ed key:
    encr_ed <- data_encrypt(private_ed, sym_key)
    stopifnot(identical(private_ed, data_decrypt(encr_ed, sym_key)))

    ## Tests:
    msg <- serialize("test", NULL)
    tt <- sig_sign(msg, private_ed)
    stopifnot(sig_verify(msg, tt, public_ed))
    tt <- simple_encrypt(msg, public_curve)
    stopifnot(identical(msg, simple_decrypt(tt, private_curve)))

    ## Update filename:
    filename <- gsub("\\.gfu$", ".gyp", oldpath)

    ## Create the storage file:
    group <- keys[["group"]]
    version <- goldfinger_env[["version"]]
    date_time <- Sys.time()

    public_save <- list(user=user, name=name, email=email, version=version, date_time=date_time, public_curve=public_curve, public_ed=public_ed)

    # Allow a single profile file to contain multiple groups (assuming that username and key are the same, so just the admin key differs):
    admin_ed <- list(keys[["admin_ed"]])
    names(admin_ed) <- group
    private_save <- c(public_save, list(salt=salt, encr_curve=encr_curve, encr_ed=encr_ed, admin_ed=admin_ed, weblink=weblink))
    saveRDS(private_save, file=filename, compress=FALSE)

    public_save <- c(public_save, list(group=group))

    if(user!="md") unlink(path)
    cat("NOTE: a new profile has been created at ", filename, "\n(The old profile at ", path, " has been deleted)\nYour Rprofile file has been updated but the old references to goldfinger in Rprofile\nand your system keychain have not been removed (you can do that yourself if you like)\n", sep="")

    ## Add the path to the storage file to the user's Rprofile:
    rprofline <- str_c("options(goldeneye_path='", filename, "')\n")
    eval(parse(text=rprofline))
    cat("\n\n## Added by the goldeneye package on ", as.character(Sys.Date()), ":\n", rprofline, "\n\n", sep="", file=file.path("~", ".Rprofile"), append=TRUE)

    ## Create a file to be sent for public registration:
    public_encry <- data_encrypt(serialize(public_save, NULL), hash(charToRaw(keys$webpwd)))

    pfilen <- str_c(keys$group, "_", user, "_public.gyp")
    saveRDS(public_encry, file=pfilen, compress=FALSE)

    cat("Please send the following file to Matt:  '", pfilen, "'\nNOTE: in sending this file, you consent to your name and email address (as given above) being stored and made available in encrypted form via ", keys$weburl, "\n", sep="")

    cat("#### Upgrade complete ####\n")

    local <- gy_userfile()
  }

  return(local)

}



upgrade_encrypt <- function(object){

  # For potentially very old save versions:
  if(!is.null(object$metadata$package_version) && numeric_version(object$metadata$package_version) < 0.3){
    stop("Upgrading from version 1 or version 2 saves is not yet implemented", call.=FALSE)
    # Probably need to decrypt here and then re-encrypt using the new function??
  }
  if(!inherits(object, "goldeneye")) stop("The object to be decrypted must have been created using gy_encrypt", call.=FALSE)
  stopifnot(!is.null(object$metadata$package_version) && numeric_version(object$metadata$package_version) >= 0.3)

  if(numeric_version(object$metadata$package_version) < 0.4){
    ## Do something to upgrade if necessary
  }

  return(object)
}
