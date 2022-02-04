#' Title
#'
#' @importFrom stringr str_remove str_c
#' @importFrom getPass getPass
#' @importFrom keyring key_set_with_value key_get key_list key_delete
#' @importFrom sodium hash keygen pubkey sig_keygen sig_pubkey data_encrypt data_decrypt sig_sign sig_verify simple_encrypt simple_decrypt auth_encrypt auth_decrypt
#' @importFrom rstudioapi selectDirectory isAvailable
#'
#' @export
gy_setup <- function(){

  cat("#### Setup goldeneye encryption ####\n")

  ## First ask for web link and password for users file
  weblink <- readline(prompt="Setup link:  ")
  # Should be in the format https://*link*#*password*#*admin*
  # Test validity and obtain current user information:
  keys <- refresh_users(weblink, setup=TRUE)

  ## Then ask for name, email, username:
  name <- readline(prompt="Name:  ")
  email <- readline(prompt="Email:  ")
  tuser <- tolower(str_remove(email, "@.*"))
  chkuser <- function(user, err=FALSE){
    msg <- ""
    if(tolower(user)=="local_user") msg <- ("The username 'local_user' cannot be used")
    if(tolower(user)=="all") msg <- ("The username 'all' cannot be used")
    if(tolower(user)=="admin") msg <- ("The username 'admin' cannot be used")
    if(gsub("[[:alnum:]]","",user)!="") msg <- ("The username can only contain letters and numbers")
    if(tolower(user) %in% tolower(keys$users$usernames)) msg <- ("That username is already taken: to re-use your own username please contact the group admin")
    if(err && msg!="") stop(msg, call.=FALSE)
    invisible(msg)
  }
  if(chkuser(tuser, err=FALSE)==""){
    user <- tolower(readline(prompt=str_c("Username (leave blank to accept ", tuser, "):  ")))
    if(user=="") user <- tuser
  }else{
    user <- tolower(readline(prompt=str_c("Username:  ")))
  }
  chkuser(user, err=TRUE)

  ## Password:
  repeat{
    pass <- getPass(msg="Password:  ", noblank = TRUE)
    pass2 <- getPass(msg="Password (confirm):  ", noblank = TRUE)
    if(pass==pass2) break
    cat("Error:  passwords do not match!  Try again...\n")
  }

  ## File locations:
  repeat{
    filename <- readline(prompt=str_c("User file (leave blank to accept ", keys$group, "_", user, ".gyp):  "))
    if(filename=="") filename <- str_c(keys$group, "_", user, ".gyp")
    cat("Please select a location to store this file...\n")
    # rstudioapi version:
    if(isAvailable("1.1.288")){
      Sys.sleep(1)
      path <- selectDirectory()
    }else{
      repeat{
        path <- readline(prompt="Directory to use:  ")
        if(dir.exists(path)) break
        cat("Error: directory not found ... please try again\n")
      }
    }

    if(!file.exists(file.path(path, filename))) break
    cat("Error:  file already exists, enter a new filename\nor manually delete the old file before proceeding\n")
  }

  # Store the password:
  key_set_with_value("goldeneye", str_c(keys$group, ":", user), pass)
  # Generate and store a salt:
  salt <- str_c(sample(c(letters,LETTERS,0:9),6),collapse="")
  # Convert to symmetric encryption key:
  sym_key <- hash(charToRaw(str_c(salt,pass)), size=32)

  ## Set up asymmetric curve25519 key pair for encryption:
  private_curve <- keygen()
  public_curve <- pubkey(private_curve)
  # Then encrypt the private curve key:
  encr_curve <- data_encrypt(private_curve, sym_key)
  stopifnot(identical(private_curve, data_decrypt(encr_curve, sym_key)))

  ## Set up asymmetric ed25519 key pair for signing:
  private_ed <- sig_keygen()
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

  ## Create the storage file:
  group <- keys[["group"]]
  version <- goldfinger_env[["version"]]
  date_time <- Sys.time()

  public_save <- list(user=user, name=name, email=email, version=version, date_time=date_time, public_curve=public_curve, public_ed=public_ed)

  # Allow a single profile file to contain multiple groups (assuming that username and key are the same, so just the admin key differs):
  admin_ed <- list(keys[["admin_ed"]])
  names(admin_ed) <- group

  private_save <- c(public_save, list(salt=salt, encr_curve=encr_curve, encr_ed=encr_ed, admin_ed=admin_ed, weblink=weblink))
  saveRDS(private_save, file=file.path(path, filename), compress=FALSE)

  public_save <- c(public_save, list(group=group))


  cat("#### Setup complete ####\n")

  ## Add the path to the storage file to the user's Rprofile:

  rprofline <- str_c("options(goldeneye_path='", file.path(path, filename), "')\n")
  eval(parse(text=rprofline))
  cat("In order for goldeneye to work between R sessions, you need\nto add the following line to your R profile:\n", rprofline, "\n")
  ok <- readline(str_c("To do this automatically (for '", file.path("~", ".Rprofile"), "') type y:  "))
  if(tolower(ok)=="y"){
    cat("\n\n## Added by the goldeneye package on ", as.character(Sys.Date()), ":\n", rprofline, "\n\n", sep="", file=file.path("~", ".Rprofile"), append=TRUE)
    cat("R profile file appended\n")
  }

  gy_userfile()

  ## Create a file to be sent for public registration:
  public_encry <- data_encrypt(serialize(public_save, NULL), hash(charToRaw(keys$webpwd)))

  pfilen <- str_c(keys$group, "_", user, "_public.gyp")
  saveRDS(public_encry, file=pfilen, compress=FALSE)

  cat("Account creation complete: please send the following file to the group admin:  '", pfilen, "'\nNOTE: in sending this file, you consent to your name and email address (as given above) being stored and made available in encrypted form via ", keys$weburl, "\n", sep="")

  goldfinger_env$group <- keys$group

  ## TODO: add something more about GDPR ??

}

