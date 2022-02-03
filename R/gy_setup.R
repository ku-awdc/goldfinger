#' Title
#'
#' @importFrom stringr str_remove str_c
#' @importFrom getPass getPass
#' @importFrom keyring key_set_with_value key_get key_list key_delete
#' @importFrom sodium sha256 keygen pubkey data_encrypt data_decrypt
#' @importFrom cyphr key_sodium keypair_sodium encrypt_object decrypt_object
#' @importFrom rstudioapi selectDirectory isAvailable
#'
#' @export
gy_setup <- function(){

  cat("#### Setup goldeneye encryption ####\n")

  ## First ask for web link and password for users file
  weblink <- readline(prompt="Setup link:  ")
  # Should be in the format https://*link*#*password*#*admin*
  # Test validity and obtain current user information:
  keys <- refresh_users(weblink)

  ## Then ask for name, email, username:
  name <- readline(prompt="Name:  ")
  email <- readline(prompt="Email:  ")
  tuser <- tolower(str_remove(email, "@.*"))
  chkuser <- function(user, err=FALSE){
    msg <- ""
    if(tolower(user)=="local_user") msg <- ("The username 'local_user' cannot be used")
    if(tolower(user)=="all") msg <- ("The username 'all' cannot be used")
    if(gsub("[[:alnum:]]","",user)!="") msg <- ("The username can only contain letters and numbers")
    if(tolower(user) %in% tolower(keys$usernames)) msg <- ("That username is already taken: to re-use your own username please contact the group admin")
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
  sym_key <- key_sodium(sha256(charToRaw(str_c(salt,pass))))
  # Set up asymmetric key pair:
  private_key <- keygen()
  public_key <- pubkey(private_key)
  # Then encrypt the private key:
  private_encr <- encrypt_object(private_key, sym_key)
  stopifnot(identical(private_key, decrypt_object(private_encr, sym_key)))

  version <- goldfinger_env$version
  date_time <- Sys.time()

  ## Create the storage file:
  public_save <- list(name=name, email=email, user=user, version=version, date_time=date_time, public_key=public_key, group=keys$group)
  saveRDS(c(public_save, list(salt=salt, private_encr=private_encr, admin_public=keys$admin_public)), file=file.path(path, filename), compress=FALSE)

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

  gy_check()

  ## Create a file to be sent for public registration:
  public_encry <- simple_encrypt(serialize(public_save, NULL), keys$admin_public)

  pfilen <- str_c(keys$group, "_", user, "_public.gyp")
  saveRDS(public_encry, file=pfilen, compress=FALSE)

  cat("Account creation complete: please send the following file to the group admin:\n'", pfilen, "'\nNOTE: in sending this file, you consent to your name and email address (as given above) being stored and made available in encrypted form via ", keys$weburl, "\n", sep="")

  ## TODO: add something more about GDPR ??

}

# This function only gets called to set up a new user for a group:
refresh_users <- function(weblink, silent=FALSE){

  stopifnot(is.character(weblink), length(weblink)==1, !is.na(weblink))
  if(!str_detect(weblink, "#")) stop("Invalid setup link provided (no #)", call.=FALSE)
  if(!str_detect(weblink, "^https://")) stop("Invalid setup link provided (not a URL)", call.=FALSE)

  weblink <- str_split(weblink, "#")[[1]]
  if(!length(weblink)==3) stop("Invalid setup link provided (cannot split twice on #)", call.=FALSE)

  if(!silent) cat("Downloading user list...\n")
  tmpfl <- tempdir(check=TRUE)
  download.file(weblink[1], file.path(tmpfl, "users.gyu"), quiet=TRUE, mode="wb")
  on.exit(unlink(file.path(tmpfl, "users.gyu")))

  users_enc <- readRDS(file.path(tmpfl, "users.gyu"))
  keys <- unserialize(data_decrypt(users_enc, sha256(charToRaw(weblink[2]))))

  ## Cache within environment:
  goldfinger_env$webcache[[keys$group]] <- keys$users

  ## Retrieve the public key of the admin for setup:
  keys$admin_public <- keys$users[[weblink[3]]]$public_key
  keys$weburl <- weblink[1]

  invisible(keys)
}

# Function called repeatedly in a session:
get_users <- function(group=goldfinger_env$group, all_users=FALSE, refresh=FALSE){
  stop("TODO")
}
