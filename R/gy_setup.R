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
  usernames <- setup_users(weblink)

  ## TODO: got to here

  ## TODO:  check the username has not already been used, and contains only A-Za-z0-9

  ## TODO: save admin_user, admin_public, group inside .gyp file

  ## Then ask for name, email, username, password

  ## Basic info:
  name <- readline(prompt="Name:  ")
  email <- readline(prompt="Email:  ")
  tuser <- str_remove(email, "@.*")
  user <- readline(prompt=str_c("Username (leave blank to accept ", tuser, "):  "))
  if(user=="") user <- tuser
  if(tolower(user)=="local_user") stop("The username 'local_user' cannot be used", call. = FALSE)

  ## Password:
  repeat{
    pass <- getPass(msg="Password:  ", noblank = TRUE)
    pass2 <- getPass(msg="Password (confirm):  ", noblank = TRUE)
    if(pass==pass2) break
    cat("Error:  passwords do not match!  Try again...\n")
  }

  ## File locations:
  repeat{
    filename <- readline(prompt=str_c("User file (leave blank to accept goldfinger_", user, ".gfu):  "))
    if(filename=="") filename <- str_c("goldfinger_", user, ".gfu")
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
  key_set_with_value("goldfinger", user, pass)
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
  public_save <- list(name=name, email=email, user=user, version=version, date_time=date_time, public_key=public_key)
  saveRDS(c(public_save, list(salt=salt, private_encr=private_encr)), file=file.path(path, filename), compress=compress)

  cat("#### Setup complete ####\n")

  ## Add the path to the storage file to the user's Rprofile:

  rprofline <- str_c("options(goldfinger_path='", file.path(path, filename), "')\n")
  eval(parse(text=rprofline))
  cat("In order for goldfinger to work between R sessions, you need\nto add the following line to your R profile:\n", rprofline, "\n")
  ok <- readline(str_c("To do this automatically (for '", file.path("~", ".Rprofile"), "') type y:  "))
  if(tolower(ok)=="y"){
    cat("\n\n## Added by the goldfinger package on ", as.character(Sys.Date()), ":\n", rprofline, "\n\n", sep="", file=file.path("~", ".Rprofile"), append=TRUE)
    cat("R profile file appended\n")
  }

  gf_check()

  ## Create a file to be sent for public registration:
  kp <- keypair_sodium(users_sigkey, private_key, authenticated=FALSE)
  public_encry <- encrypt_object(public_save, kp)

  saveRDS(public_encry, file=str_c("goldfinger_", user, ".gyp"), compress=compress)

  cat("We're done: please send the following file to Matt:\n'", str_c(getwd(), "/goldfinger_", user, ".gfp"), "'\n", sep="")

  ## TODO: query online database to make sure this user does not already exist

}

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
