#' Title
#'
#' @importFrom stringr str_remove str_c
#' @importFrom getPass getPass
#' @importFrom keyring key_set_with_value key_get key_list key_delete
#' @importFrom sodium sha256 keygen pubkey
#' @importFrom cyphr key_sodium keypair_sodium encrypt_object decrypt_object
#' @importFrom rstudioapi selectDirectory isAvailable
#'
#' @export
gf_setup <- function(){

  ## First ask for name, email, username, password

  cat("#### Setup goldfinger encryption ####\n")

  ## Basic info:
  name <- readline(prompt="Name:  ")
  email <- readline(prompt="Email:  ")
  tuser <- str_remove(email, "@.*")
  user <- readline(prompt=str_c("Username (leave blank to accept ", tuser, "):  "))
  if(user=="") user <- tuser

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
  # Convert to symmetric encryption key:
  sym_key <- key_sodium(sha256(charToRaw(pass)))
  # Set up asymmetric key pair:
  private_key <- keygen()
  public_key <- pubkey(private_key)
  # Then encrypt the private key:
  private_encr <- encrypt_object(private_key, sym_key)
  stopifnot(identical(private_key, decrypt_object(private_encr, sym_key)))

  version <- "0.1.0-1"
  date_time <- Sys.time()

  ## Create the storage file:
  save(name, email, user, version, date_time, private_encr, public_key, file=file.path(path, filename))
  cat("#### Setup complete ####\n")

  ## Add the path to the storage file to the user's Rprofile:

  rprofline <- str_c("options(goldfinger_path='", file.path(path, filename), "')\n")
  eval(parse(text=rprofline))
  cat("In order for goldfinger to work between R sessions, you need to add the following line to your R profile:\n", rprofline, "\n")
  ok <- readline(str_c("To do this automatically (for '", file.path("~", ".Rprofile"), "') type y:  "))
  if(tolower(ok)=="y") cat("\n\n## Added by the goldfinger package on ", as.character(Sys.Date()), ":\n", rprofline, "\n\n", sep="", file=file.path("~", ".Rprofile"), append=TRUE)

  gf_check()

  ## Create a file to be sent for public registration:
  cwd <- getwd()
  save(name, email, user, version, date_time, public_key, file=str_c("goldfinger_", user, ".gfp"))

  cat("We're done: please send the file '", str_c(cwd, "/goldfinger_", user, ".gfp"), "' to Matt\n", sep="")

  ## TODO: query online database to make sure this user does not already exist

}
