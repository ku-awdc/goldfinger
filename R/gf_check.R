#' @name gf_utilities
#' @title Utilities for goldfinger encryption
#'
#' @param silent
#'

#' @rdname gf_utilities
#' @export
gf_check <- function(path = getOption('goldfinger_path'), silent=FALSE){

  if(is.null(path)) stop("Path to the goldfinger.gfu file not found: set options(goldfinger_path='...') and try again", call.=FALSE)
  if(!file.exists(path)) stop("No goldfinger.gfu file found at ", path)
  local <- readRDS(path)

  ## Check that the symmetric encryption key can be found:
  pass <- tryCatch(
    key_get("goldfinger", username=local$user),
    error=function(e){
      tryCatch(key_delete("goldfinger", username=local$user), error=function(e) { })
      pass <- getPass(msg="Password:  ")
      # Check the password works:
      sym_key <- key_sodium(sha256(charToRaw(str_c(local$salt,pass))))
      private_key <- decrypt_object(local$private_encr, sym_key)
      key_set_with_value("goldfinger", local$user, pass)
      return(pass)
    }
  )

  sym_key <- key_sodium(sha256(charToRaw(str_c(local$salt,pass))))
  private_key <- decrypt_object(local$private_encr, sym_key)
  public_key <- local$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  if(!silent) cat("goldfinger setup verified\n")

  goldfinger_env$localcache <- local
  invisible(local)

}

#' @rdname gf_utilities
#' @export
gf_users <- function(fallback=TRUE, refresh=FALSE){

  ## Get all info:
  all_keys <- gf_all_keys(refresh=refresh, all_users = TRUE)

  ## Drop the public keys and convert to data frame:
  live_data <- attr(all_keys, "live_data", TRUE)

  users <- bind_rows(lapply(all_keys, function(x){

    x$local <- FALSE

    # If this is the local user drop the private key and check vs public registry:
    if("private_encr" %in% names(x)){
      x$private_encr <- NULL
      x$salt <- NULL
      x$local <- TRUE
      if(x$user %in% names(all_keys)){
        if(!identical(x$public_key, all_keys[[x$user]]$public_key)){
          warning(str_c("Your public key does not match the online version for user '", x$user, "' - you should seek assistance"))
        }
      }else{
        warning(str_c("Your user profile '", x$user, "' is not (yet) online"))
      }
    }else if(x$user == all_keys$local_user$user){
      # Otherwise check and remove if this user is the same as the local user:
      return(NULL)
    }

    x$public_key <- NULL
    x$setup_date <- as.Date(x$date_time)

    return(as.data.frame(x))

  }))[,c("user","name","email","setup_date","local")]

  return(users)

}


## Underlying utility function is NOT exported

gf_localuser <- function(refresh=FALSE){

  if(refresh || is.null(goldfinger_env$local_user)){
    goldfinger_env$local_user <- gf_check(silent=TRUE)$user
  }

  return(goldfinger_env$local_user)

}

gf_all_keys <- function(refresh=FALSE, all_users=FALSE, fallback=TRUE){

  ## Obtain the public keys of other users from the web resource:
  if(all_users && (refresh || is.null(goldfinger_env$webcache))){
    ss <- try({
      webloc <- "https://ku-awdc.github.io/rsc/goldfinger/goldfinger_users.gfp"
      tmpfl <- tempdir(check=TRUE)
      download.file(webloc, file.path(tmpfl, "goldfinger_users.gfp"), quiet=TRUE, mode="wb")
      users_enc <- readRDS(file.path(tmpfl, "goldfinger_users.gfp"))
      unlink(file.path(tmpfl, "goldfiner_users.gfp"))
      live_data <- TRUE
    })
    if(inherits(ss,"try-error")){
      if(!fallback) stop("Unable to download the goldfinger_users.gfp file from the internet", call.=FALSE)
      warning("Unable to download the goldfinger_users.gfp file from the internet: using a cached version created during package build", call.=FALSE)
      instpub <- system.file("goldfinger_users.gfp", package = "goldfinger")
      users_enc <- readRDS(instpub)
      live_data <- FALSE
    }
    goldfinger_env$webcache <- users_enc
    goldfinger_env$live_data <- live_data
  }else{
    users_enc <- goldfinger_env$webcache
    live_data <- goldfinger_env$live_data
  }

  ## Decrypt:
  if(all_users){
    kp_d <- keypair_sodium(users_sigkey, sha256(charToRaw("goldfinger")))
    users <- decrypt_object(users_enc, kp_d)
  }else{
    users <- NULL
  }

  ## Obtain local user info:
  if(refresh || is.null(goldfinger_env$localcache)){
    local_user <- gf_check(silent=TRUE)
    goldfinger_env$localcache <- local_user
  }
  local_user <- goldfinger_env$localcache

  rv <- c(list(local_user = local_user), users)
  attr(rv, "live_data") <- live_data

  return(rv)

}


users_sigkey <- as.raw(c(0x02, 0x18, 0x05, 0x6e, 0x4c, 0x28, 0x07, 0xd8, 0x67,
    0x27, 0x7f, 0x0f, 0x77, 0xe5, 0x3a, 0x5a, 0x3e, 0x12, 0xb9, 0x9e,
    0x02, 0x0d, 0x3b, 0xea, 0x5b, 0x0a, 0xdc, 0xfc, 0x8b, 0x9b, 0x70,
    0x17))

goldfinger_env <- new.env()
goldfinger_env$webcache <- NULL
goldfinger_env$live_data <- FALSE
goldfinger_env$localcache <- NULL
goldfinger_env$local_user <- NULL
## TODO: retrieve version automatically
goldfinger_env$version <- "0.2.0-1"
