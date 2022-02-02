#' @name gy_encrypt
#' @title Encrypt and decrypt a pre-serialised object using goldeneye
#' @param object
#' @param file
#' @param user
#' @param local_user
#' @param ascii
#' @param version
#' @param compress
#' @param overwrite
#'
#' @rdname gy_encrypt
#' @export
gy_encrypt <- function(object, user=character(0), local_user=TRUE, comment = "", encr_fun = NULL){

  if(!is.raw(object)) stop("The object argument must be a single serialised object", call.=FALSE)

  ser_method <- attr(object, "ser_method", exact=TRUE)
  if(is.null(ser_method)){
    ser_method <- "custom"
  }

  localuser <- gf_localuser()
  keys <- gf_all_keys(all_users = length(user)>0)
  live_data <- attr(keys, "live_data", TRUE)

  ## Shortcut for all users:
  if("all" %in% user){
    user <- unique(c(user, names(keys)))
    user <- user[!user %in% c("all","local_user")]
  }
  if("local_user" %in% user) stop("Invalid user 'local_user' - please use your true username", call.=FALSE)

  ## Check the desired user(s) are available:
  if(!all(user %in% names(keys))){
    stop("One or more specified user is not available")
  }
  if(local_user){
    ## Remove duplicate user if there to avoid confusion:
    user <- user[!user %in% localuser]
    user <- c(user, "local_user")
  }

  stopifnot(localuser==keys$local_user$user)

  ## Get private and public keys for this user:
  pass <- key_get("goldfinger", username=keys$local_user$user)
  pass_key <- key_sodium(sha256(charToRaw(str_c(keys$local_user$salt,pass))))
  private_key <- decrypt_object(keys$local_user$private_encr, pass_key)
  public_key <- keys$local_user$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Generate a symmetric encryption key:
  sym_key <- keygen()

  ## Wrap this key in the potentially user-supplied function:
  if(is.null(encr_fun)){
    encr_fun <- function(key) function() key
  }
  ## Run the encrypt function to obtain the decrypt function
  # Note that this may have side effects of e.g. creating a file with a secondary key:
  decr_fun <- encr_fun(sym_key)

  if(!is.function(decr_fun)) stop("The encr_fun supplied must be a function that returns a function", call.=FALSE)
  if(!is.null(formals(decr_fun))) stop("The encr_fun supplied must be a function that returns a function that has no arguments", call.=FALSE)
  decr_fun <- serialize(decr_fun, NULL)

  ## Encrypt this for each user:
  decrypt_key <- lapply(user, function(u){
    public <- keys[[u]]$public_key

    rand <- sample.int(length(decr_fun))
    key_rand <- decr_fun[rand]
    reorder <- order(rand)
    stopifnot(all(key_rand[reorder]==decr_fun))

    keyval <- list(user = ifelse(u=="local_user", keys$local_user$user, u),
                   key_rand = key_rand,
                   reorder = reorder
    )
    class(keyval) <- "goldeneye_symkey"

    encrypt_object(serialize(keyval, NULL), keypair_sodium(public, private_key))
  })
  user[user=="local_user"] <- keys$local_user$user
  names(decrypt_key) <- user

  ## Encrypt the objects themselves using sodium directly:
  object_encr <- data_encrypt(object, sym_key)
  # Add the serialization method as an attribute:
  attr(object_encr, "ser_method") <- ser_method

  ## Package the metadata:
  metadata <- list(user=keys$local_user$user, public_key=keys$local_user$public_key, comment=comment, package_version=goldfinger_env$version, date_time=Sys.time())

  ## And return:
  retval <- list(group="goldfinger", metadata=metadata, decrypt=decrypt_key, object_encr=object_encr)
  class(retval) <- c("goldeneye","list")
  return(retval)

}


#' @rdname gf_encrypt
#' @export
gy_decrypt <- function(object){

  ## See if we are dealing with an old save format, and if so then upgrade:
  object <- upgrade_encrypt(object)

  ## Determine the local user:
  localuser <- gf_localuser()
  keys <- gf_all_keys(all_users = object$metadata$user != localuser)

  ## Get private and public keys for this user:
  pass <- key_get("goldfinger", username=keys$local_user$user)
  pass_key <- key_sodium(sha256(charToRaw(str_c(keys$local_user$salt,pass))))
  private_key <- decrypt_object(keys$local_user$private_encr, pass_key)
  public_key <- keys$local_user$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Find the relevant decrypt key:
  if(! keys$local_user$user %in% names(object$decrypt)){
    stop("You are not authorised to decrypt this file", call.=FALSE)
  }

  if(object$metadata$user %in% names(keys) && !identical(object$metadata$public_key, keys[[object$metadata$user]]$public_key)){
    stop("The data has been tampered with", call.=FALSE)
  }

  ser_method <- attr(object$object_encr, "ser_method", exact=TRUE)
  if(is.null(ser_method)){
    warning("The provided object did not have a serialization method attribute - assuming that this is base::serialize")
    ser_method <- "base"
  }

  enc_fun <- object$decrypt[[keys$local_user$user]]
  decr_fun <- unserialize(decrypt_object(enc_fun, keypair_sodium(object$metadata$public_key, private_key)))
  stopifnot(inherits(decr_fun, "goldeneye_symkey"))
  stopifnot(decr_fun$user == keys$local_user$user)
  sym_key <- unserialize(decr_fun$key_rand[decr_fun$reorder])()

  # Add ser_method
  object <- data_decrypt(object$object_encr, sym_key)

  attr(object, "ser_method") <- ser_method

  return(object)

}

