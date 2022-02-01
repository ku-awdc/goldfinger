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
gy_encrypt <- function(object, user=character(0), local_user=TRUE, comment = ""){

  if(!is.raw(object)) stop("The object argument must be a single serialised object", call.=FALSE)

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

  ## Encrypt this for each user:
  decrypt_key <- lapply(user, function(u){
    public <- keys[[u]]$public_key

    rand <- sample.int(32)
    key_rand <- sym_key[rand]
    reorder <- order(rand)
    stopifnot(all(key_rand[reorder]==sym_key))

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
  object <- gy_check(object)

  ## Determine the local user:
  localuser <- gf_localuser()
  keys <- gf_all_keys(all_users = fcon$metadata$user != localuser)

  ## Get private and public keys for this user:
  pass <- key_get("goldfinger", username=keys$local_user$user)
  pass_key <- key_sodium(sha256(charToRaw(str_c(keys$local_user$salt,pass))))
  private_key <- decrypt_object(keys$local_user$private_encr, pass_key)
  public_key <- keys$local_user$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Find the relevant decrypt key:
  if(! keys$local_user$user %in% names(fcon$decrypt)){
    stop("You are not authorised to decrypt this file", call.=FALSE)
  }

  if(fcon$metadata$user %in% names(keys) && !identical(fcon$metadata$public_key, keys[[fcon$metadata$user]]$public_key)){
    stop("The data has been tampered with", call.=FALSE)
  }

  keyval <- unserialize(decrypt_object(fcon$decrypt[[keys$local_user$user]], keypair_sodium(fcon$metadata$public_key, private_key)))
  stopifnot(inherits(keyval, "goldeneye_symkey"))
  stopifnot(keyval$user == keys$local_user$user)
  sym_key <- keyval$key_rand[keyval$reorder]

  return(unserialize(data_decrypt(fcon$object_encr, sym_key)))

}


gy_check <- function(object){

  # For potentially very old save versions:
  if(!is.null(object$metadata$package_version) && numeric_version(object$metadata$package_version) < 0.3){
    stop("Upgrading from version 1 or version 2 saves is not yet implemented", call.=FALSE)
  }
  if(!inherits(object, "goldeneye")) stop("The object to be decrypted must have been created using gy_encrypt", call.=FALSE)
  stopifnot(!is.null(object$metadata$package_version) && numeric_version(object$metadata$package_version) >= 0.3)

  if(numeric_version(object$metadata$package_version) < 0.4){
    ## Do something to upgrade if necessary
  }

  return(object)
}
