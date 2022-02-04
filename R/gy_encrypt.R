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
gy_encrypt <- function(object, user=character(0), local_user=TRUE, comment = "", funs = list(type="identity")){

  if(!is.raw(object)) stop("The object argument must be a single serialised object", call.=FALSE)

  ser_method <- attr(object, "ser_method", exact=TRUE)
  if(is.null(ser_method)){
    ser_method <- "custom"
  }

  localuser <- get_localuser()
  keys <- get_users(all_users=length(user)>0)

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

  ## Get private and public keys for this user:
  pass <- get_password(username=localuser$keyringuser)
  pass_key <- hash(charToRaw(str_c(localuser$salt,pass)))
  private_key <- data_decrypt(localuser$encr_curve, pass_key)
  public_key <- localuser$public_curve

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Generate a symmetric encryption key:
  sym_key <- keygen()

  ## Process the encr_fun types:
  if(!is.list(funs) || !"type" %in% names(funs)){
    stop("The funs argument must be a list, with first element 'type'", call.=FALSE)
  }
  if(".x" %in% names(funs)) stop("The name .x is reserved and cannot be in funs", call.=FALSE)
  type <- funs[["type"]]

  # Currently only two supported options:
  ## TODO: more types, and make run_custom=FALSE default
  if(type=="identity"){
    # Nothing to do here:
    encr_fun <- function(x) x
    decr_fun <- function(x) x
  }else if(type=="custom"){
    if(!all(c("encr_fun","decr_fun") %in% names(funs))) stop("For custom funs you must supply both encr_fun and decr_fun")
    encr_fun <- funs$encr_fun
    if(!is.function(encr_fun)) stop("The encr_fun supplied must be a function", call.=FALSE)
    if(!length(formals(encr_fun))==1) stop("The encr_fun supplied must be a function that takes a single argument", call.=FALSE)
    decr_fun <- funs$decr_fun
    if(!is.function(decr_fun)) stop("The decr_fun supplied must be a function", call.=FALSE)
    if(!length(formals(decr_fun))==1) stop("The decr_fun supplied must be a function that takes a single argument", call.=FALSE)
  }

  ## Check encr_fun and decr_fun are symmetric:
  funs$.x <- encr_fun(sym_key)
  if(!identical(sym_key, decr_fun(funs[[".x"]]))) stop("The provided encr_fun and decr_fun are not symmetric", call.=FALSE)
  funs <- serialize(funs, NULL)

  ## Encrypt this for each user:
  decrypt_key <- lapply(user, function(u){
    public <- if(u=="local_user") localuser$public_curve else keys[[u]]$public_curve

    rand <- sample.int(length(funs))
    key_rand <- funs[rand]
    reorder <- order(rand)
    stopifnot(all(key_rand[reorder]==funs))

    keyval <- list(user = ifelse(u=="local_user", localuser$user, u),
                   key_rand = key_rand,
                   reorder = reorder
    )
    class(keyval) <- "goldeneye_symkey"

    auth_encrypt(serialize(keyval, NULL), private_key, public)
  })
  user[user=="local_user"] <- localuser$user
  names(decrypt_key) <- user

  ## Encrypt the objects themselves:
  object_encr <- data_encrypt(object, sym_key)
  # Add the serialization method as an attribute:
  attr(object_encr, "ser_method") <- ser_method

  ## Package the metadata:
  metadata <- list(user=localuser$user, public_curve=localuser$public_curve, comment=comment, minimum_version="0.3.0", package_version=goldfinger_env$version, date_time=Sys.time())

  ## And return:
  retval <- list(group="goldfinger", metadata=metadata, decrypt=decrypt_key, object_encr=object_encr)
  class(retval) <- c("goldeneye","list")
  return(retval)

}


#' @rdname gf_encrypt
#' @export
gy_decrypt <- function(object, run_custom = TRUE){

  ## See if we are dealing with an old save format, and if so then upgrade:
  object <- upgrade_encrypt(object)

  ## Determine the local user:
  localuser <- get_localuser()
  keys <- get_users(all_users = object$metadata$user != localuser$user)

  ## Get private and public keys for this user:
  pass <- get_password(localuser$keyringuser)
  pass_key <- hash(charToRaw(str_c(localuser$salt,pass)))
  private_key <- data_decrypt(localuser$encr_curve, pass_key)
  public_key <- localuser$public_curve

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Find the relevant decrypt key:
  if(! localuser$user %in% names(object$decrypt)){
    stop("You are not authorised to decrypt this file", call.=FALSE)
  }

  if(object$metadata$user %in% names(keys)){
    if(!identical(object$metadata$public_curve, keys[[object$metadata$user]][["public_curve"]])){
      stop("The data has been tampered with", call.=FALSE)
    }
  }else{
    if(object$metadata$user != localuser$user){
      warning("The user that sent this file is not registered with the group", call.=FALSE)
    }
  }

  ser_method <- attr(object$object_encr, "ser_method", exact=TRUE)
  if(is.null(ser_method)){
    warning("The provided object did not have a serialization method attribute - assuming that this is base::serialize")
    ser_method <- "base"
  }

  crypt <- object$decrypt[[localuser$user]]
  uncrypt <- unserialize(auth_decrypt(crypt, private_key, object$metadata$public_curve))
  stopifnot(inherits(uncrypt, "goldeneye_symkey"))
  stopifnot(uncrypt$user == localuser$user)

  # Unserialise:
  funs <- unserialize(uncrypt$key_rand[uncrypt$reorder])
  stopifnot("type" %in% names(funs))
  type <- funs[["type"]]

  if(type=="identity"){
    # If the key is just a key:
    sym_key <- funs[[".x"]]
  }else if(type=="custom"){
    stopifnot("decr_fun" %in% names(funs))

    # If the key is a function then only run it if we have permission:
    # (as we cannot vouch for potential side effects):
    if(!run_custom){
      stop("The decryption algorithm requires running a function:  if you trust the source of the file then try again with the argument run_custom=TRUE", call.=FALSE)
    }
    sym_key <- funs[["decr_fun"]](funs[[".x"]])
  }else{
    stop("The decryption key/function is invalid", call.=FALSE)
  }

  # Add ser_method
  object <- data_decrypt(object$object_encr, sym_key)

  attr(object, "ser_method") <- ser_method

  return(object)

}

