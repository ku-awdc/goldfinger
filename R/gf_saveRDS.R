#' @name gf_saveRDS
#' @title Save and read encrypted RDS
#' @param object
#' @param file
#' @param user
#' @param local_user
#' @param ascii
#' @param version
#' @param compress
#' @param overwrite
#'
#' @rdname gf_saveRDS
#' @export
gf_saveRDS <- function(object, file=stop("file must be specified (.rdg file extension is recommended)"), user=character(0), local_user=TRUE, ascii = FALSE, version = NULL, compress="xz", overwrite=FALSE){

  if(file.exists(file) && !overwrite) stop("Specified file exists: use overwrite=TRUE if necessary", call.=FALSE)

  if("gf_type" %in% names(attributes(file))){
    gf_type <- attr(file, "gf_type", TRUE)
  }else{
    gf_type <- "gf_saveRDS"
  }

  localuser <- gf_localuser()
  keys <- gf_all_keys(all_users = length(user)>0)
  live_data <- attr(keys, "live_data", TRUE)

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
    encrypt_object(sym_key, keypair_sodium(public, private_key))
  })
  user[user=="local_user"] <- keys$local_user$user
  names(decrypt_key) <- user

  ## Encrypt the objects themselves using sodium directly:
  object_encr <- data_encrypt(serialize(object, NULL), sym_key)

  ## Package the metadata:
  metadata <- list(user=keys$local_user$user, public_key=keys$local_user$public_key, email=keys$local_user$email, date_time=Sys.time(), gf_type=gf_type)

  ## And save:
  saveRDS(list(metadata=metadata, decrypt=decrypt_key, object_encr=object_encr), file=file, compress=compress)

}


#' @rdname gf_saveRDS
#' @export
gf_readRDS <- function(file=stop("file must be specified (.rdg file extension is recommended)")){

  fcon <- readRDS(file)

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

  sym_key <- decrypt_object(fcon$decrypt[[keys$local_user$user]], keypair_sodium(fcon$metadata$public_key, private_key))

  return(unserialize(data_decrypt(fcon$object_encr, sym_key)))

}