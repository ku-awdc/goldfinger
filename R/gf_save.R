#' Title
#'
#' @param ...
#' @param user
#'
#' @export
gf_save <- function(..., list=character(), file="encrypted_data.rdg", user=gf_user(), compress="xz"){

  names <- as.character(substitute(list(...)))[-1L]
  if(length(names)==0) stop("No objects passed to be saved", call.=FALSE)
  list <- c(list, names)
  objects <- mget(list)
  names(objects) <- list

  info <- gf_check(silent=TRUE)

  ## TODO: download and check user database, then add local user if not part of that

  ## Generate a symmetric encryption key:
  sym_key <- key_sodium(keygen())

  ## Encrypt this for each user:
  decrypt_key <- lapply(user, function(u){

    ## TODO: find public key for this user:
    public <- info$public_key

    encrypt_object(sym_key, keypair_sodium(public, info$private_key))
  })
  names(decrypt_key) <- user

  ## Encrypt the objects themselves:
  objects_encr <- encrypt_object(objects, sym_key)

  ## Package the metadata:
  metadata <- list(decrypt=decrypt_key, user=info$user, public_key=info$public_key, email=info$email, date_time=Sys.time())

  ## And save:
  save(metadata, objects_encr, file=file, compress=compress)
  invisible(file)

}


gf_load <- function(){

  decrypt_object(decrypt_key$md, keypair_sodium(info$public_key, info$private_key))

}
