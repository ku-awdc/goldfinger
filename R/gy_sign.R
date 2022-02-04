#' @name gy_sign
#' @title Sign and verify a file
#'
#' @param object
#'
#' @return
#' @export
#'

#' @rdname gy_serialise
#' @export
gy_sign <- function(object, method="hash"){

  ## TODO: method can be hash, base, qs, none (where none means it is already raw)

  ## Serialise/hash the object:
  sopts <- c("hash", serialization_options[serialization_options!="custom"], "none")
  mtch <- pmatch(method, sopts)
  if(is.na(mtch)) stop(str_c("Unrecognised serialisation method '", method, "' - options are: ", str_c(sopts, collapse=", ")))
  method <- sopts[mtch]
  if(method %in% serialization_options){
    object <- gy_serialise(object, method=method)
  }else if(method=="hash"){
    object <- hash(serialize(object, NULL))
  }else if(method=="none"){
    if(!is.raw(object)) stop("The object must be type raw for method=none", call.=FALSE)
  }else{
    stop("Serialisation method '", method, "' is not yet implemented - perhaps update the package?", call.=FALSE)
  }

  ## Get private and public keys for this user:
  local <- get_localuser()
  pass <- get_password(local$keyringuser)
  pass_key <- hash(charToRaw(str_c(local$salt,pass)))
  private_ed <- data_decrypt(local$encr_ed, pass_key)
  public_ed <- local$public_ed

  ## Validate with the public key:
  public_test <- sig_pubkey(private_ed)
  if(!identical(public_ed, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Sign the object:
  signature <- sig_sign(object, private_ed)
  attr(signature, "user") <- str_c(local$group, ":", local$user)
  attr(signature, "ser_method") <- method

  return(signature)
}


#' @rdname gy_sign
#' @export
gy_verify <- function(object, signature, public_ed = NULL, silent=FALSE){

  if(!is.raw(signature)) stop("The provided signature must be of type raw", call.=FALSE)

  ## Serialise/hash the object:
  sopts <- c("hash", serialization_options[serialization_options!="custom"], "none")
  mtch <- pmatch(attr(signature, "ser_method", exact=TRUE), sopts)
  if(length(mtch)!=1 || is.na(mtch)) stop(str_c("Unrecognised serialisation method attribute '", method, "' - options are: ", str_c(sopts, collapse=", ")))
  method <- sopts[mtch]
  if(method %in% serialization_options){
    object <- gy_serialise(object, method=method)
  }else if(method=="hash"){
    object <- hash(serialize(object, NULL))
  }else if(method=="none"){
    if(!is.raw(object)) stop("The object must be type raw for method=none", call.=FALSE)
  }else{
    stop("Serialisation method '", method, "' is not yet implemented - perhaps update the package?", call.=FALSE)
  }

  ## Get the relevant public key:
  if(is.null(public_ed)){
    public_ed <- get_public_key(attr(signature, "user", exact=TRUE), "ed")
  }

  ## Verify:
  save(object, signature, public_ed, file="debug_file_for_matt.rda")
  ok <- try(sig_verify(object, signature, public_ed))

  if(inherits(ok, "try-error")) ok <- FALSE

  if(!silent){
    if(ok){
      cat("Verification succeeded\n")
    }else{
      stop("Verification failed - the object may have been tampered with", call.=FALSE)
    }
  }

  invisible(ok)

}
