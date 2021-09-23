#' @name gf_utilities
#' @title Utilities for goldfinge encryption
#'
#' @param silent
#'

#' @rdname gf_utilities
#' @export
gf_check <- function(silent=FALSE){

  ## Find the location:
  path <- getOption('goldfinger_path')
  if(is.null(path)) stop("Path to the goldfinger.gfu file not found: set options(goldfinger_path='...') and try again", call.=FALSE)
  if(!file.exists(path)) stop("No goldfinger.gfu file found at ", path)
  gfenv <- new.env()
  load(path, envir=gfenv)
  # as.list(gfenv)

  ## Check that the symmetric encryption key can be found:
  pass <- key_get("goldfinger", username=gfenv$user)
  sym_key <- key_sodium(sha256(charToRaw(pass)))
  private_key <- decrypt_object(gfenv$private_encr, sym_key)
  public_key <- gfenv$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  if(!silent) cat("goldfinger setup verified\n")

  rv <- as.list(gfenv)
  rv$private_key <- private_key
  invisible(rv)

}

#' @rdname gf_utilities
#' @export
gf_user <- function(){
  gf_check(silent=FALSE)$user
}
