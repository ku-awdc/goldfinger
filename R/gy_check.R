#' @name gy_check
#' @title Utilities for goldfinger encryption
#'
#' @param silent
#'

#' @rdname gy_check
#' @export
gy_check <- function(path = getOption('goldfinger_path'), silent=FALSE){

  if(is.null(path)) stop("Path to the goldfinger.gfu file not found: set options(goldfinger_path='...') and try again", call.=FALSE)
  if(!file.exists(path)) stop("No goldfinger.gfu file found at ", path)
  local <- readRDS(path)

  # local <- gy_upgrade_user(local)

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
