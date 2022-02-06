#' @name gy_check
#' @title Utilities for goldfinger encryption
#'
#' @param silent
#'

#' @rdname gy_check
#' @export
gy_userfile <- function(path = getOption('goldeneye_path'), silent=FALSE){

  # For backwards compatibility:
  if(is.null(path)) path <- getOption('goldfinger_path')

  if(is.null(path)) stop("Path to the goldeneye user file not found: set options(goldeneye_path='...') and try again", call.=FALSE)
  if(!file.exists(path)) stop("No goldeneye user file found at ", path)

  local <- upgrade_user(readRDS(path), path)

  goldfinger_env$localuser <- gy_check(local)
  ## TODO: implement multiple groups
  goldfinger_env$group <- names(local$admin_ed)[1]
  goldfinger_env$user <- local$user

  invisible(local)
}

#' @rdname gy_check
#' @export
gy_check <- function(local=NULL, silent=FALSE){

  if(is.null(local)) stop("FIXME")

  # Take the first group if there are multiple:
  group <- names(local[["admin_ed"]][1])
  ## TODO: allow switching between groups

  ## Check naming is OK:
  if(!identical(hash(serialize(names(local), NULL)), as.raw(c(0x4a, 0x5e, 0x00, 0x0d, 0x15, 0x5f, 0xe4, 0x61, 0x52, 0x10, 0x1a, 0xb3, 0xe8, 0x64, 0x64, 0x0f, 0xac, 0x5c, 0x83, 0xaf, 0x47, 0xb5, 0x3a, 0xf0, 0x29, 0x21, 0xfc, 0xaa, 0x0d, 0xa0, 0x52, 0xef)))){
    stop("An unexpected error occured while processing the user file - please contact the package author", call.=FALSE)
  }

  ## Obtain the private curve key:
  private_curve <- get_gykey(group, local$user, local$salt, local$encr_curve)
  public_curve <- local$public_curve
  public_test <- pubkey(private_curve)
  if(!identical(public_curve, public_test)) stop("Something went wrong: the public curve key cannot be regenerated", call.=FALSE)

  ## Obtain the private ed key:
  private_ed <- get_gykey(group, local$user, local$salt, local$encr_ed)
  public_ed <- local$public_ed
  public_test <- sig_pubkey(private_ed)
  if(!identical(public_ed, public_test)) stop("Something went wrong: the public ed key cannot be regenerated", call.=FALSE)

  invisible(local)
}
