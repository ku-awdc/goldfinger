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
  lcn <- names(local)
  epn <- c("user", "name", "email", "versions", "public_curve", "public_ed", "salt", "encr_curve", "encr_ed", "admin_ed", "weblink")
  if(length(lcn)!=length(epn) || !all(epn %in% lcn)){
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
