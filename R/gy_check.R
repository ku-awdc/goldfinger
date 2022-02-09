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

  local <- gy_check(upgrade_user(readRDS(path), path))
  package_env$currentlocal <- local

  ## TODO: implement switching between multiple groups
  package_env$currentgroup <- local$groups$default_group

  if(!silent) cat("User set to '", local$user, "' of group '", package_env$currentgroup, "' (from file '", path, "')\n", sep="")

  invisible(local)
}

#' @rdname gy_check
#' @export
gy_check <- function(local=NULL, silent=FALSE){

  if(is.null(local)) local <- package_env$currentlocal
  if(is.null(local)) local <- gy_userfile()

  group <- package_env$currentgroup
  ## TODO: allow switching between groups

  ## Check naming is OK:
  lcn <- names(local)
  epn <- c("user", "name", "email", "versions", "public_curve", "public_ed", "salt", "encr_curve", "encr_ed", "groups")
  if(length(lcn)!=length(epn) || !all(epn %in% lcn)){
    stop("An unexpected error occured while processing the user file - please contact the package author", call.=FALSE)
  }
  if(!is.list(local[["groups"]]) || !"default_group" %in% names(local[["groups"]])){
    stop("An unexpected error occured while processing the groups element of the user file - please contact the package author", call.=FALSE)
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
