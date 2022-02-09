#' Title
#'
#' @param group
#' @param refresh
#'
#' @return
#' @export
#'
#' @examples
gy_users <- function(group=NULL, refresh=FALSE){

  if(is.null(package_env$currentlocal)) gy_userfile()
  if(is.null(group)) group <- package_env$currentgroup
  users <- get_users(all_users=TRUE, group=group, refresh=refresh)

  ## TODO: prettier printing
  print(lapply(users, function(x) x[c("user","name","email","date_time")]))

  invisible(names(users))
}
