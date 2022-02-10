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

  usrs <- t(vapply(users, function(x){
    c(unlist(x[c("user","name","email")]), user_since=str_replace(as.character(x$date_time), " .*", ""))
    }, character(4))) %>%
    as_tibble() %>%
    mutate(user_since=as.Date(user_since)) %>%
    arrange(user_since)

  return(usrs)
}
