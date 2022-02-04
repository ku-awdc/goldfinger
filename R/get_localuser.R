get_localuser <- function(){

  if(is.null(goldfinger_env$localuser)) gy_userfile()

  ## TODO: implement different groups
  local <- goldfinger_env$localuser
  local$group <- "goldfinger"
  local$keyringuser <- str_c(local$group, ":", local$user)

  return(local)
}


# This function only gets called to set up a new user for a group:
refresh_users <- function(weblink, setup=FALSE, silent=FALSE){

  stopifnot(is.character(weblink), length(weblink)==1, !is.na(weblink))
  if(!str_detect(weblink, "#")) stop("Invalid setup link provided (no #)", call.=FALSE)
  if(!str_detect(weblink, "^https://")) stop("Invalid setup link provided (not a URL)", call.=FALSE)

  weblink <- str_split(weblink, "#")[[1]]
  if(!length(weblink)==3) stop("Invalid setup link provided (cannot split twice on #)", call.=FALSE)

  if(!silent) cat("Downloading user list...\n")
  tmpfl <- tempdir(check=TRUE)
  download.file(weblink[1], file.path(tmpfl, "users.gyu"), quiet=TRUE, mode="wb")
  on.exit(unlink(file.path(tmpfl, "users.gyu")))

  info <- readRDS(file.path(tmpfl, "users.gyu"))

  check_version(info$minimum_version, info$package_version, info$date_time)

  public_ed <- info[["users"]][["public_ed"]]
  public_curve <- info[["users"]][["public_curve"]]

  if(setup){
    ## Save the administrators public ed key:
    if(!weblink[3] %in% names(public_ed)) stop("Invalid admin username", call.=FALSE)
    admin_ed <- public_ed[[weblink[3]]]
  }else{
    ## Otherwise use the pre-saved admin_ed
    admin_ed <- get_localuser()[["admin_ed"]][[goldfinger_env$group]]
  }

  ## Verify the downloaded user:
  gy_verify(info$users, info$verification, public_ed=admin_ed)

  ## Decrypt and extract user information:
  user_info <- unserialize(data_decrypt(info[["users"]][["user_info"]], hash(charToRaw(weblink[2]))))

  stopifnot(all(names(user_info) %in% names(public_curve)))
  stopifnot(all(names(public_curve) %in% names(user_info)))
  stopifnot(all(names(user_info) %in% names(public_ed)))
  stopifnot(all(names(public_ed) %in% names(user_info)))

  un <- names(user_info)
  names(un) <- un
  users <- lapply(un, function(x) c(user_info[[x]], list(public_curve=public_curve[[x]], public_ed=public_ed[[x]])))

  ## Cache within environment:
  goldfinger_env$webcache[[info$group]] <- users

  keys <- list(users=users, weburl=weblink[1], webpwd=weblink[2], admin_user=weblink[3], admin_ed=admin_ed, group=info$group)

  invisible(keys)
}

# Function called repeatedly in a session:
get_users <- function(all_users=FALSE, group=goldfinger_env$group, refresh=FALSE){

  if(is.null(goldfinger_env$localuser)) gy_userfile()

  if(group!=goldfinger_env$group) stop("Changing group is not yet implemented")

  if(!all_users){
    local <- list(get_localuser()[c("name","email","user","version","date_time","public_curve","public_ed")])
    names(local) <- local[[1]][["user"]]
    return(local)
  }

  if(refresh || is.null(goldfinger_env$webcache[[group]])){
    refresh_users(get_localuser()[["weblink"]], setup=FALSE, silent=FALSE)
  }
  lapply(goldfinger_env$webcache[[group]], function(x) stopifnot(all(names(x) == c("name","email","user","version","date_time","public_curve","public_ed"))))

  return(goldfinger_env$webcache[[group]])
}

check_version <- function(minimum_version, package_version, date_time){

  ## TODO: implement

}


get_public_key <- function(user, type="curve", weblink=NULL){

  ## TODO: implement
  # user can be group:admin

  get_localuser()$public_ed

}



get_password <- function(username){
  tryCatch(
    key_get("goldeneye", username=username),
    error=function(e){
      tryCatch(key_delete("goldeneye", username=username), error=function(e) { })
      pass <- getPass(msg="Password:  ")
      key_set_with_value("goldeneye", username, pass)
      return(pass)
    }
  )
}
