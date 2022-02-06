get_localuser <- function(){

  if(is.null(goldfinger_env$localuser)) gy_userfile()

  ## TODO: implement different groups
  local <- goldfinger_env$localuser
  local$group <- "goldfinger"

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
  check_version(info)

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

check_version <- function(versions, local_versions=get_versions()){

  stopifnot(is.character(versions))
  stopifnot(all(c("type","date_time","minimum","actual","sodium","qs","rcpp","R") %in% names(versions)))
  stopifnot(versions["type"] %in% c("generic","decrypt","verify","deserialise"))

  if(numeric_version(versions["minimum"]) > numeric_version(local_versions["actual"])){
    type <- versions["type"]
    if(type=="decrypt"){
      msg <- "Decrypting this file requires an update of "
    }else if(type=="verify"){
      msg <- "Verification of this file requires an update of "
    }else if(type=="deserialise"){
      msg <- "Deserialisation of this file requires an update of "
    }else{
      if(!type=="generic"){
        warning("Unrecognised type in version check")
      }
      # NB: this includes downloading the users profile
      msg <- "You need to update "
    }
    cat("ERROR:  ", msg, "the goldfinger package (you have version ", local_versions["actual"], " but version ", versions["minimum"], " or later is required). To update the package run the following code:\n\ninstall.packages('goldfinger', repos=c('https://cran.rstudio.com/', 'https://ku-awdc.github.io/drat/'))", sep="")

    stop("Package update required", call.=FALSE)
  }

  invisible(TRUE)

}

get_versions <- function(...){
  retval <- c(package_env$versions, date_time=as.character(Sys.time()), ...)
  if(!"minimum" %in% names(retval)) retval <- c(retval, minimum="0.4.0-0")
  if(!"type" %in% names(retval)) retval <- c(retval, type="generic")
  check_version(retval, local_versions=retval)
  return(retval)
}


get_public_key <- function(user, type="curve", weblink=NULL){

  ## TODO: implement
  # user can be group:admin

  get_localuser()$public_ed

}



get_gykey <- function(group, user, salt, key_encr){

  ## TODO: allow use of environmental passwords for testing purposes?

  ## TODO: limit the number of times this can fail using an env
  decrfun <- function(pass){
    pass_key <- hash(charToRaw(str_c(salt,pass)))
    data_decrypt(key_encr, pass_key)
  }

  username <- paste0(group, ":", user)
  tryCatch(
    decrfun(key_get("goldeneye", username=username)),
    error=function(e){
      tryCatch(key_delete("goldeneye", username=username), error=function(e) { })
      key_set_with_value("goldeneye", username, getPass(msg="Password:  "))
      decrfun(pass)
    }
  )
}
