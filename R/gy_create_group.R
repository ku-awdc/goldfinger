gy_create_group <- function(group, weblink, password){

  group <- tolower(group)
  if(group=="default") stop("The group name 'default' is reserved", call.=FALSE)
  ## Get local user info (will be admin):
  user <- gy_localuser()




}


gy_add_group <- function(weblink, new_users){


}
