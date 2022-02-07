## Example for SSN

# Load the library and set the user file:
library("goldfinger")
gy_userfile()
# Or:
# gy_userfile(path="..../goldfinger_saxmose.gyp")

## A secret dataset:
cars <- data("cars")
# Cleanup
unlink("cars.rdg")


## Basic usage:

# Encrypt for only the local user:
gy_save(cars, file="cars.rdg")

# Re-load:
(gy_load("cars.rdg"))

# Encrypt for md and saxmose:
gy_save(cars, file="cars.rdg", user=c("md","saxmose"), overwrite=TRUE)

# Encrypt for md and mossa only (will fail for saxmose even if thats the local user):
gy_save(cars, file="cars.rdg", user=c("md","mossa"), local_user=FALSE, overwrite=TRUE)
# Should fail:
(gy_load("cars.rdg"))



## Additional security:

# Define a decrypt function that writes to log file on decrypt:
encfun <- function(x) x
decfun <- function(x){
  user <- goldfinger:::get_localuser()$user
  cat("User", user, "decrypted the file at", as.character(Sys.time()), "\n", file="logfile.txt", append=TRUE)
  x
}
gy_save(cars, file="cars.rdg", funs = list(type="custom", encr_fun=encfun, decr_fun=decfun), overwrite=TRUE)
# Every time this is run a line gets appended to the log:
(gy_load("cars.rdg"))
readLines("logfile.txt")


# Decrypt the file that I sent you - this uses a secondary encryption layer for the decryption key that is loaded from a website I set up:
rm(cars)
(gy_load("cars_killswitch.rdg"))

# And here is how it works:
encfun <- function(x){
  tmpfl <- tempdir(check=TRUE)
  cat("Attempting to download killswitch...\n")
  ss <- try({
    conn <- url("https://www.dropbox.com/s/tpk6es9pm5xuu5b/kill_switch_test.rds?raw=1")
    onkey <- readRDS(conn)
    close(conn)
  })
  if(inherits(ss, "try-error")) stop("Killswitch not available to download")
  sodium::data_encrypt(x, onkey)
}
decfun <- function(x){
  tmpfl <- tempdir(check=TRUE)
  cat("Attempting to download killswitch...\n")
  ss <- try({
    conn <- url("https://www.dropbox.com/s/tpk6es9pm5xuu5b/kill_switch_test.rds?raw=1")
    onkey <- readRDS(conn)
    close(conn)
  })
  if(inherits(ss, "try-error")) stop("Killswitch not available to download")
  sodium::data_decrypt(x, onkey)
}
gy_save(cars, file="cars.rdg", user=c("md","saxmose"), funs = list(type="custom", encr_fun=encfun, decr_fun=decfun), overwrite=TRUE)


# Cleanup
unlink("cars.rdg")
