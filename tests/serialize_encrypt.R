library("goldfinger")

#fn <- gy_setup(NULL, "test", "test@test.com", "test", "", getwd(), append_Rprofile=FALSE)
fn <- gy_setup(NA_character_, "test", "test@test.com", "test", "", getwd(), append_Rprofile=FALSE)
unlink(fn)

## Test signing
x <- as.raw(1:10)
ss <- gy_sign(x)
gy_verify(x, ss)

## Test serialize and unserialize methods

x <- tibble(x1=rnorm(50), x2=x1*10)

obj1 <- gy_serialise(x, method="b")
stopifnot(identical(x, gy_deserialise(obj1)))

obj2 <- gy_serialise(x, method="q", preset="archive")
stopifnot(identical(x, gy_deserialise(obj2)))

stopifnot(object.size(obj2) < object.size(obj1))

enc1 <- gy_encrypt(obj1)
obj1a <- gy_decrypt(enc1)
stopifnot(identical(x, gy_deserialise(obj1a)))

enc2 <- gy_encrypt(obj2)
obj2a <- gy_decrypt(enc2)
stopifnot(identical(x, gy_deserialise(obj2a)))

switch <- rbinom(1,1,0.5)
encfun <- function(x){
  if(switch){
    cat("Reversed key...\n")
    rev(x)
  }else{
    cat("Normal key...\n")
    x
  }
}
enc3 <- gy_encrypt(obj2, funs = list(type="custom", encr_fun=encfun, decr_fun=encfun))
stopifnot(identical(x, gy_deserialise(gy_decrypt(enc3, run_custom = TRUE))))

gy_saveRDS(x, "test.rdg")
stopifnot(identical(x, gy_readRDS("test.rdg")))
unlink("test.rdg")


x2 <- x
gy_save(x2, file="test.rdg")
rm(x2)
gy_load("test.rdg")
stopifnot(identical(x, x2))
rm(x2)
unlink("test.rdg")


if(FALSE){

  gy_userfile('~/Downloads/gy_test_private.gyp')
  obj1a <- gy_decrypt(enc1)

  enc2 <- gy_encrypt(obj2, user="md")
  obj2a <- gy_decrypt(enc2)
  stopifnot(identical(x, gy_deserialise(obj2a)))

  gy_userfile('~/Documents/Personal/gy_md_private.gyp')
  obj2a <- gy_decrypt(enc2)
  stopifnot(identical(x, gy_deserialise(obj2a)))

  onkey <- sodium::hash(as.raw(runif(100)))
  #saveRDS(onkey, "~/Dropbox/goldeneye/kill_switch_test.rds")
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
  enc4 <- gy_encrypt(obj2, funs = list(type="custom", encr_fun=encfun, decr_fun=decfun))
  stopifnot(identical(x, gy_deserialise(gy_decrypt(enc4))))

}
