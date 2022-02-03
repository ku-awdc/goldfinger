## Test serialize and unserialize methods

x <- tibble(x1=rnorm(50), x2=x1*10)

obj1 <- gy_serialise(x, "b")
stopifnot(identical(x, gy_deserialise(obj1)))

obj2 <- gy_serialise(x, "q", preset="archive")
stopifnot(identical(x, gy_deserialise(obj2)))

stopifnot(object.size(obj2) < object.size(obj1))

enc1 <- gy_encrypt(obj1)
obj1a <- gy_decrypt(enc1)
stopifnot(identical(x, gy_deserialise(obj1a)))

enc2 <- gy_encrypt(obj2)
obj2a <- gy_decrypt(enc2)
stopifnot(identical(x, gy_deserialise(obj1a)))

encfun <- function(x){
  switch <- rbinom(1,1,0.5)
  if(switch) x <- rev(x)
  function(){
    if(switch){
      cat("Reversed key...\n")
      rev(x)
    }else{
      cat("Normal key...\n")
      x
    }
  }
}
enc3 <- gy_encrypt(obj2, encr_fun = encfun)
stopifnot(identical(x, gy_deserialise(gy_decrypt(enc3, run_function = TRUE))))

gy_saveRDS(x, "test.rdg")
stopifnot(identical(x, gy_readRDS("test.rdg")))
unlink("test.rdg")
