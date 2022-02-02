## Test serialize and unserialize methods

x <- tibble(x1=rnorm(50), x2=x1*10)

obj1 <- gy_serialise(x, "s")
stopifnot(identical(x, gy_deserialise(obj1)))

obj2 <- gy_serialise(x, "q", preset="archive")
stopifnot(identical(x, gy_deserialise(obj2)))

object.size(obj1)
object.size(obj2)

stopifnot(object.size(obj2) < object.size(obj1))
