#' @name gy_serialise
#' @title Serialise and deserialise a list of objects/files
#' @param object
#' @param file
#' @param user
#' @param local_user
#' @param ascii
#' @param version
#' @param compress
#' @param overwrite
#'
#' @importFrom qs qserialize qdeserialize
#'
#' @rdname gy_serialise
#' @export
gy_serialise <- function(object, method="base", ...){

  if(!is.character(method) || length(method)!=1 || is.na(method)) stop("The serialisation method argument must be a length 1 character", call.=FALSE)

  mtch <- pmatch(method, serialization_options)
  if(is.na(mtch)) stop(str_c("Unrecognised serialisation method argument '", method, "' - options are: ", str_c(serialization_options, collapse=", ")))
  method <- serialization_options[mtch]

  if(method == "base"){
    # base::serialize, which does not allow compression:
    rv <- serialize(object=object, connection=NULL, ...)
  }else if(method == "qs"){
    # qs::qserialize, with or without compression (default with):
    rv <- qserialize(x=object, ...)
  }else if(method == "custom"){
    stop("The custom serialisation method is invalid for this function", call.=FALSE)
  }else{
    stop("Serialisation method '", method, "' is not yet implemented - perhaps update the package?", call.=FALSE)
  }

  ## Add the serialization method as an attribute:
  attr(rv, "ser_method") <- method

  return(rv)
}


#' @rdname gy_serialise
#' @export
gy_deserialise <- function(object, ...){

  if(!is.raw(object)) stop("The provided object must be of type raw", call.=FALSE)

  method <- attr(object, "ser_method", exact=TRUE)
  if(is.null(method)){
    warning("The provided object did not have a serialization method attribute - assuming that this is base::serialize")
    method <- "base"
  }

  if(!is.character(method) || length(method)!=1 || is.na(method)) stop("The serialisation method attribute must be a length 1 character", call.=FALSE)
  if(method=="serialise") method <- "serialize"

  mtch <- pmatch(method, serialization_options)
  if(is.na(mtch)) stop(str_c("Unrecognised serialisation method attribute '", method, "' - options are: ", str_c(serialization_options, collapse=", ")))
  method <- serialization_options[mtch]

  if(method == "base"){
    # base::unserialize
    rv <- unserialize(connection=object, ...)
  }else if(method == "qs"){
    # qs::qdeserialize
    rv <- qdeserialize(x=object, ...)
  }else if(method == "custom"){
    stop("Unable to automatically deserialise custom-serialised objects", call.=FALSE)
  }else{
    stop("Deserialisation method '", method, "' is not yet implemented - perhaps update the package?", call.=FALSE)
  }

  return(rv)

}

# Common to both functions:
serialization_options <- c("custom", "base", "qs")

#' @rdname gy_serialise
#' @export
gy_serialize <- gy_serialise

#' @rdname gy_serialise
#' @export
gy_deserialize <- gy_deserialise
