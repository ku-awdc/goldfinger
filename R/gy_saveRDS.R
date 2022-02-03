#' @name gf_saveRDS
#' @title Save and read encrypted RDS
#' @param object
#' @param file
#' @param user
#' @param local_user
#' @param ascii
#' @param version
#' @param compress
#' @param overwrite
#'
#' @rdname gy_saveRDS
#' @export
gy_saveRDS <- function(object, file=stop("file must be specified (.rdg file extension is recommended)"), user=character(0), local_user=TRUE, comment = "", overwrite=FALSE, ascii = FALSE, encr_fun = NULL, ...){

  if(file.exists(file) && !overwrite) stop("Specified file exists: use overwrite=TRUE if necessary", call.=FALSE)

  if("gf_type" %in% names(attributes(file))){
    gf_type <- attr(file, "gf_type", TRUE)
  }else{
    gf_type <- "gf_saveRDS"
  }

  ## Serialise and encrypt:
  ser_obj <- gy_serialise(object, ...)
  enc_obj <- gy_encrypt(ser_obj, user=user, local_user=local_user, comment = comment, encr_fun = encr_fun)

  ## And save:
  saveRDS(enc_obj, file=file, ascii=ascii, compress=FALSE)

}


#' @rdname gy_saveRDS
#' @export
gy_readRDS <- function(file=stop("file must be specified (.rdg file extension is recommended)"), run_function=FALSE){

  ## Read file:
  enc_obj <- readRDS(file)

  ## Unencrypt and deserialise:
  ser_obj <- gy_decrypt(enc_obj, run_function=run_function)
  object <- gy_deserialise(ser_obj)

  return(object)

}
