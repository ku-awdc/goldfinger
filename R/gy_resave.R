#' Upgrade older goldfinger saved data files to remove dependencies on the qs package
#'
#' @details
#' For more details see vignette("goldfinger-qs")
#'
#' @param input_file the name of the saved file to resave
#' @param output_file the name of the file to save to (default is to replace the existing file)
#'
#' @export
gy_resave <- function(input_file=stop("input_file must be specified (.rdg file extension is recommended)"), output_file=input_file){

  package_env$qs_warning <- FALSE

  # Read saved file:
  enc_obj <- readRDS(input_file)
  if(!"object_encr" %in% names(enc_obj) || !"ser_method" %in% names(attributes(enc_obj$object_encr))){
    stop("File does not seem to be a goldfinger encrypted data file: if you think this is a mistake, please report it to Matt", call.=FALSE)
  }
  # If not qs then return early:
  if(attr(enc_obj$object_encr, "ser_method")!="qs"){
    message("Provided file was not serialised using qs:  no action needed!")

  }else{

    # Decrypt:
    ser_obj <- gy_decrypt(enc_obj, run_custom=TRUE)
    # Deserialise:
    object <- gy_deserialise(ser_obj)
    # Reserialise:
    reser_obj <- gy_serialise(object)
    # Extract symmetric encryption key:
    symkey <- gy_decrypt(enc_obj, run_custom=list(run_custom=TRUE))
    # Re-encrypt using this key:
    reenc_obj <- sodium::data_encrypt(reser_obj, symkey)
    # Copy attributes:
    attr(reenc_obj, "ser_method") <- attr(reser_obj, "ser_method")
    attr(reenc_obj, "versions") <- attr(reser_obj, "versions")
    # Replace encrypted object:
    enc_obj$object_encr <- reenc_obj

    # Test decrypt and deserialise:
    obj2 <- gy_deserialise(gy_decrypt(enc_obj))
    if(!identical(object, obj2)) stop("Resaving failed: the updated object is not identical to the previous version")

    # Re-save to file:
    saveRDS(enc_obj, file=output_file, ascii=FALSE, compress=FALSE)

  }

  package_env$qs_warning <- TRUE
}
