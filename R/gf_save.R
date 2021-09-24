#' @name gf_save
#' @title Save and load encrypted files
#'
#' @param ...
#' @param list
#' @param file
#' @param user
#' @param local_user
#' @param ascii
#' @param version
#' @param compress
#' @param overwrite

#' @rdname gf_save
#' @export
gf_save <- function(..., list=character(), file=stop("file must be specified (.rdg file extension is recommended)"), user=character(0), local_user=TRUE, ascii = FALSE, version = NULL, compress="xz", overwrite=FALSE){

  names <- as.character(substitute(list(...)))[-1L]
  if(length(names)==0) stop("No objects passed to be saved", call.=FALSE)
  list <- c(list, names)
  objects <- mget(list, inherits=TRUE)
  names(objects) <- list

  file <- eval(file)
  attr(file, "gf_type") <- "gf_save"
  gf_saveRDS(objects, file=file, user=user, local_user=local_user, ascii=ascii, version=version, compress=compress, overwrite=overwrite)

}


#' @rdname gf_save
#' @export
gf_load <- function(file=stop("file must be specified (.rdg file extension is recommended)")){

  fcon <- readRDS(file)
  if(fcon$metadata$gf_type != "gf_save") warning("Archive was created using ", fcon$metadata$gf_type, " not gf_save")

  objects <- gf_readRDS(file)
  stopifnot(inherits(objects, "list"))

  for(i in seq_len(length(objects))){
    assign(names(objects)[i], objects[[i]], envir=parent.frame())
  }

  invisible(names(objects))

}
