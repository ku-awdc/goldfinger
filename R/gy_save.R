#' @name gy_save
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

#' @rdname gy_save
#' @export
gy_save <- function(..., list=character(), file=stop("file must be specified (.rdg file extension is recommended)"), user=character(0), local_user=TRUE, comment = "", overwrite=FALSE, ascii = FALSE, funs = list(type="identity"), method="base"){

  names <- as.character(substitute(list(...)))[-1L]
  if(length(names)==0) stop("No objects passed to be saved", call.=FALSE)
  list <- c(list, names)
  objects <- mget(list, inherits=TRUE)
  names(objects) <- list

  file <- eval(file)
  attr(file, "gy_type") <- "gy_save"
  gy_saveRDS(objects, file=file, user=user, local_user=local_user, comment=comment, overwrite=overwrite, ascii=ascii, funs=funs, method=method)

}


#' @rdname gy_save
#' @export
gy_load <- function(file=stop("file must be specified (.rdg file extension is recommended)")){

  fcon <- readRDS(file)
  if(fcon$metadata$gy_type != "gy_save") warning("Archive was created using ", fcon$metadata$gy_type, " not gy_save")

  objects <- gy_readRDS(file)
  stopifnot(inherits(objects, "list"))

  for(i in seq_len(length(objects))){
    assign(names(objects)[i], objects[[i]], envir=parent.frame())
  }

  invisible(names(objects))

}
