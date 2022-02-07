.onLoad <- function(libname, pkgname){

  package_env$versions <- c(
    actual = utils::packageDescription(pkgname, fields='Version'),
    sodium = utils::packageDescription("sodium", fields='Version'),
    qs = utils::packageDescription("qs", fields='Version'),
    rcpp = utils::packageDescription("Rcpp", fields='Version'),
    R = base::as.character(base::getRversion())
  )

}

.onAttach <- function(libname, pkgname){

	# This will be run after load if the package is attached:
	packageStartupMessage(paste('Attaching goldfinger version ', package_env$versions["actual"], sep=''))

}

package_env <- new.env()
package_env$versions <- NULL
package_env$currentlocal <- NULL
package_env$currentgroup <- NA_character_

