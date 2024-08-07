% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/gy_serialise.R, R/gy_sign.R
\name{gy_serialise}
\alias{gy_serialise}
\alias{gy_deserialise}
\alias{gy_serialize}
\alias{gy_deserialize}
\alias{gy_sign}
\title{Serialise and deserialise a list of objects/files}
\usage{
gy_serialise(object, files = character(0), method = "qs", ...)

gy_deserialise(object, files = TRUE, ...)

gy_serialize(object, files = character(0), method = "qs", ...)

gy_deserialize(object, files = TRUE, ...)

gy_sign(object, method = "hash")
}
\arguments{
\item{object}{}

\item{overwrite}{}
}
\description{
Serialise and deserialise a list of objects/files

Sign and verify a file
}
