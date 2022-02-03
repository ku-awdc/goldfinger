#' Title
#'
#' @param object
#'
#' @return
#' @export
#'
#' @examples
gy_sign <- function(object){

  ## Get private and public keys for this user:
  local <- gf_localuser()
  pass <- key_get("goldeneye", username=str_c(local$group, ":", local$user))
  pass_key <- key_sodium(sha256(charToRaw(str_c(local$salt,pass))))
  private_key <- decrypt_object(local$private_encr, pass_key)
  public_key <- local$public_key

  ## Validate with the public key:
  public_test <- pubkey(private_key)
  if(!identical(public_key, public_test)) stop("Something went wrong: the public key cannot be regenerated", call.=FALSE)

  ## Sign the object:
  encr <- simple_encrypt(sha256(serialize(object, NULL)), private_key)
  decr <- simple_decrypt(encr, public_key)

  encr <- simple_encrypt(sha256(serialize(object, NULL)), public_key)
  decr <- simple_decrypt(encr, private_key)

}
