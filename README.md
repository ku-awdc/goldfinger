# goldfinger

R package to facilitate safe sharing of data using encryption

To install this package from our drat repository, try the following:

```r
options(
  repos = structure(c(CRAN="https://cran.rstudio.com/",
          "ku-awdc"="https://ku-awdc.github.io/drat/"))
)
install.packages("goldfinger")
```

To set up a user:

```r
library("goldfinger")
gf_setup()
```

and follow the instructions.

More help will be added soon...