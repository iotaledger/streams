# API Reference

Users are broken down into two types: `Author` and `Subscriber`. An `Author` is the user 
that generates the channel, accepts subscription requests and can perform access granting 
and restriction methods. A `Subscriber` is an instance that can attach to a channel to read 
from and write to depending on the access privileges they've been granted. 

You can generate the api reference with:
```
cargo doc --document
```





