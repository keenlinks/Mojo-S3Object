# Mojo::S3Object

Very early development code (although I use currently for my projects). A lot to be done (DRY, abstraction, tests). I wanted a basic S3 helper for objects, especially a policy producer for browser-based uploads. Originally a plugin, changed from a plugin to a non-plugin module so it can be used easier outside of a non-Mojolicious app (command line back-up script). It can be used blocking or non-blocking, but I need a better understanding of the non-blocking code to make sure it is correclty done.
