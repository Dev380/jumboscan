# Jumboscan

Jumboscan is an implementation of a mass-scale scanner in Rust that speaks the Minecraft pre-1.7 and netty protocols. Currently, everything is in place to work - I just have decided not to finish the last pieces of glue, as I don't have an actual use case for this yet. See [the blog](https://dev380.github.io/blog/scanner-minecraft/).

## Usage

You must be on an operating system using Linux as the kernel for the correct socket(7) API behaviour. The program will not check for this and memory unsafe behaviour may occur if run on a different UNIX-like OS. Root permissions are required in order to spit out arbitrary packets and listen on an entire interface.
