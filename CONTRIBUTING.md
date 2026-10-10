# Contributing

Thanks for taking a look at SecretScope. This is a personal learning project,
but suggestions and fixes are welcome.

## Getting set up

You need a recent Rust toolchain (the project builds on Rust 1.75 and newer) and
Go 1.22 or newer for the Kubernetes webhook. The optional cluster demo needs
Docker and kind.

## Before opening a pull request

Please make sure the following pass locally:

    make fmt-check
    make lint
    make test

For the webhook:

    make webhook-test

## Style

The code favors small, readable functions over clever ones, and comments
explain why a piece of code exists rather than restating what it does. New
behavior should come with a test. Please do not add real credentials to the
repository, even in tests. Use synthetic placeholder values like the ones
already in the fixtures.
