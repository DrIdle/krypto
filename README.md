# krypto
Krypto: Cryto library for Kotlin

This project holds implementation of various cryptographic primitives written purely in Kotlin.

## Disclaimer

These implementations should not be used in a real environment. I only created them so I can better understand how they work and of course to practice some Kotlin.

The classes in this project utilize arrays of unsinged types (such as `UByteArray` or `UIntArray`), which at the time of writing are only at experimental level in Kotlin. To make this fact more prominent, the affected classes have the appropriate annotation.

On the other hand, some of the implementations use new features in the language (for example `rotateLeft`), which can only be found in Kotlin version 1.6 or higher. Therefore, you have to have a version which supports these methods to use these implementations.

## The structure of the project

The source files live under the `src` folder. You can find a `main` and a `test` folder there. The former contains the implementations structured in a packages, while the latter holds the tests for these implementations. In the `utils` package you can find the extensions function which make the classes more readable.

## Documentation

All class, function, interfaces etc. are documented using KDoc. The Dokka plugin is included in build.gradle and it can be used to generate a more accessible  documentation in a number of different formats. All formats correspond to a specific Gradle task.

To generate the documentation in HTML for example use:
```
./gradlew dokkaHtml
```

## Usage

To get an idea of how to use the different classes and functions in this project have a look at tests.
