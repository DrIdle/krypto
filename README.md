# krypto
Krypto: Cryto library for Kotlin

This project holds implementation of various cryptographic primitives written purely in Kotlin.

**NOTE** that these implementatios should not be used in a real environment. I only created them so I can better understand how they work and of course to practice some Kotlin.

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
