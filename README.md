# Torus-Utils-Java

[![](https://jitpack.io/v/org.torusresearch/torus-utils-java.svg)](https://jitpack.io/#org.torusresearch/torus-utils-java)

## Introduction

Use this package to do threshold resolution of API calls to Torus nodes. 
Since Torus nodes operate on a threshold assumption, we need to ensure that API calls also follow such an assumption.
This is to prevent malicious nodes from withholding shares, or deliberately slowing down the entire process.

This utility library allows for early exits in optimistic scenarios, while handling rejection of invalid inputs from nodes in malicious/offline scenarios.
The general approach is to evaluate predicates against a list of (potentially incomplete) results, and exit when the predicate passes.

README.md
## Features
- Handles up to threshold number of failures.
- Optimistic early exit (eg. 5/9 nodes return valid shares = complete)
- All API's return `CompletableFutures`

## Getting Started

Typically your application should depend on release versions of torus-utils-java, but you may also use snapshot dependencies for early access to features and fixes, refer to the Snapshot Dependencies section.
This project uses [jitpack](https://jitpack.io/docs/) for release management

Add the relevant dependency to your project:

```groovy
repositories {
        maven { url "https://jitpack.io" }
   }
   dependencies {
         implementation 'org.torusresearch:torus-utils-java:2.0.1'
   }
```

## Requirements

- Android - API level 24
- Java 8 / 1.8