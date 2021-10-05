# Contribute to Streams

This document describes how to contribute to Streams.

We encourage everyone with knowledge of IOTA technology to contribute.

Thanks! :heart:

<details>
<summary>Do you have a question :question:</summary>
<br>

If you have a general or technical question, you can use one of the following resources instead of submitting an issue:

- [**Developer documentation:**](https://wiki.iota.org/) For official information about developing with IOTA technology
- [**Discord:**](https://discord.iota.org/) For real-time chats with the developers and community members
- [**IOTA cafe:**](https://iota.cafe/) For technical discussions with the Research and Development Department at the IOTA Foundation
- [**StackExchange:**](https://iota.stackexchange.com/) For technical and troubleshooting questions
</details>

<br>

<details>
<summary>Ways to contribute :mag:</summary>
<br>

To contribute to Streams on GitHub, you can:

- Report a bug
- Suggest a new feature
- Build a new feature
- Contribute to the documentation
- Join the Streams Initiative
</details>

<br>

<details>
<summary>Report a bug :bug:</summary>
<br>

This section guides you through reporting a bug. Following these guidelines helps maintainers and the community understand the bug, reproduce the behavior, and find related bugs.

### Before reporting a bug

Please check the following list:

- **Do not open a GitHub issue for [security vulnerabilities](.github/SECURITY.MD)**, instead, please contact us at [security@iota.org](mailto:security@iota.org).

- **Ensure the bug was not already reported** by searching on GitHub under [**Issues**](https://github.com/iotaledger/streams/issues). If the bug has already been reported **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

**Note:** If you find a **Closed** issue that seems similar to what you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

### Submitting A Bug Report

To report a bug, [open a new issue](https://github.com/iotaledger/streams/issues/new), and be sure to include as many details as possible, using the template.

**Note:** Minor changes such as fixing a typo can but do not need an open issue.

If you also want to fix the bug, submit a [pull request](#pull-requests) and reference the issue.

</details>

<br>

<details>
<summary>Suggest a new feature :bulb:</summary>
<br>

This section guides you through suggesting a new feature. Following these guidelines helps maintainers and the community collaborate to find the best possible way forward with your suggestion.

### Before suggesting a new feature

**Ensure the feature has not already been suggested** by searching on GitHub under [**Issues**](https://github.com/iotaledger/streams/issues).

### Suggesting a new feature

To suggest a new feature, talk to the IOTA community and IOTA Foundation members in the #streams-discussion channel on [Discord](https://discord.iota.org/).

If the team approves your feature, an issue will be created for it.

</details>

<br>

<details>
<summary>Build a new feature :hammer:</summary>
<br>

This section guides you through building a new feature. Following these guidelines helps give your feature the best chance of being approved and merged.

### Before building a new feature

Make sure to discuss the feature in the #streams-discussion channel on [Discord](https://discord.iota.org/).

### Building a new feature

To build a new feature, check out a new branch based on the `master` branch.

If your feature has a public-facing API, please consider the following:

- Make sure to document the feature, using the guidelines in this [Rust RFC](https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text)
- Makes sure to include [documentation tests](https://doc.rust-lang.org/rustdoc/documentation-tests.html)
</details>

<br>

<details>
<summary>Contribute to the documentation :black_nib:</summary>
<br>

The IOTA Streams documentation is hosted on [https://wiki.iota.org/](https://wiki.iota.org/streams/welcome), and built from this repositories' documentation folder using Docusarus.  

For information on how to contribute to the documentation please see the [contribution guidelines](https://wiki.iota.org/docs/participate/contribute-to-wiki/welcome).

</details>

<br>

<details>
<summary>Join the Streams Initiative :deciduous_tree:</summary>
<br>

The [IOTA Streams Initiative](https://github.com/iota-community/IOTAStreams) is a collaborative effort to improve the Streams developer experience by focussing on the following goals:

- Quality assurance and review
- Documentation
- Code samples
- Improvements to modules and libraries

## How much time is involved

You can invest as much or as little time as you want into the initiative.

## What's in it for you

In return for your time, not only do you get to be a part of the future of IOTA technology, you will also be given a badge on Discord to show others that you're a valuable member of the IOTA community.

## How to join

If you're interested in joining, chat to us in the #experience channel on [Discord](https://discord.iota.org/).

</details>

<br>

<details>
<summary>Pull requests :mega:</summary>
<br>

This section guides you through submitting a pull request (PR). Following these guidelines helps give your PR the best chance of being approved and merged.

### Before submitting a pull request

When creating a pull request (PR), please follow these steps to have your contribution considered by the maintainers:

- A PR should have exactly one concern (for example one feature or one bug). If a PR addresses more than one concern, it should be split into more PRs.

- A PR can be merged only if it references an open issue

  **Note:** Minor changes such as fixing a typo can but do not need an open issue.

### Submitting a pull request

The following is a typical workflow for submitting a new pull request:

1. Fork this repository
2. Create a new branch based on your fork. For example, `git checkout -b fix/my-fix` or ` git checkout -b feat/my-feature`.
3. Make your changes
4. Run the `cargo fmt` command to make sure your code is well formatted
5. Commit your changes, using a clear commit message, and push them to your fork
6. Target your pull request to be merged with the `master` branch

If all [status checks](https://help.github.com/articles/about-status-checks/) pass, and the maintainer approves the PR, it will be merged.

**Note:** Reviewers may ask you to complete additional work, tests, or other changes before your pull request can be approved and merged.

</details>

<br>

<details>
<summary>Code of Conduct :clipboard:</summary>
<br>

This project and everyone participating in it is governed by the [IOTA Code of Conduct](.github/CODE_OF_CONDUCT.md).
