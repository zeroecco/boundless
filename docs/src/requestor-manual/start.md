# Requestor Quick Start

This guide highlights tips, tools, and techniques for building RISC Zero guest programs that integrate with the [Boundless market][page-market] to generate proofs for them.

## Before you begin

<div class="warning">

Those completely new to development of verifiable computation using a zkVM should first get a firm grasp of the [core concepts][r0-docs], [terms][r0-terms], and experiment with [examples][r0-examples].

</div>

1. Follow the [local development][page-local-dev] to install deps and configure a Boundless devnet.
2. To interact with live [market deployment][page-deployments], you must obtain funds for gas fees and proof fulfillment payments.

## Starting a New Project

<div class="warning">

For existing RISC Zero apps, see the [integrating existing projects](#integrating-existing-projects) section.

</div>

### Examples

The Boundless' monorepo includes [examples][boundless-examples] that can be used as _reference_ on the patterns required in the `host` to integrate and interact with Boundless.

## Foundry Template

The [Boundless foundry template][boundless-foundry-template] is the best place to start _building_ a new Boundless application.

## Integrating Existing Projects

Applications presently using Bonsai map almost directly to the Boundless workflows and patterns.
Key differences include:

| Details                  | Boundless                               | Bonsai                               |
| ------------------------ | --------------------------------------- | ------------------------------------ |
| Required for fulfillment | Payment to market prover                | API key                              |
| Submission endpoint      | A [Market deployment][page-deployments] | [api.bonsai.xyz](https://bonsai.xyz) |
| TODO                     | More here?                              | ?                                    |

Use the [Boundless foundry template][boundless-foundry-template]

TODO: compare base [foundry template][r0-foundry-template] noting that we intend to bring best practices discovered from Boundless into a new base template (likely using one of the existing repos and archiving the other)

[r0-docs]: https://dev.risczero.com/api
[r0-terms]: https://dev.risczero.com/terminology

<!-- TODO versioning of all links https://linear.app/risczero/issue/DR-369/version-all-links-correctly-in-the-boundless-book -->

[r0-examples]: https://github.com/risc0/risc0/tree/release-1.1/examples
[boundless-examples]: https://github.com/boundless-xyz/boundless/tree/main/examples/
[boundless-repo]: https://github.com/boundless-xyz/boundless/
[boundless-foundry-template]: https://github.com/boundless-xyz/boundless-foundry-template/
[r0-foundry-template]: https://github.com/risc0/risc0-foundry-template/
[page-deployments]: ../market/deployments.md
[page-local-dev]: ../market/local-development.md
[page-market]: ../market/README.md
