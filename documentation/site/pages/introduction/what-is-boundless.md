---
title: What is Boundless?
description: Boundless is a set of Infrastructure and abstractions that provide the best place to develop your application, regardless of where you are.
---

# What Is Boundless?

Boundless is a set of Infrastructure and abstractions that provide the best place to develop your application, regardless of where you are. Boundless has two core pieces:

## Core Services

> Invisible yet powerful, providing best-in-class ZK infrastructure to handle proof generation, aggregation, and verification.

Core Services are the engine powering the most performant, reliable and cost-efficient proof delivery to your protocol on-chain. Boundless abstracts away the complexities of launching and maintaining a ZK application, providing a seamless experience while ensuring access to top-tier ZK infrastructure. These services include:

### Proving

Proof generation requires significant computational resources. Managing this yourself is impractical, and most alternatives force reliance on a single entity operating a coordination or incentive scheme. Boundless solves this with a network of provers equipped with optimal hardware (including accelerated hardware), competing to fulfill your requests. This ensures not only the best price for your proof but also removes reliance on a single entity, offering a decentralized and reliable proving system.

### Aggregation

Proofs must be verified on-chain, but submitting them individually can be prohibitively expensive. Boundless leverages proof aggregation, allowing multiple proofs to be combined, significantly reducing the cost of verification. For example, on Ethereum mainnet, aggregation reduces verification costs by up to 95%. These savings are automatically factored into your proof costs, as provers competitively bid to deliver your proofs efficiently.

### Settlement

Developing, deploying, and maintaining market and verifier contracts across multiple chains is a heavy burden for developers. Boundless eliminates this by pre-deploying and maintaining these contracts for you. With an ever-expanding list of supported chains, Boundless ensures your application is ready to settle proofs wherever you build.

## Extensions

> Purpose-built tools that seamlessly integrate ZK functionality into your stack, making it feel like a natural part of your development workflow.

Extensions provide additional abstractions to accelerate time-to-market (GTM) and expand functionality for developers. These tools are developed both by the Boundless team and third-party contributors. Extensions are grouped by common use cases, making them highly adaptable to the growing adoption of zkVMs.

With Boundless, developers gain access to industry-leading ZK infrastructure without the complexity of managing it themselves. In most cases, there's no need to interact with the underlying infrastructure at all—simply request a proof, and it's delivered efficiently and reliably.

### Rollups

Extensions that make deploying a rollup easier within Boundless such as a full rollup stack, integrations for existing rollup ecosystems and alt-DA support.

### EVM

Make building an application easier such as using Solidity in the zkVM and additional packages through 3rd parties.
