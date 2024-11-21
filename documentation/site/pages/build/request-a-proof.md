Request a proof (??)

Key thing to mention here: proof here means an attestation from the set verifier that the proof they requested has been verified and included. Perhaps we could call this construct a “Boundless Proof” directly to delineate between standard ZKP ready for verification, and the above representation of a proof already verified and stored in a merkle tree.

To request a proof, you can either send an onchain transaction to the market contract. The parameters of the request are filled out by the requestor in request.yaml.
Next, explain offchain flow
Key point: the proof that you receive is already verified. It is an attestation to a proof that was verified, the proof verifications are merklised and stored onchain. This verified proof is what you use onchain.
Request.yaml explainer
Tradeoffs in dimensionality. A nice dynamic proof estimator tool would be great here.
Megacycle, cost, time, cycle cost
Current market price: ETH per mcycle cost.
How to track your proof request’s progress
How to get funds back for proofs that were not fulfilled

Broadcasting Proof Requests from current documentation will fill out a lot of this page.
