import formatters from "@poppinss/intl-formatter";
import { Skeleton } from "@risc0/ui/skeleton";
import { useEffect, useState } from "react";
import { useBlockNumber, usePublicClient } from "wagmi";

type PricingInputs = {
  programCycles: number;
  desiredTimeMinutes: number;
  currentBlockNumber: number | undefined;
};

const SEPOLIA_CHAIN_ID = 11155111;

const calculateSuggestion = (cycles: number, minutes: number, startBlock: number, blocksPerMinute: number) => {
  const basePrice = (cycles / 1000000) * 0.5;

  return {
    minPrice: basePrice,
    maxPrice: basePrice * 2,
    biddingStart: startBlock + blocksPerMinute, // Start bidding after 1 minute
    rampUpBlocks: Math.ceil(minutes * 0.5 * blocksPerMinute),
    timeoutBlocks: Math.ceil(minutes * blocksPerMinute),
    lockInStake: basePrice * 4,
  };
};

export default function PricingCalculator() {
  const { data: blockNumber } = useBlockNumber({ chainId: SEPOLIA_CHAIN_ID });
  const publicClient = usePublicClient({ chainId: SEPOLIA_CHAIN_ID });
  const [blocksPerMinute, setBlocksPerMinute] = useState<number | undefined>(undefined);
  const [inputs, setInputs] = useState<PricingInputs>({
    programCycles: 1000000,
    desiredTimeMinutes: 10,
    currentBlockNumber: undefined,
  });

  useEffect(() => {
    if (blockNumber && !inputs.currentBlockNumber) {
      setInputs((prev) => ({ ...prev, currentBlockNumber: Number(blockNumber) }));
    }
  }, [blockNumber, inputs]);

  useEffect(() => {
    async function calculateBlocksPerMinute() {
      if (!blockNumber || !publicClient) {
        return;
      }

      try {
        // Get current block timestamp
        const currentBlock = await publicClient.getBlock();

        // Get block from ~5 minutes ago
        const pastBlock = await publicClient.getBlock({
          blockNumber: blockNumber - 25n, // ~5 minutes worth of blocks
        });

        if (currentBlock.timestamp && pastBlock.timestamp) {
          const timeDiffMinutes = (Number(currentBlock.timestamp) - Number(pastBlock.timestamp)) / 60;
          const blockDiff = Number(currentBlock.number - pastBlock.number);
          const actualBlocksPerMinute = blockDiff / timeDiffMinutes;

          setBlocksPerMinute(Math.round(actualBlocksPerMinute));
        }
      } catch (error) {
        console.error("Failed to calculate blocks per minute:", error);
      }
    }

    calculateBlocksPerMinute();
  }, [blockNumber, publicClient]);

  const suggestion =
    blocksPerMinute && inputs.currentBlockNumber
      ? calculateSuggestion(inputs.programCycles, inputs.desiredTimeMinutes, inputs.currentBlockNumber, blocksPerMinute)
      : null;

  return (
    <div className="my-8 rounded-lg border border-[var(--vocs-color\_border);] p-6">
      {suggestion ? (
        <>
          <h3 className="mb-4 font-semibold text-lg">Request Parameters Calculator</h3>

          <div className="space-y-4">
            <div>
              <label htmlFor="programCycles" className="mb-1 block text-sm">
                Program Cycles
              </label>
              <input
                id="programCycles"
                type="number"
                min="1"
                value={inputs.programCycles}
                onChange={(e) =>
                  setInputs((prev) => ({
                    ...prev,
                    programCycles: Math.max(1, Number(e.target.value)),
                  }))
                }
                className="w-full rounded border border-[var(--vocs-color\_border);] px-3 py-2"
              />
            </div>

            <div>
              <label htmlFor="proofTime" className="mb-1 block text-sm">
                Desired Proof Time (in minutes)
              </label>
              <input
                id="proofTime"
                type="number"
                min="1"
                value={inputs.desiredTimeMinutes}
                onChange={(e) =>
                  setInputs((prev) => ({
                    ...prev,
                    desiredTimeMinutes: Math.max(1, Number(e.target.value)),
                  }))
                }
                className="w-full rounded border border-[var(--vocs-color\_border);] px-3 py-2"
              />
            </div>

            <div>
              <label htmlFor="currentBlockNumber" className="mb-1 block text-sm">
                Current Block Number
              </label>
              <input
                id="currentBlockNumber"
                type="number"
                min="1"
                value={inputs.currentBlockNumber}
                onChange={(e) =>
                  setInputs((prev) => ({
                    ...prev,
                    currentBlockNumber: Math.max(1, Number(e.target.value)),
                  }))
                }
                className="w-full rounded border border-[var(--vocs-color\_border);] px-3 py-2"
              />
            </div>

            <div className="pt-4">
              <h4 className="mb-2 font-medium">Suggested Parameters</h4>
              <div className="rounded border border-[var(--vocs-color\_border);] bg-muted p-4">
                <dl className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <dt>Minimum Price:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.minPrice)} ETH</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Maximum Price:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.maxPrice)} ETH</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Bidding Start Block:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.biddingStart)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Ramp-up Period:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.rampUpBlocks)} blocks</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Timeout:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.timeoutBlocks)} blocks</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt>Lock-in Stake:</dt>
                    <dd>{formatters.number("en-US").format(suggestion.lockInStake)} ETH</dd>
                  </div>
                </dl>
              </div>
            </div>
          </div>
        </>
      ) : (
        <Skeleton className="h-[514px] w-full" />
      )}
    </div>
  );
}
