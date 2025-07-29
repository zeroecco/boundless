import NumberFlow from "@number-flow/react";
import { useState } from "react";

type Network = "base-mainnet" | "base-sepolia";

type PricingInputs = {
  programCycles: number;
  desiredTimeMinutes: number;
};

type NetworkConfig = {
  name: string;
  blocksPerMinute: number;
  currencySymbol: string;
  basePriceMultiplier: number;
};

const NETWORK_CONFIGS: Record<Network, NetworkConfig> = {
  "base-mainnet": {
    name: "Base Mainnet",
    blocksPerMinute: 30, // ~2 second block time
    currencySymbol: "ETH",
    basePriceMultiplier: 1,
  },
  "base-sepolia": {
    name: "Base Sepolia Testnet",
    blocksPerMinute: 30,
    currencySymbol: "Base SepETH",
    basePriceMultiplier: 0.001, // Much cheaper for testnet
  },
};

function calculateSuggestion(cycles: number, minutes: number, networkConfig: NetworkConfig) {
  const basePrice = (cycles / 1_000_000) * 0.0001 * networkConfig.basePriceMultiplier;
  const biddingStartDelay = Math.ceil(cycles / (30 * 1_000_000)); // cycles / 30MHz in blocks

  const lockInStakeUSDC = basePrice * 4 * 3000;

  return {
    minPrice: basePrice,
    maxPrice: basePrice * 2,
    biddingStartDelay,
    rampUpBlocks: Math.min(100, Math.ceil(minutes * 0.5 * networkConfig.blocksPerMinute)), 
    timeoutBlocks: Math.ceil(minutes * networkConfig.blocksPerMinute),
    lockInStake: lockInStakeUSDC,
  };
}

export default function PricingCalculator() {
  const [network, setNetwork] = useState<Network>("base-sepolia");
  const [inputs, setInputs] = useState<PricingInputs>({
    programCycles: 1_000_000,
    desiredTimeMinutes: 10,
  });

  const networkConfig = NETWORK_CONFIGS[network];
  const suggestion = calculateSuggestion(inputs.programCycles, inputs.desiredTimeMinutes, networkConfig);
cd 
  const handleNumericInput = (e, field: keyof PricingInputs) => {
    const value = e.target.value.replace(/[^0-9]/g, "");
    setInputs((prev) => ({
      ...prev,
      [field]: value ? Number(value) : 0,
    }));
  };

  return (
    <div className="my-8 rounded-lg border border-[var(--vocs-color_border);] p-6">
      <div className="space-y-4">
        {/* Network Dropdown */}
        <div>
          <label htmlFor="network-select" className="mb-2 block text-sm font-medium">
            Network
          </label>
          <select
            id="network-select"
            value={network}
            onChange={(e) => setNetwork(e.target.value as Network)}
            className="w-full rounded border border-[var(--vocs-color_border);] px-3 py-2 bg-white"
          >
            <option value="base-sepolia">Base Sepolia</option>
            <option value="base-mainnet">Base Mainnet</option>
          </select>
        </div>

        <div>
          <label htmlFor="programCycles" className="mb-1 block text-sm">
            Program Cycles
          </label>
          <input
            id="programCycles"
            value={inputs.programCycles}
            onChange={(e) => handleNumericInput(e, "programCycles")}
            className="w-full rounded border border-[var(--vocs-color_border);] px-3 py-2"
          />
        </div>

        <div>
          <label htmlFor="desiredTimeMinutes" className="mb-1 block text-sm">
            Desired Proof Time (in minutes)
          </label>
          <input
            id="desiredTimeMinutes"
            value={inputs.desiredTimeMinutes}
            onChange={(e) => handleNumericInput(e, "desiredTimeMinutes")}
            className="w-full rounded border border-[var(--vocs-color_border);] px-3 py-2"
          />
        </div>

        <div className="pt-4">
          <h4 className="mb-2 font-medium">Suggested Parameters</h4>
          <div className="rounded border border-[var(--vocs-color_border);] bg-muted p-4">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt>Minimum Price:</dt>
                <dd>
                  <NumberFlow
                    className="font-mono"
                    format={{
                      minimumFractionDigits: 8,
                    }}
                    value={suggestion.minPrice}
                    suffix={` ${networkConfig.currencySymbol}`}
                  />
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Maximum Price:</dt>
                <dd>
                  <NumberFlow
                    format={{
                      minimumFractionDigits: 8,
                    }}
                    className="font-mono"
                    value={suggestion.maxPrice}
                    suffix={` ${networkConfig.currencySymbol}`}
                  />
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Bidding Start Delay:</dt>
                <dd>
                  <NumberFlow
                    className="font-mono"
                    value={suggestion.biddingStartDelay}
                    suffix={suggestion.biddingStartDelay === 1 ? " block" : " blocks"}
                  />
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Ramp-up Period:</dt>
                <dd>
                  <NumberFlow
                    className="font-mono"
                    value={suggestion.rampUpBlocks}
                    suffix={suggestion.rampUpBlocks === 1 ? " block" : " blocks"}
                  />
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Timeout:</dt>
                <dd>
                  <NumberFlow
                    className="font-mono"
                    value={suggestion.timeoutBlocks}
                    suffix={suggestion.timeoutBlocks === 1 ? " block" : " blocks"}
                  />
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Lock-in Stake:</dt>
                <dd>
                  <NumberFlow
                    format={{
                      minimumFractionDigits: 6,
                      maximumFractionDigits: 6,
                    }}
                    className="font-mono"
                    value={suggestion.lockInStake}
                    suffix=" USDC"
                  />
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </div>
  );
}
