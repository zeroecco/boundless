import { Button } from "vocs/components";

export default function Main() {
  return (
    <div className="fixed inset-0 bg-[url('/bg-light.jpg')] bg-background bg-center bg-cover bg-no-repeat pt-[60px] dark:bg-[url('/bg-dark.jpg')]">
      <div className="flex animate-fade-in flex-col items-center justify-center py-24">
        <h1 className="mb-4 text-center font-bold text-5xl">
          Build <span className="font-normal font-serif">where you are</span>, with the power of ZK
        </h1>

        <img
          className="pointer-events-none my-8 animate-flickerAndFloat opacity-90 drop-shadow-[0_20px_50px_rgba(0,0,0,0.25)] dark:drop-shadow-[0_20px_50px_rgba(255,255,255,0.1)]"
          src="/cubes.png"
          width={300}
          height={300}
          alt="cubes"
        />

        <div className="mt-4 flex gap-4">
          <Button href="/build/quickstart" variant="accent">
            Quick Start
          </Button>
          <Button href="/introduction/why-boundless">Why Boundless?</Button>
        </div>
      </div>
      <img className="pointer-events-none absolute right-24 bottom-24" src="/ys.svg" alt="decorators" />
    </div>
  );
}
