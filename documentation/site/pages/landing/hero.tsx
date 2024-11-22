import { useEffect } from "react";

export default function Hero() {
  useEffect(() => {
    const logo = document.querySelector(".logo");
    logo?.classList.add("h-10");
  }, []);

  return (
    <section className="relative">
      <div className="cc8v2 c38j2 cscpp c82xa cxj7m absolute" aria-hidden="true">
        <div className="cjxwv cwgyo cjgwc cmxwm csv9q ca7zz c5uon czfz1" />
      </div>
      <div className="cc8v2 c38j2 cfkl5 cvizd c82xa absolute" aria-hidden="true">
        <div className="cjxwv cwgyo cjgwc cmxwm csv9q cx349 ca7zz c5uon czfz1" />
      </div>
      <div className="cc8v2 c38j2 cinxm c2l8u c82xa absolute" aria-hidden="true">
        <div className="cjxwv cwgyo cjgwc cmxwm csv9q cx349 ca7zz c5uon czfz1" />
      </div>

      <div className="cxbfd cx5hs cqcwp cn7jq">
        <div className="ccd2c cb4uz cbgts">
          <div className="cczaz headline-text cb4uz">
            <div className="text-center">
              <img src="/logo.png" alt="Boundless logo" className="mx-auto h-10" />
            </div>
            <h1 className="cqzis c9f55 c9s5u my-16 font-serif">
              The first universal ZK protocol <br />
              that transforms how blockchains compute
            </h1>
            <div className="c441s cqcwp">
              <p className="ce0zw cprne c60f3">
                By turning complex computations into lightweight, verifiable proofs, Boundless enables applications to
                scale seamlessly across all chains—no compromises, no limits.
              </p>
              <p className="ce0zw cprne c60f3">
                With Boundless, developers can write and deploy sophisticated applications once deemed impossible. Build
                without worrying about infrastructure, execution limits, or compute overhead. Our Core Services handle
                proof generation, aggregation, and settlement, while Extensions like Steel and Kailua unlock
                unprecedented cost savings and speed—all using the tools and languages you already know.
              </p>
              <p className="ce0zw cprne c60f3">
                Boundless lets you focus on building the future. We'll handle the rest.
              </p>
              <div className="csw7z c2xfw cgkcp cnbst relative">
                <div className="c0ix1 citj5 c6dyc cdj6q cqcwp relative">
                  <a
                    className="cdnfp cnbzd cnky1 cw1xo c8slg cg07b c07cc cwq93 codvp cnv5k cayql bg-primary text-white dark:text-black"
                    href="/prove/broker-node"
                  >
                    Quick Start
                  </a>
                  <a className="c2np1 c3ns1 c8slg cgwj6 c2mml c07cc cwq93 cayql" href="/introduction/why-boundless">
                    Why Boundless
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
