import Footer from "../../footer";
import Hero from "./hero";

export default function Main() {
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        position: "fixed",
        backgroundColor: "#EFECE3",
        padding: "100px",
        top: 0,
        left: 0,
      }}
    >
      <main
        style={{
          backgroundImage: "url('/temp.svg')",
          width: "100%",
          height: "100%",
          backgroundSize: "contain",
          backgroundPosition: "center",
          backgroundRepeat: "no-repeat",
          backgroundColor: "#EFECE3",
          padding: "100px",
        }}
      />
    </div>
  );
}
