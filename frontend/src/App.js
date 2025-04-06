import { useState } from "react";
import EncryptForm from "./components/EncryptForm";
import DecryptForm from "./components/DecryptForm";
import ResultDisplay from "./components/ResultDisplay";

const App = () => {
  const [result, setResult] = useState(null);

  return (
    <div>
      <h1>CryptoAES Web App</h1>
      <EncryptForm onResult={setResult} />
      <DecryptForm onResult={setResult} />
      <ResultDisplay data={result} />
    </div>
  );
};

export default App;
