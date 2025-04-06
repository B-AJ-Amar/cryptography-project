import { useState } from "react";
import { decryptMessage } from "../api/api";

const DecryptForm = ({ onResult }) => {
  const [ciphertext, setCiphertext] = useState("");
  const [iv, setIv] = useState("");
  const [tag, setTag] = useState("");

  const handleDecrypt = async () => {
    if (!ciphertext || !iv || !tag) return alert("All fields are required");

    try {
      const decryptedData = await decryptMessage({ ciphertext, iv, tag });
      onResult(decryptedData); 
    } catch (error) {
      alert("Decryption failed. Check the backend.");
    }
  };

  return (
    <div>
      <h2>Decrypt a Message</h2>
      <input
        type="text"
        value={ciphertext}
        onChange={(e) => setCiphertext(e.target.value)}
        placeholder="Ciphertext"
      />
      <input
        type="text"
        value={iv}
        onChange={(e) => setIv(e.target.value)}
        placeholder="IV"
      />
      <input
        type="text"
        value={tag}
        onChange={(e) => setTag(e.target.value)}
        placeholder="Tag"
      />
      <button onClick={handleDecrypt}>Decrypt</button>
    </div>
  );
};

export default DecryptForm;
