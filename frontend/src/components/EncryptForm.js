import { useState } from "react";
import { encryptMessage } from "../api/api";

const EncryptForm = ({ onResult }) => {
  const [message, setMessage] = useState("");

  const handleEncrypt = async () => {
    if (!message.trim()) return alert("Enter a message to encrypt");

    try {
      const encryptedData = await encryptMessage(message);
      onResult(encryptedData); // Pass result to parent
    } catch (error) {
      alert("Encryption failed. Check the backend.");
    }
  };

  return (
    <div>
      <h2>Encrypt a Message</h2>
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter message"
      />
      <button onClick={handleEncrypt}>Encrypt</button>
    </div>
  );
};

export default EncryptForm;
