const API_URL = "http://127.0.0.1:5001";

export const encryptMessage = async (message) => {
  try {
    const response = await fetch(`${API_URL}/encrypt`, {  
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    if (!response.ok) {
      throw new Error("Failed to encrypt message");
    }

    return await response.json();
  } catch (error) {
    console.error(error);
    throw new Error("Encryption failed. Please try again.");
  }
};

export const decryptMessage = async ({ ciphertext, iv, tag }) => {
  try {
    const response = await fetch(`${API_URL}/decrypt`, {  
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext, iv, tag }),
    });

    if (!response.ok) {
      throw new Error("Failed to decrypt message");
    }

    return await response.json();
  } catch (error) {
    console.error(error);
    throw new Error("Decryption failed. Please try again.");
  }
};
