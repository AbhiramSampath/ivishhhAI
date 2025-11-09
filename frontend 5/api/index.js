import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE_URL = "http://localhost:8000";

// Token management
async function getAccessToken() {
  return await AsyncStorage.getItem('accessToken');
}

async function setAccessToken(token) {
  await AsyncStorage.setItem('accessToken', token);
}

async function getRefreshToken() {
  return await AsyncStorage.getItem('refreshToken');
}

async function setRefreshToken(token) {
  await AsyncStorage.setItem('refreshToken', token);
}

// Device fingerprint generation (placeholder)
function generateDeviceFingerprint() {
  // Implement device fingerprinting logic here
  return "device_fingerprint_placeholder";
}

// ZKP proof generation (placeholder)
function generateZKPProof() {
  // Implement ZKP proof generation logic here
  return "zkp_proof_placeholder";
}

// Retry logic for API calls
async function fetchWithRetry(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After') || 1;
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return response;
    } catch (error) {
      if (i === retries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1))); // Exponential backoff
    }
  }
}

async function translateText(text, sourceLang, targetLang) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/translate/text`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      text,
      src_lang: sourceLang,
      tgt_lang: targetLang,
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",  // 64+ chars
      user_token: "dummy_user_token_1234567890",     // 10+ chars
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
    }),
  });
  const data = await response.json();
  return data.translated_text;
}

async function getPhrasebook() {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/phrasebook`, {
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
  });
  const data = await response.json();
  return data.phrases;
}

async function sendMessage(message, language, recipientId, saveToPhrasebook = false) {
  const token = await getAccessToken();
  const payload = {
    user_id: recipientId,
    message: message,
    device_fingerprint: generateDeviceFingerprint(),
    consent_token: "",       // Add consent token if available
    zkp_proof: generateZKPProof(),
    language: language,
  };

  const response = await fetchWithRetry(`${API_BASE_URL}/chat`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  return data;
}

async function processVoiceChat(file, language, saveToPhrasebook = false, sourceLang = null) {
  const token = await getAccessToken();
  const formData = new FormData();
  formData.append("file", file);
  formData.append("tgt_lang", language);
  if (sourceLang) {
    formData.append("src_lang", sourceLang);
  }
  formData.append("user_token", "");  // Add user token if needed
  formData.append("zk_proof", generateZKPProof());
  formData.append("device_fingerprint", generateDeviceFingerprint());

  const response = await fetchWithRetry(`${API_BASE_URL}/translate/audio`, {
    method: "POST",
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: formData,
  });
  const data = await response.json();
  return data;
}

// Blockchain API functions
async function regenerateDID(userId) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/blockchain/regenerate-did`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",
    }),
  });
  const data = await response.json();
  return data;
}

async function exportPrivateKey(userId, encryptionPassword) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/blockchain/export-private-key`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
      encryption_password: encryptionPassword,
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",
    }),
  });
  const data = await response.json();
  return data;
}

// Change password API function
async function changePassword(userId, currentPassword, newPassword) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      current_password: currentPassword,
      new_password: newPassword,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",
    }),
  });
  const data = await response.json();
  return data;
}

// Switch language API function
async function switchLanguage(userId, command) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/language/switch`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      command: command,
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",
    }),
  });
  const data = await response.json();
  return data;
}

// User API functions
async function getUserDetails(userId) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/details`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
    }),
  });
  const data = await response.json();
  return data;
}

async function updateVoiceAuth(userId, enabled) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/update-voice-auth`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      voice_auth_enabled: enabled,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
    }),
  });
  const data = await response.json();
  return data;
}

async function fetchLanguages() {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/languages`, {
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
  });
  const data = await response.json();
  return data.languages || [];
}

async function updateUserLanguage(userId, language, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/update-language`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      language,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function uploadVoiceSample(audioBlob, userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const formData = new FormData();
  formData.append('audio', audioBlob);
  formData.append('user_id', userId);
  formData.append('device_fingerprint', deviceFingerprint);
  formData.append('zkp_proof', zkpProof);

  const response = await fetchWithRetry(`${API_BASE_URL}/voice-biometric/upload-sample`, {
    method: 'POST',
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: formData,
  });
  const data = await response.json();
  return data;
}

async function verifyVoiceSample(audioBlob, userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const formData = new FormData();
  formData.append('audio', audioBlob);
  formData.append('user_id', userId);
  formData.append('device_fingerprint', deviceFingerprint);
  formData.append('zkp_proof', zkpProof);

  const response = await fetchWithRetry(`${API_BASE_URL}/voice-biometric/verify`, {
    method: 'POST',
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: formData,
  });
  const data = await response.json();
  return data;
}

async function saveBackupPin(pin, userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/voice-biometric/save-pin`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      pin,
      user_id: userId,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

// Create avatar API function
async function createAvatar(userId, voiceStyle, voiceSample = null) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/create-avatar`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      voice_style: voiceStyle,
      voice_sample: voiceSample,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
      session_token: "dummy_session_token_1234567890123456789012345678901234567890123456789012345678901234567890",
    }),
  });
  const data = await response.json();
  return data;
}

// FAQ API function
async function getFAQs() {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/faq`, {
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
  });
  const data = await response.json();
  return data.faqs;
}

// Feedback API function
async function submitFeedback(email, description, feedbackType, attachment = null) {
  const token = await getAccessToken();
  const formData = new FormData();
  formData.append("email", email);
  formData.append("description", description);
  formData.append("feedback_type", feedbackType);
  formData.append("user_token", "dummy_user_token_1234567890");
  formData.append("device_fingerprint", generateDeviceFingerprint());
  formData.append("zkp_proof", generateZKPProof());
  if (attachment) {
    formData.append("attachment", attachment);
  }

  const response = await fetchWithRetry(`${API_BASE_URL}/feedback/submit`, {
    method: "POST",
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: formData,
  });
  const data = await response.json();
  return data;
}

// Linked accounts API functions
async function linkAccount(accountName) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/link-account`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      account_name: accountName,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
    }),
  });
  const data = await response.json();
  return data;
}

async function unlinkAccount(accountName) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/user/unlink-account`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      account_name: accountName,
      device_fingerprint: generateDeviceFingerprint(),
      zkp_proof: generateZKPProof(),
    }),
  });
  const data = await response.json();
  return data;
}

// Auth API functions
async function login(email, password, deviceFingerprint, zkpProof) {
  const response = await fetchWithRetry(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function register(email, password, deviceFingerprint, zkpProof) {
  const response = await fetchWithRetry(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

// Onboarding API functions
async function completeOnboarding(userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/onboarding/complete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

// Personalization API functions
async function getPersonalization(userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/personalization/get`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function updateMemory(userId, memoryEnabled, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/personalization/update-memory`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      memory_enabled: memoryEnabled,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function updatePrompt(userId, prompt, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/personalization/update-prompt`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      prompt,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function getLanguageTest(userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/personalization/get-language-test`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

async function resetLanguageTest(userId, deviceFingerprint, zkpProof) {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/personalization/reset-language-test`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      user_id: userId,
      device_fingerprint: deviceFingerprint,
      zkp_proof: zkpProof,
    }),
  });
  const data = await response.json();
  return data;
}

// Open Source API functions
async function getOpenSourceLicenses() {
  const token = await getAccessToken();
  const response = await fetchWithRetry(`${API_BASE_URL}/legal/open-source`, {
    headers: {
      "Authorization": token ? `Bearer ${token}` : "",
    },
  });
  const data = await response.json();
  return data;
}

// Add more API functions as needed for other backend routes

export { translateText, getPhrasebook, sendMessage, processVoiceChat, regenerateDID, exportPrivateKey, changePassword, switchLanguage, getUserDetails, updateVoiceAuth, fetchLanguages, updateUserLanguage, uploadVoiceSample, verifyVoiceSample, saveBackupPin, createAvatar, getFAQs, submitFeedback, linkAccount, unlinkAccount, login, register, completeOnboarding, getPersonalization, updateMemory, updatePrompt, getLanguageTest, resetLanguageTest, getOpenSourceLicenses };
