import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
});

// Auth
export const login = async (data) => {
  const response = await api.post('/auth/login', data);
  return response.data;
};

export const register = async (data) => {
  const response = await api.post('/auth/register', data);
  return response.data;
};

export const refreshToken = async (refreshToken) => {
  const response = await api.post('/auth/refresh', { refresh_token: refreshToken });
  return response.data;
};

export const logout = async (token) => {
  const response = await api.post('/auth/logout', {}, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Chat
export const sendChat = async (data, token) => {
  const response = await api.post('/chat/chat', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Translate
export const translateText = async (data, token) => {
  const response = await api.post('/translate/text', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

export const translateAudio = async (formData, token) => {
  const response = await api.post('/translate/audio', formData, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

// STT
export const uploadAudioForSTT = async (formData, token) => {
  const response = await api.post('/stt/upload', formData, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

// TTS
export const generateTTS = async (data, token) => {
  const response = await api.post('/tts/generate', data, {
    headers: { Authorization: `Bearer ${token}` },
    responseType: 'blob'
  });
  return response.data;
};

// Other endpoints can be added similarly

// Sentiment Analysis
export const analyzeSentiment = async (data, token) => {
  const response = await api.post('/sentiment/analyze/sentiment', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Diagnostic
export const getDiagnostic = async (token) => {
  const response = await api.get('/diagnostics/health', {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Health
export const getHealth = async (token) => {
  const response = await api.get('/health/status', {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Permissions
export const getPermissions = async (userId, token) => {
  const response = await api.get('/permissions/user', {
    params: { user_id: userId },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Phrasebook
export const getPhrasebook = async (language, token) => {
  const response = await api.get('/phrasebook/phrases', {
    params: { language },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Report Translation
export const reportTranslation = async (data, token) => {
  const response = await api.post('/report_translation/report', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Sidebar
export const getSidebar = async (userId, token) => {
  const response = await api.get('/sidebar/data', {
    params: { user_id: userId },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Video Call
export const startVideoCall = async (data, token) => {
  const response = await api.post('/video_call/start', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Voice Call
export const startVoiceCall = async (data, token) => {
  const response = await api.post('/voice_call/start', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Collaboration
export const getCollaborationData = async (sessionId, token) => {
  const response = await api.get('/collab/data', {
    params: { session_id: sessionId },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Emoji Reactions
export const sendEmojiReaction = async (data, token) => {
  const response = await api.post('/emoji_reactions/send', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Feedback
export const submitFeedback = async (data, token) => {
  const response = await api.post('/feedback/submit', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Gamified Learning
export const getGamifiedLearning = async (userId, token) => {
  const response = await api.get('/gamified_learning/progress', {
    params: { user_id: userId },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// GPT
export const getGptResponse = async (data, token) => {
  const response = await api.post('/gpt/generate', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Ivish
export const getIvishResponse = async (data, token) => {
  const response = await api.post('/ivish/query', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Language Switch
export const switchLanguage = async (data, token) => {
  const response = await api.post('/language_switch/switch', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// NER Tagger
export const tagNer = async (data, token) => {
  const response = await api.post('/ner_tagger/tag', data, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Referral Rewards
export const getReferralRewards = async (userId, token) => {
  const response = await api.get('/referral_rewards/rewards', {
    params: { user_id: userId },
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};
