import { useState } from 'react';
import { sendChat } from '../services/api';

export const useChat = (token) => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  const sendMessage = async (message, userId, deviceFingerprint, consentToken, zkpProof, model, language, tone) => {
    try {
      setLoading(true);
      const data = {
        user_id: userId,
        message,
        device_fingerprint: deviceFingerprint,
        consent_token: consentToken,
        zkp_proof: zkpProof,
        model,
        language,
        tone,
      };
      const response = await sendChat(data, token);
      const newMessage = {
        id: Date.now(),
        text: response.reply,
        sender: 'ai',
        emotion: response.emotion,
        timestamp: response.timestamp,
      };
      setMessages(prev => [...prev, newMessage]);
      return response;
    } catch (error) {
      console.error('Chat send failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const addUserMessage = (text) => {
    const newMessage = {
      id: Date.now(),
      text,
      sender: 'user',
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, newMessage]);
  };

  return {
    messages,
    loading,
    sendMessage,
    addUserMessage,
  };
};
