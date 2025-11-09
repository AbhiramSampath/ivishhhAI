import { useState } from 'react';
import { Audio } from 'expo-av';
import { generateTTS } from '../services/api';

export const useTTS = (token) => {
  const [loading, setLoading] = useState(false);
  const [sound, setSound] = useState(null);

  const generateSpeech = async (text, language, tone, stream, sessionId) => {
    try {
      setLoading(true);
      const data = {
        text,
        language,
        tone,
        stream,
        session_id: sessionId,
      };
      const audioBlob = await generateTTS(data, token);
      const { sound: newSound } = await Audio.Sound.createAsync({ uri: URL.createObjectURL(audioBlob) });
      setSound(newSound);
      return newSound;
    } catch (error) {
      console.error('TTS generation failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const playSpeech = async () => {
    if (sound) {
      await sound.playAsync();
    }
  };

  const stopSpeech = async () => {
    if (sound) {
      await sound.stopAsync();
    }
  };

  return {
    loading,
    generateSpeech,
    playSpeech,
    stopSpeech,
  };
};
