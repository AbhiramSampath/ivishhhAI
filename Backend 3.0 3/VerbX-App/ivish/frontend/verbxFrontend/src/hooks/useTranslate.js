import { useState } from 'react';
import { translateText, translateAudio } from '../services/api';

export const useTranslate = (token) => {
  const [loading, setLoading] = useState(false);

  const translateTextContent = async (text, srcLang, tgtLang, sessionToken, userToken, zkProof) => {
    try {
      setLoading(true);
      const data = {
        text,
        src_lang: srcLang,
        tgt_lang: tgtLang,
        session_token: sessionToken,
        user_token: userToken,
        zk_proof: zkProof,
      };
      const response = await translateText(data, token);
      return response;
    } catch (error) {
      console.error('Text translation failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const translateAudioContent = async (audioUri, tgtLang, userToken, zkProof) => {
    try {
      setLoading(true);
      const formData = new FormData();
      formData.append('file', {
        uri: audioUri,
        type: 'audio/wav',
        name: 'audio.wav',
      });
      formData.append('tgt_lang', tgtLang);
      formData.append('zk_proof', zkProof);
      const response = await translateAudio(formData, token);
      return response;
    } catch (error) {
      console.error('Audio translation failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  return {
    loading,
    translateTextContent,
    translateAudioContent,
  };
};
