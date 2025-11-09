import { useState, useRef } from 'react';
import { Audio } from 'expo-av';
import { uploadAudioForSTT } from '../services/api';
import { socket, connectRealtimeSTT, sendAudioChunk } from '../services/socket';

export const useVoice = (token) => {
  const [recording, setRecording] = useState(false);
  const [transcription, setTranscription] = useState('');
  const [realtimeTranscription, setRealtimeTranscription] = useState('');
  const recordingRef = useRef(null);

  const startRecording = async () => {
    try {
      const { status } = await Audio.requestPermissionsAsync();
      if (status !== 'granted') {
        throw new Error('Audio permission not granted');
      }

      await Audio.setAudioModeAsync({
        allowsRecordingIOS: true,
        interruptionModeIOS: Audio.INTERRUPTION_MODE_IOS_DO_NOT_MIX,
        playsInSilentModeIOS: true,
        shouldDuckAndroid: true,
        interruptionModeAndroid: Audio.INTERRUPTION_MODE_ANDROID_DO_NOT_MIX,
        playThroughEarpieceAndroid: false,
      });

      const recording = new Audio.Recording();
      await recording.prepareToRecordAsync(Audio.RECORDING_OPTIONS_PRESET_HIGH_QUALITY);
      await recording.startAsync();
      recordingRef.current = recording;
      setRecording(true);
    } catch (error) {
      console.error('Failed to start recording:', error);
    }
  };

  const stopRecording = async () => {
    try {
      if (recordingRef.current) {
        await recordingRef.current.stopAndUnloadAsync();
        const uri = recordingRef.current.getURI();
        recordingRef.current = null;
        setRecording(false);
        return uri;
      }
    } catch (error) {
      console.error('Failed to stop recording:', error);
    }
    setRecording(false);
    return null;
  };

  const uploadForSTT = async (audioUri) => {
    try {
      const formData = new FormData();
      formData.append('file', {
        uri: audioUri,
        type: 'audio/wav',
        name: 'recording.wav',
      });
      const response = await uploadAudioForSTT(formData, token);
      setTranscription(response.text);
      return response;
    } catch (error) {
      console.error('STT upload failed:', error);
      throw error;
    }
  };

  const startRealtimeSTT = () => {
    connectRealtimeSTT(token);
    socket.on('transcription', (data) => {
      setRealtimeTranscription(data.text);
    });
  };

  const stopRealtimeSTT = () => {
    socket.off('transcription');
  };

  return {
    recording,
    transcription,
    realtimeTranscription,
    startRecording,
    stopRecording,
    uploadForSTT,
    startRealtimeSTT,
    stopRealtimeSTT,
  };
};
