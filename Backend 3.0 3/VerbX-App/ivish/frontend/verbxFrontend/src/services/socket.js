import io from 'socket.io-client';
import { API_BASE_URL } from '../constants/api';

export const socket = io(API_BASE_URL, {
  transports: ['websocket'],
  upgrade: false,
});

// For realtime STT
export const connectRealtimeSTT = (token) => {
  socket.emit('authenticate', { token });
};

export const sendAudioChunk = (chunk) => {
  socket.emit('audio_chunk', chunk);
};

socket.on('transcription', (data) => {
  // Handle transcription data
  console.log('Transcription:', data);
});

// Other socket events can be added
