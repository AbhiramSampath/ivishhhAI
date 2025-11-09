import { io } from "socket.io-client";

const SOCKET_URL = "http://localhost:8003";

const socket = io(SOCKET_URL, {
  path: "/socket.io",
  transports: ["websocket"],
  autoConnect: false,
});

function connect(token) {
  if (!socket.connected) {
    socket.auth = { token };
    socket.connect();
  }
}

function disconnect() {
  if (socket.connected) {
    socket.disconnect();
  }
}

function sendMessage(messageData) {
  socket.emit("text_input", messageData);
}

function sendVoiceData(audioData, language) {
  socket.emit("voice_input", { audio: audioData, language });
}

function onMessage(callback) {
  socket.on("transcript", callback);
}

function onVoiceTranscript(callback) {
  socket.on("voice_transcript", callback);
}

function onVoiceResponse(callback) {
  socket.on("voice_response", callback);
}

function onIvishResponse(callback) {
  socket.on("response", callback);
}

function onCallInitiated(callback) {
  socket.on("call_initiated", callback);
}

function onCallAnswered(callback) {
  socket.on("call_answered", callback);
}

function onCallEnded(callback) {
  socket.on("call_ended", callback);
}

function onError(callback) {
  socket.on("error", callback);
}

export {
  socket,
  connect,
  disconnect,
  sendMessage,
  sendVoiceData,
  onMessage,
  onVoiceTranscript,
  onVoiceResponse,
  onIvishResponse,
  onCallInitiated,
  onCallAnswered,
  onCallEnded,
  onError,
};
