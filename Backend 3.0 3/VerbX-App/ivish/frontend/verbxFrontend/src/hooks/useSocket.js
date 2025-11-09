import { useEffect, useState } from 'react';
import { socket } from '../services/socket';

export const useSocket = () => {
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    socket.on('connect', () => {
      setConnected(true);
    });

    socket.on('disconnect', () => {
      setConnected(false);
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
    };
  }, []);

  const emit = (event, data) => {
    socket.emit(event, data);
  };

  const on = (event, callback) => {
    socket.on(event, callback);
  };

  const off = (event, callback) => {
    socket.off(event, callback);
  };

  return {
    connected,
    emit,
    on,
    off,
  };
};
