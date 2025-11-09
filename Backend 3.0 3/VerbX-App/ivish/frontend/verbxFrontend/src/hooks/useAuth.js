import { useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { login, register, refreshToken, logout } from '../services/api';

export const useAuth = () => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStoredAuth();
  }, []);

  const loadStoredAuth = async () => {
    try {
      const storedToken = await AsyncStorage.getItem('token');
      const storedUser = await AsyncStorage.getItem('user');
      if (storedToken && storedUser) {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
      }
    } catch (error) {
      console.error('Error loading auth:', error);
    } finally {
      setLoading(false);
    }
  };

  const loginUser = async (email, password, deviceFingerprint, voiceSample, zkpProof) => {
    try {
      const data = { email, password, device_fingerprint: deviceFingerprint, voice_sample: voiceSample, zkp_proof: zkpProof };
      const response = await login(data);
      const { access_token, refresh_token } = response;
      setToken(access_token);
      setUser({ email });
      await AsyncStorage.setItem('token', access_token);
      await AsyncStorage.setItem('refreshToken', refresh_token);
      await AsyncStorage.setItem('user', JSON.stringify({ email }));
      return response;
    } catch (error) {
      throw error;
    }
  };

  const registerUser = async (email, password, deviceFingerprint, voiceSample, zkpProof) => {
    try {
      const data = { email, password, device_fingerprint: deviceFingerprint, voice_sample: voiceSample, zkp_proof: zkpProof };
      const response = await register(data);
      return response;
    } catch (error) {
      throw error;
    }
  };

  const logoutUser = async () => {
    try {
      if (token) {
        await logout(token);
      }
      setUser(null);
      setToken(null);
      await AsyncStorage.removeItem('token');
      await AsyncStorage.removeItem('refreshToken');
      await AsyncStorage.removeItem('user');
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const refreshUserToken = async () => {
    try {
      const refreshTokenValue = await AsyncStorage.getItem('refreshToken');
      if (refreshTokenValue) {
        const response = await refreshToken(refreshTokenValue);
        const { access_token } = response;
        setToken(access_token);
        await AsyncStorage.setItem('token', access_token);
        return response;
      }
    } catch (error) {
      throw error;
    }
  };

  return {
    user,
    token,
    loading,
    loginUser,
    registerUser,
    logoutUser,
    refreshUserToken,
  };
};
