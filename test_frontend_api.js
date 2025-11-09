// Simple test for frontend API functions
const { getUserDetails, updateVoiceAuth } = require('./frontend 5/api/index.js');

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ message: 'success' }),
  })
);

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () => ({
  getItem: jest.fn(() => Promise.resolve('mock_token')),
  setItem: jest.fn(() => Promise.resolve()),
}));

// Mock generateDeviceFingerprint and generateZKPProof
jest.mock('./frontend 5/api/index.js', () => ({
  ...jest.requireActual('./frontend 5/api/index.js'),
  generateDeviceFingerprint: jest.fn(() => 'mock_fingerprint'),
  generateZKPProof: jest.fn(() => 'mock_proof'),
}));

describe('Frontend API Tests', () => {
  test('getUserDetails function exists', () => {
    expect(typeof getUserDetails).toBe('function');
  });

  test('updateVoiceAuth function exists', () => {
    expect(typeof updateVoiceAuth).toBe('function');
  });

  test('getUserDetails calls fetch with correct URL', async () => {
    await getUserDetails('testuser');
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('http://localhost:8000/user/details'),
      expect.any(Object)
    );
  });

  test('updateVoiceAuth calls fetch with correct URL', async () => {
    await updateVoiceAuth('testuser', true);
    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:8000/user/update-voice-auth',
      expect.any(Object)
    );
  });
});
