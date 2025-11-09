import React, { useState } from 'react';
import { View, Text, StyleSheet, SafeAreaView, TouchableOpacity, TextInput, Animated, Easing, Alert } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { uploadVoiceSample, verifyVoiceSample, saveBackupPin, updateVoiceAuth } from './api/index';

// Reusable Components
const NavIconsBack = ({ onPress }) => (
  <View style={styles.navIconsBackContainer}>
    <TouchableOpacity onPress={onPress}>
      <Svg width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </TouchableOpacity>
  </View>
);

const Header = ({ onBackPress }) => (
  <View style={styles.header}>
    <View style={styles.headerContent}>
      <NavIconsBack onPress={onBackPress} />
    </View>
  </View>
);

const PrimaryButton = ({ title, onPress }) => (
  <TouchableOpacity style={styles.primaryButton} onPress={onPress}>
    <Text style={styles.primaryButtonText}>{title}</Text>
  </TouchableOpacity>
);

const SecondaryButton = ({ title, onPress }) => (
  <TouchableOpacity style={styles.secondaryButton} onPress={onPress}>
    <Text style={styles.secondaryButtonText}>{title}</Text>
  </TouchableOpacity>
);

const MicrophoneIcon = ({ onPress, isRecording }) => {
  const scaleAnim = new Animated.Value(1);

  const startAnimation = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(scaleAnim, {
          toValue: 1.1,
          duration: 500,
          easing: Easing.in(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(scaleAnim, {
          toValue: 1,
          duration: 500,
          easing: Easing.out(Easing.ease),
          useNativeDriver: true,
        }),
      ]),
      { iterations: -1 }
    ).start();
  };

  React.useEffect(() => {
    if (isRecording) {
      startAnimation();
    } else {
      scaleAnim.setValue(1);
    }
  }, [isRecording]);

  return (
    <View style={styles.micIconContainer}>
      <Animated.View style={[styles.micBackground, isRecording && { transform: [{ scale: scaleAnim }] }]}>
        <TouchableOpacity onPress={onPress} style={styles.micButton}>
          <Svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <Path d="M12 15C13.6569 15 15 13.6569 15 12V6C15 4.34315 13.6569 3 12 3C10.3431 3 9 4.34315 9 6V12C9 13.6569 10.3431 15 12 15Z" fill="#F6F6F8" stroke="#F6F6F8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            <Path d="M19 12C19 15.866 15.866 19 12 19C8.13401 19 5 15.866 5 12M12 19V21" stroke="#F6F6F8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </Svg>
        </TouchableOpacity>
      </Animated.View>
    </View>
  );
};

const VoiceBiometricSetup = () => {
  const navigation = useNavigation();
  const [currentStep, setCurrentStep] = useState(1);
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [isRecording, setIsRecording] = useState(false);
  const [loading, setLoading] = useState(false);

  // Mock user data - replace with actual auth context
  const userId = 'user123';
  const deviceFingerprint = 'device123';
  const zkpProof = 'proof123';

  // This function now handles both internal step changes and navigation
  const handleBackPress = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    } else {
      navigation.goBack();
    }
  };

  const handleSetupComplete = async () => {
    setLoading(true);
    try {
      await updateVoiceAuth(userId, true, deviceFingerprint, zkpProof);
      Alert.alert('Success', 'Voice authentication has been enabled.');
      navigation.goBack(); // Or navigate to home/settings
    } catch (error) {
      console.error('Error enabling voice auth:', error);
      Alert.alert('Error', 'Failed to enable voice authentication. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const renderScreen = () => {
    switch (currentStep) {
      case 1:
        return (
          <View style={styles.screenContent}>
            <Text style={styles.stepIndicator}>Step 1 of 4</Text>
            <Text style={styles.sectionTitle}>Set Up Your Voice Biometric</Text>
            <Text style={styles.bodyText}>Use your voice to quickly and securely verify your identity.</Text>
            <View style={styles.bottomButtonContainer}>
              <PrimaryButton title="Get Started" onPress={() => setCurrentStep(2)} />
            </View>
          </View>
        );
      case 2:
        return (
          <View style={styles.screenContent}>
            <Text style={styles.stepIndicator}>Step 2 of 4</Text>
            <Text style={styles.sectionTitle}>Hold the Mic and speak the Phrase below</Text>
            <Text style={styles.bodyText}>My voice is my password</Text>
            <View style={styles.microphoneContainer}>
              <MicrophoneIcon onPress={async () => {
                setIsRecording(!isRecording);
                if (isRecording) {
                  setLoading(true);
                  try {
                    // Mock audio blob - in real app, get from recording
                    const mockAudioBlob = new Blob(['mock audio data'], { type: 'audio/wav' });
                    await uploadVoiceSample(mockAudioBlob, userId, deviceFingerprint, zkpProof);
                    setCurrentStep(3);
                  } catch (error) {
                    console.error('Error uploading voice sample:', error);
                    Alert.alert('Error', 'Failed to upload voice sample. Please try again.');
                  } finally {
                    setLoading(false);
                  }
                }
              }} isRecording={isRecording} />
              {loading && <Text style={styles.loadingText}>Uploading...</Text>}
            </View>
          </View>
        );
      case 3:
        return (
          <View style={styles.screenContent}>
            <Text style={styles.stepIndicator}>Step 3 of 4</Text>
            <Text style={styles.sectionTitle}>Now we'll verify your voiceprint by matching your sample.</Text>
            <View style={styles.progressBarContainer}>
              <View style={styles.progressBarBackground}>
                <View style={styles.progressBarFill} />
              </View>
              <Text style={styles.progressPercentage}>25%</Text>
            </View>
            <View style={styles.bottomButtonContainer}>
              <SecondaryButton title="Retry" onPress={() => setCurrentStep(2)} />
              <View style={{ height: 10 }} />
              <PrimaryButton title="Verify Voice" onPress={async () => {
                setLoading(true);
                try {
                  // Mock audio blob - in real app, get from recording
                  const mockAudioBlob = new Blob(['mock verification audio'], { type: 'audio/wav' });
                  const result = await verifyVoiceSample(mockAudioBlob, userId, deviceFingerprint, zkpProof);
                  if (result.verified) {
                    setCurrentStep(4);
                  } else {
                    Alert.alert('Verification Failed', 'Voice verification failed. Please try again.');
                  }
                } catch (error) {
                  console.error('Error verifying voice:', error);
                  Alert.alert('Error', 'Failed to verify voice. Please try again.');
                } finally {
                  setLoading(false);
                }
              }} />
              {loading && <Text style={styles.loadingText}>Verifying...</Text>}
            </View>
          </View>
        );
      case 4:
        return (
          <View style={[styles.screenContent, { justifyContent: 'space-between' }]}>
            <View style={{ width: '100%' }}>
              <Text style={styles.stepIndicator}>Step 4 of 4</Text>
              <Text style={styles.sectionTitle}>Set a backup PIN</Text>
              <Text style={styles.bodyText}>If we can’t recognize your voice, you can use this PIN to access your account.</Text>
              <View style={styles.pinInputContainer}>
                <TextInput
                  style={styles.textInput}
                  placeholder="Enter PIN"
                  placeholderTextColor="#848484"
                  keyboardType="numeric"
                  secureTextEntry
                  value={pin}
                  onChangeText={setPin}
                />
                <TextInput
                  style={styles.textInput}
                  placeholder="Confirm PIN"
                  placeholderTextColor="#848484"
                  keyboardType="numeric"
                  secureTextEntry
                  value={confirmPin}
                  onChangeText={setConfirmPin}
                />
              </View>
            </View>
            <View style={styles.bottomButtonContainer}>
              <PrimaryButton title="Save PIN" onPress={async () => {
                if (pin !== confirmPin) {
                  Alert.alert('Error', 'PINs do not match');
                  return;
                }
                setLoading(true);
                try {
                  await saveBackupPin(pin, userId, deviceFingerprint, zkpProof);
                  setCurrentStep(5);
                } catch (error) {
                  console.error('Error saving PIN:', error);
                  Alert.alert('Error', 'Failed to save PIN. Please try again.');
                } finally {
                  setLoading(false);
                }
              }} />
              {loading && <Text style={styles.loadingText}>Saving...</Text>}
            </View>
          </View>
        );
      case 5:
        return (
          <View style={styles.screenContent}>
            <Text style={styles.stepIndicator}>Step 4 of 4</Text>
            <Text style={styles.completionTitle}>Your voice biometric setup is complete.</Text>
            <Text style={styles.completionBody}>Your voiceprint is securely stored and used solely to identify you. Your privacy and data security are our priority.</Text>
            <View style={styles.bottomButtonContainer}>
              <PrimaryButton title="Re-enroll voiceprint" onPress={() => setCurrentStep(2)} />
              <View style={{ height: 10 }} />
              <SecondaryButton title="Delete" onPress={() => setCurrentStep(1)} />
            </View>
            {loading && <Text style={styles.loadingText}>Enabling voice auth...</Text>}
          </View>
        );
      default:
        return null;
    }
  };

  React.useEffect(() => {
    if (currentStep === 5) {
      handleSetupComplete();
    }
  }, [currentStep]);

  return (
    <SafeAreaView style={styles.container}>
      <Header onBackPress={handleBackPress} />
      {renderScreen()}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    paddingTop:44,
  },
  header: {
    paddingTop: 30,
    paddingHorizontal: 7,
    marginBottom: 20,
    marginLeft:10,
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
  },
  navIconsBackContainer: {
    height: 36,
    width: 36,
    justifyContent: 'center',
    alignItems: 'center',
  },
  headerTitle: {
    color: '#0C0D11',
    fontSize: 20,
    fontWeight: '500',
  },
  screenContent: {
    flex: 1,
    paddingHorizontal: 20,
    justifyContent: 'flex-start',
    alignItems: 'center',
  },
  stepIndicator: {
    fontSize: 18,
    color: '#2C2C2C',
    textAlign: 'left',
    marginBottom: 20,
    alignSelf: 'flex-start',
    fontWeight: '500',
  },
  sectionTitle: {
    fontSize: 40,
    fontWeight: '700',
    color: '#0C0D11',
    textAlign: 'left',
    marginBottom: 12,
    alignSelf: 'flex-start',
    width: '100%',
  },
  bodyText: {
    fontSize: 16,
    color: '#121417',
    textAlign: 'left',
    marginBottom: 30,
    alignSelf: 'flex-start',
    width: '100%',
  },
  bottomButtonContainer: {
    position: 'absolute',
    bottom: 20,
    width: '100%',
    paddingHorizontal: 20,
  },
  primaryButton: {
    backgroundColor: '#0C0D11',
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
    height: 52,
  },
  primaryButtonText: {
    color: '#F6F6F8',
    fontSize: 17,
    fontWeight: '700',
  },
  secondaryButton: {
    backgroundColor: '#E0E0E0',
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    height: 52,
  },
  secondaryButtonText: {
    color: '#2C2C2C',
    fontSize: 17,
    fontWeight: '700',
  },
  // Screen-specific styles
  microphoneContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  micIconContainer: {
    width: 150,
    height: 150,
    backgroundColor: '#E0E0E0',
    borderRadius: 75,
    justifyContent: 'center',
    alignItems: 'center',
  },
  micBackground: {
    width: 100,
    height: 100,
    backgroundColor: '#0C0D11',
    borderRadius: 50,
    justifyContent: 'center',
    alignItems: 'center',
    position: 'absolute',
  },
  micButton: {
    width: '100%',
    height: '100%',
    justifyContent: 'center',
    alignItems: 'center',
  },
  progressBarContainer: {
    marginTop: 50,
    width: '100%',
    alignItems: 'center',
  },
  progressBarBackground: {
    height: 8,
    backgroundColor: '#E0E0E0',
    borderRadius: 4,
    overflow: 'hidden',
    width: '100%',
    marginBottom: 5,
  },
  progressBarFill: {
    width: '25%',
    height: '100%',
    backgroundColor: '#FFA364',
    borderRadius: 4,
  },
  progressPercentage: {
    fontSize: 14,
    color: '#0C0D11',
    alignSelf: 'flex-end',
    marginTop: 5,
  },
  pinInputContainer: {
    width: '100%',
    marginTop: 40,
    marginBottom: 20,
  },
  textInput: {
    height: 44,
    backgroundColor: '#E7E7E7',
    borderRadius: 12,
    paddingHorizontal: 18,
    fontSize: 14,
    color: '#0C0D11',
    marginBottom: 12,
  },
  completionTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#0C0D11',
    textAlign: 'center',
    marginTop: 20,
  },
  completionBody: {
    fontSize: 16,
    color: '#2C2C2C',
    textAlign: 'center',
    marginTop: 10,
  },
});

export default VoiceBiometricSetup;