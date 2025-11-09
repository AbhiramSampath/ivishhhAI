import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  StatusBar,
  SafeAreaView,
  Alert,
  Image,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import Svg, { Path } from 'react-native-svg';
import { createAvatar } from './api';

const AIPersonaOnboarding = () => {
  const [currentScreen, setCurrentScreen] = useState(0);
  const [selectedVoiceStyle, setSelectedVoiceStyle] = useState('Calm & Professional');
  const [isRecording, setIsRecording] = useState(false);
  const navigation = useNavigation();

  const voiceStyles = [
    { id: 1, label: 'Friendly & Warm' },
    { id: 2, label: 'Calm & Professional' },
    { id: 3, label: 'Energetic & Upbeat' },
  ];

  const handleVoiceStyleSelect = (style) => {
    setSelectedVoiceStyle(style);
  };

  const handleNext = () => {
    if (currentScreen < 2) {
      setCurrentScreen(currentScreen + 1);
    } else {
      // Call createAvatar API on completion
      createAvatar("dummy_user_token_1234567890", selectedVoiceStyle)
        .then(response => {
          if (response.success) {
            Alert.alert('Setup Complete!', 'Your AI Persona has been created successfully.');
          } else {
            Alert.alert('Error', 'Failed to create AI Persona.');
          }
        })
        .catch(() => {
          Alert.alert('Error', 'Failed to create AI Persona.');
        });
    }
  };

  const handleRecordPress = () => {
    setIsRecording(true);
    setTimeout(() => {
      setIsRecording(false);
      Alert.alert('Recording Complete!', 'Voice sample recorded successfully.');
    }, 3000);
  };

  const renderCreateAvatarScreen = () => (
    <View style={styles.screenContainer}>
      <Image 
        source={require('./assets/curve.png')} 
        style={styles.curveScreen1}
        resizeMode="contain"
      />
      <View style={styles.content}>
        <Text style={styles.title}>Welcome to Your AI Persona</Text>
        <Text style={styles.subtitle}>
          Let's build a voice and personality that speaks just like you — in every language.
        </Text>
      </View>
      <TouchableOpacity style={styles.nextButton} onPress={handleNext}>
        <Text style={styles.nextButtonText}>Get Started</Text>
      </TouchableOpacity>
    </View>
  );

  const renderPickStyleScreen = () => (
    <View style={styles.screenContainer}>
      <Image 
        source={require('./assets/curve.png')} 
        style={styles.curveScreen2}
        resizeMode="contain"
      />
      <View style={styles.content}>
        <Text style={styles.title}>Pick how you Sound</Text>
        <Text style={styles.subtitle}>
          Choose a voice style that reflects your tone. You can always customize more later.
        </Text>

        <View style={styles.voiceOptions}>
          {voiceStyles.map((style) => (
            <TouchableOpacity
              key={style.id}
              style={[
                styles.voiceOption,
                selectedVoiceStyle === style.label && styles.selectedVoiceOption,
              ]}
              onPress={() => handleVoiceStyleSelect(style.label)}>
              <Text
                style={[
                  styles.voiceOptionText,
                  selectedVoiceStyle === style.label && styles.selectedVoiceOptionText,
                ]}>
                {style.label}
              </Text>
              <View
                style={[
                  styles.checkBox,
                  selectedVoiceStyle === style.label && styles.selectedCheckBox,
                ]}>
                {selectedVoiceStyle === style.label && (
                  <Text style={styles.checkMark}>✓</Text>
                )}
              </View>
            </TouchableOpacity>
          ))}
        </View>
      </View>

      <TouchableOpacity style={styles.nextButton} onPress={handleNext}>
        <Text style={styles.nextButtonText}>Next</Text>
      </TouchableOpacity>
    </View>
  );

  const renderRecordVoiceScreen = () => (
    <View style={styles.screenContainer}>
      {/* Back Button */}
      <TouchableOpacity 
        style={styles.backButton} 
        onPress={() => navigation.navigate('Home')}
      >
        <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
          <Path
            d="M19 12H5M12 19L5 12L12 5"
            stroke="#000"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </Svg>
        <Text style={styles.backButtonText}>Back</Text>
      </TouchableOpacity>

      <Image 
        source={require('./assets/curve.png')} 
        style={styles.curveScreen3}
        resizeMode="contain"
      />
      <View style={styles.content}>
        <Text style={styles.title}>Hold the Mic and speak the lines below</Text>
        <Text style={styles.subtitle}>
          Let's build a voice and personality that speaks just like you — in every language.
        </Text>

        <View style={styles.recordingArea}>
          <TouchableOpacity
            style={styles.micButton}
            onPress={handleRecordPress}>
            <Image 
              source={require('./assets/Mic.png')} 
              style={styles.micImage}
              resizeMode="contain"
            />
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );

  const screens = [
    renderCreateAvatarScreen,
    renderPickStyleScreen,
    renderRecordVoiceScreen,
  ];

  return (
    <View style={[styles.container, { backgroundColor: '#FFA364' }]}>
      <StatusBar barStyle="dark-content" />
      <SafeAreaView style={styles.safeArea}>
        {screens[currentScreen]()}
      </SafeAreaView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  safeArea: {
    flex: 1,
  },
  screenContainer: {
    flex: 1,
    paddingHorizontal: 24,
    paddingTop: 60,
  },
  content: {
    flex: 1,
    paddingTop: 40,
    zIndex: 1,
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#000',
    marginBottom: 16,
    lineHeight: 38,
  },
  subtitle: {
    fontSize: 17,
    color: '#333',
    lineHeight: 24,
    marginBottom: 40,
  },
  voiceOptions: {
    marginTop: 20,
    gap: 16,
  },
  voiceOption: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 16,
    paddingHorizontal: 20,
    backgroundColor: 'rgba(255, 255, 255, 0.3)',
    borderRadius: 12,
    borderWidth: 2,
    borderColor: 'transparent',
  },
  selectedVoiceOption: {
    backgroundColor: '#000',
    borderColor: '#000',
  },
  voiceOptionText: {
    fontSize: 17,
    fontWeight: '500',
    color: '#000',
  },
  selectedVoiceOptionText: {
    color: '#fff',
  },
  checkBox: {
    width: 24,
    height: 24,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: '#000',
    backgroundColor: 'transparent',
    alignItems: 'center',
    justifyContent: 'center',
  },
  selectedCheckBox: {
    borderColor: '#fff',
    backgroundColor: '#fff',
  },
  checkMark: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#000',
  },
  recordingArea: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 60,
  },
  micButton: {
    top: 150,
  },
  micImage: {
    width: 80,
    height: 80,
  },
  nextButton: {
    backgroundColor: '#000',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginBottom: 70,
  },
  nextButtonText: {
    color: '#fff',
    fontSize: 17,
    fontWeight: '600',
  },
  // Curve styles for different screens
  curveScreen1: {
    position: 'absolute',
    top: 100,
    right: -50,
    width: 300,
    height: 300,
    opacity: 0.2,
    zIndex: 0,
  },
  curveScreen2: {
    position: 'absolute',
    top: 300,
    left: -80,
    width: 350,
    height: 350,
    opacity: 0.15,
    zIndex: 0,
    transform: [{ rotate: '45deg' }],
  },
  curveScreen3: {
    position: 'absolute',
    bottom: 200,
    right: -100,
    width: 400,
    height: 400,
    opacity: 0.1,
    zIndex: 0,
    transform: [{ rotate: '-30deg' }],
  },
  backButton: {
    position: 'absolute',
    top: 40,
    left: 18,
    zIndex: 10,
    padding: 8,
    flexDirection: 'row',
    alignItems: 'center',
  },
  backButtonText: {
    color: '#000',
    fontSize: 17,
    fontWeight: '600',
    marginLeft: 8,
  },
});

export default AIPersonaOnboarding;