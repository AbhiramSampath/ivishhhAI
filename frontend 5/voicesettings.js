import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Platform,
  Animated,
  Alert,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import Slider from '@react-native-community/slider';
import { useNavigation } from '@react-navigation/native';
import { updateVoiceAuth } from './api/index';

// Custom Dropdown Component (No changes)
const CustomDropdown = ({ label, selectedValue, options, onSelect, isOpen, onToggle }) => {
  return (
    <View style={[styles.dropdownContainer, Platform.OS === 'android' && { zIndex: 1 }]}>
      <Text style={styles.dropdownLabel}>{label}</Text>
      <TouchableOpacity style={styles.dropdownButton} onPress={onToggle}>
        <Text style={styles.dropdownText}>{selectedValue}</Text>
        <Svg
          width={14}
          height={8}
          viewBox="0 0 14 8"
          fill="none"
          style={[styles.dropdownIcon, isOpen && styles.dropdownIconOpen]}
        >
          <Path
            d={"M1 1L7 7L13 1"}
            stroke="#4A4A4A"
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </Svg>
      </TouchableOpacity>
      {isOpen && (
        <View style={styles.dropdownOptions}>
          {options.map((option, index) => (
            <TouchableOpacity
              key={index}
              style={[
                styles.dropdownOption,
                selectedValue === option && styles.dropdownOptionSelected,
                index === 0 && styles.dropdownOptionFirst,
                index === options.length - 1 && styles.dropdownOptionLast
              ]}
              onPress={() => {
                onSelect(option);
                onToggle();
              }}
            >
              <Text style={[
                styles.dropdownOptionText,
                selectedValue === option && styles.dropdownOptionTextSelected
              ]}>
                {option}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      )}
    </View>
  );
};

// Custom Slider Component (No changes)
const CustomSlider = ({ title, value, onValueChange, minimumValue = 0, maximumValue = 1, step = 0.1, unit = "x" }) => {
  const displayValue = unit === "x" ? `${value}${unit}` : value;
  const getTickMarks = () => {
    const marks = [];
    const interval = step * 4;
    if (interval <= 0) return marks;
    const count = Math.max(1, Math.floor((maximumValue - minimumValue) / interval));
    for (let i = 0; i <= count; i++) {
      const markVal = parseFloat((minimumValue + i * interval).toFixed(6));
      marks.push(markVal);
    }
    if (marks[marks.length - 1] < maximumValue - 1e-9) marks.push(maximumValue);
    return marks;
  };
  const marks = getTickMarks();
  const handleTickPress = (mark) => {
    const snapped = Math.round(mark / step) * step;
    onValueChange(Number(snapped.toFixed(6)));
  };
  const onAccessibilityAction = (event) => {
    const action = event.nativeEvent.actionName;
    if (action === 'increment') {
      const next = Math.min(maximumValue, +(value + step).toFixed(6));
      onValueChange(next);
    } else if (action === 'decrement') {
      const prev = Math.max(minimumValue, +(value - step).toFixed(6));
      onValueChange(prev);
    }
  };
  return (
    <View style={styles.sliderContainer}>
      <View style={styles.sliderHeader}>
        <Text style={styles.sliderTitle}>{title}</Text>
        <Text style={styles.sliderValue}>{displayValue}</Text>
      </View>
      <View style={styles.sliderWrapper}>
        <Slider
          style={styles.slider}
          minimumValue={minimumValue}
          maximumValue={maximumValue}
          value={value}
          onValueChange={onValueChange}
          step={step}
          minimumTrackTintColor="#E6E6E6"
          maximumTrackTintColor="#E6E6E6"
          thumbTintColor="#FF8A3D"
          accessible={true}
          accessibilityLabel={`${title} slider`}
          accessibilityRole="adjustable"
          accessibilityActions={[{ name: 'increment' }, { name: 'decrement' }]}
          onAccessibilityAction={onAccessibilityAction}
        />
        <View style={styles.tickMarksContainer} pointerEvents="box-none">
          {marks.map((mark, index) => {
            const percent = ((mark - minimumValue) / (maximumValue - minimumValue)) * 100;
            const leftPercent = `${percent}%`;
            return (
              <TouchableOpacity
                key={index}
                activeOpacity={0.9}
                onPress={() => handleTickPress(mark)}
                accessibilityLabel={`${title} ${mark}${unit}`}
                accessibilityRole="button"
                style={[
                  styles.tickTouchArea,
                  { left: leftPercent, transform: [{ translateX: -22 }] }
                ]}
              >
                <View style={styles.tickDot} />
              </TouchableOpacity>
            );
          })}
        </View>
      </View>
    </View>
  );
};

// Custom Toggle Component with smooth Animated API
const CustomToggle = ({ title, subtitle, value, onValueChange, onToggleChange }) => {
  // `Animated.Value` to track the thumb position
  const thumbTranslateX = useRef(new Animated.Value(value ? 18 : 0)).current;

  // Animate the thumb position whenever the `value` prop changes
  useEffect(() => {
    Animated.timing(thumbTranslateX, {
      toValue: value ? 18 : 0, // 44 (track width) - 22 (thumb width) - 4 (padding) = 18
      duration: 250, // Animation duration in milliseconds
      useNativeDriver: true, // Use native driver for better performance
    }).start();
  }, [value, thumbTranslateX]);

  const handlePress = async () => {
    const newValue = !value;
    onValueChange(newValue);
    if (onToggleChange) {
      try {
        await onToggleChange(newValue);
      } catch (error) {
        console.error('Failed to update voice auth:', error);
        // Revert on error
        onValueChange(value);
      }
    }
  };

  return (
    <View style={styles.toggleContainer}>
      <View style={styles.toggleContent}>
        <View style={styles.toggleTextContainer}>
          <Text style={styles.toggleTitle}>{title}</Text>
          <Text style={styles.toggleSubtitle}>{subtitle}</Text>
        </View>
        <TouchableOpacity
          style={[
            styles.customToggleTrack,
            value && styles.customToggleTrackActive
          ]}
          onPress={handlePress}
        >
          {/* Use `Animated.View` to apply the animation */}
          <Animated.View style={[
            styles.customToggleThumb,
            { transform: [{ translateX: thumbTranslateX }] }
          ]} />
        </TouchableOpacity>
      </View>
    </View>
  );
};

export default function VoiceSettings() {
  const navigation = useNavigation();
  // State management
  const [voiceSpeed, setVoiceSpeed] = useState(0.5);
  const [selectedVoiceType, setSelectedVoiceType] = useState('Male');
  const [isVoiceDropdownOpen, setIsVoiceDropdownOpen] = useState(false);
  const [wakeWordEnabled, setWakeWordEnabled] = useState(false);
  const [micSensitivity, setMicSensitivity] = useState(0.5);
  const [emotionToneEnabled, setEmotionToneEnabled] = useState(false);
  const [voiceBiometricsEnabled, setVoiceBiometricsEnabled] = useState(false);
  const [loading, setLoading] = useState(false);
  const voiceTypeOptions = ['Male', 'Female', 'Emotional Tone'];
  const getSensitivityLabel = (value) => {
    if (value <= 0.33) return 'Low';
    if (value <= 0.66) return 'Medium';
    return 'High';
  };
  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* Header */}
        <View style={styles.header}>
          <View style={styles.headerContent}>
            <TouchableOpacity onPress={() => navigation.goBack()}>
              <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
                <Path
                  d="M7 1L1 7L7 13"
                  stroke="#2C2C2C"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </Svg>
            </TouchableOpacity>
            <Text style={styles.headerTitle}>Voice Settings</Text>
          </View>
        </View>
        {/* Voice Speed Slider */}
        <CustomSlider
          title="Voice Speed"
          value={voiceSpeed}
          onValueChange={setVoiceSpeed}
          minimumValue={0.1}
          maximumValue={2.0}
          step={0.1}
          unit="x"
        />
        {/* Voice Type Selection Dropdown */}
        <CustomDropdown
          label="Voice Type Selection"
          selectedValue={selectedVoiceType}
          options={voiceTypeOptions}
          onSelect={setSelectedVoiceType}
          isOpen={isVoiceDropdownOpen}
          onToggle={() => setIsVoiceDropdownOpen(!isVoiceDropdownOpen)}
        />
        {/* Wake Word Toggle */}
        <CustomToggle
          title="Wake Word"
          subtitle="Enable the 'Hey Ivish' wake word to activate the assistant."
          value={wakeWordEnabled}
          onValueChange={setWakeWordEnabled}
        />
        {/* Mic Sensitivity Slider */}
        <CustomSlider
          title="Mic Sensitivity"
          value={micSensitivity}
          onValueChange={setMicSensitivity}
          minimumValue={0}
          maximumValue={1}
          step={0.01}
          unit={getSensitivityLabel(micSensitivity)}
        />
        {/* Emotion Tone Toggle */}
        <CustomToggle
          title="Emotion Tone"
          subtitle="Enable emotional speech output to sound more human-like."
          value={emotionToneEnabled}
          onValueChange={setEmotionToneEnabled}
        />
        {/* Voice Biometrics Toggle */}
        <CustomToggle
          title="Voice Biometrics"
          subtitle="Use your voice to unlock the assistant and verify your identity."
          value={voiceBiometricsEnabled}
          onValueChange={setVoiceBiometricsEnabled}
          onToggleChange={async (enabled) => {
            setLoading(true);
            try {
              await enableVoiceBiometrics(enabled);
            } catch (error) {
              console.error('Error updating voice biometrics:', error);
              Alert.alert('Error', 'Failed to update voice biometrics. Please try again.');
              setVoiceBiometricsEnabled(!enabled); // Revert on error
            } finally {
              setLoading(false);
            }
          }}
        />
        {/* Voice Biometrics Setup Button */}
        <TouchableOpacity 
          style={[
            styles.setupButton,
            voiceBiometricsEnabled && styles.setupButtonActive
          ]} 
          onPress={() => navigation.navigate('VoiceBiometrics')} // Updated navigation target
        >
          <Text style={[
            styles.setupButtonText,
            voiceBiometricsEnabled && styles.setupButtonTextActive
          ]}>
            Voice Biometrics Setup
          </Text>
          <Svg width={8} height={14} viewBox="0 0 8 14" fill="none">
            <Path
              d="M1 13L7 7L1 1"
              stroke={voiceBiometricsEnabled ? "#FFFFFF" : "#4A4A4A"}
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </TouchableOpacity>
      </ScrollView>
      {/* Background signature */}
      <View style={styles.signatureContainer}>
        <Text style={styles.signature}>L</Text>
      </View>
    </View>
  );
}
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    paddingTop: 50,
  },
  scrollContent: {
    paddingBottom: 100,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'flex-start',
    paddingHorizontal: 20,
    marginBottom: 20,
    marginLeft:10,
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 25,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
    lineHeight: 26,
  },
  // Slider Styles
  sliderContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
  },
  sliderHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  sliderTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
  },
  sliderValue: {
    fontSize: 14,
    fontWeight: '500',
    color: '#61758A',
    fontFamily: 'Poppins',
  },
  sliderWrapper: {
    height: 56,
    justifyContent: 'center',
    position: 'relative',
  },
  slider: {
    width: '100%',
    height: 40,
  },
  tickMarksContainer: {
    position: 'absolute',
    left: 0,
    right: 0,
    top: '50%',
    height: 44,
    marginTop: -22,
  },
  tickTouchArea: {
    position: 'absolute',
    width: 44,
    height: 44,
    justifyContent: 'center',
    alignItems: 'center',
  },
  tickDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#D1D1D1',
  },
  tickDotHovered: {
    backgroundColor: '#B8B8B8',
    transform: [{ scale: 1.15 }],
  },
  // Dropdown Styles
  dropdownContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
    zIndex: 1000,
  },
  dropdownLabel: {
    fontSize: 16,
    fontWeight: '500',
    color: '#0E0E0E',
    fontFamily: 'Poppins',
    marginBottom: 4,
  },
  dropdownButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#F6F6F8',
    borderWidth: 1,
    borderColor: '#4A4A4A',
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 8,
    height: 36,
  },
  dropdownButtonOpen: {
    backgroundColor: 'rgba(255, 138, 61, 0.1)',
  },
  dropdownText: {
    fontSize: 14,
    fontWeight: '500',
    color: '#4A4A4A',
    fontFamily: 'Poppins',
    flex: 1,
  },
  dropdownIcon: {
    transition: 'transform 0.2s',
  },
  dropdownIconOpen: {
    transform: [{ rotate: '180deg' }],
  },
  dropdownOptions: {
    backgroundColor: '#FFFFFF',
    borderWidth: 1,
    borderColor: '#4A4A4A',
    borderRadius: 12,
    marginTop: 4,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
    overflow: 'hidden',
  },
  dropdownOption: {
    paddingHorizontal: 12,
    paddingVertical: 12,
  },
  dropdownOptionFirst: {
    borderTopLeftRadius: 12,
    borderTopRightRadius: 12,
  },
  dropdownOptionLast: {
    borderBottomLeftRadius: 12,
    borderBottomRightRadius: 12,
  },
  dropdownOptionSelected: {
    backgroundColor: 'rgba(255, 163, 100, 0.7)',
  },
  dropdownOptionText: {
    fontSize: 14,
    fontWeight: '500',
    color: '#4A4A4A',
    fontFamily: 'Poppins',
  },
  dropdownOptionTextSelected: {
    color: '#2C2C2C',
  },
  dropdownSubtitle: {
    fontSize: 10,
    fontWeight: '400',
    color: '#787878',
    fontFamily: 'Poppins',
    lineHeight: 14,
    marginTop: 6,
  },
  // List Item Styles
  listItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 32,
    paddingVertical: 16,
    backgroundColor: '#FFFFFF',
  },
  listItemTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#0E0E0E',
    fontFamily: 'Poppins',
    flex: 1,
  },
  // Toggle Styles
  toggleContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
  },
  toggleContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  toggleTextContainer: {
    flex: 1,
    marginRight: 16,
  },
  toggleTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#0E0E0E',
    fontFamily: 'Poppins',
    marginBottom: 4,
  },
  toggleSubtitle: {
    fontSize: 12,
    fontWeight: '400',
    color: '#848484',
    fontFamily: 'Poppins',
    lineHeight: 16,
  },
  customToggleTrack: {
    width: 44,
    height: 22,
    borderRadius: 11,
    backgroundColor: '#E6E6E6',
    justifyContent: 'center',
    padding: 2,
    position: 'relative',
  },
  customToggleTrackActive: {
    backgroundColor: '#FF8A3D',
  },
  customToggleThumb: {
    width: 18,
    height: 18,
    borderRadius: 9,
    backgroundColor: '#FFFFFF',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 2,
    elevation: 2,
  },
  // Voice Biometrics Button Styles
  setupButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#E0E0E0',
    height: 48,
    borderRadius: 12,
    paddingHorizontal: 20,
    marginHorizontal: 32,
    marginTop: 24,
    borderWidth: 1.7,
    borderColor: '#0C0D11',
  },
  setupButtonActive: {
    backgroundColor: '#0C0D11',
    borderWidth: 1.7,
    borderColor: '#0C0D11',
  },
  setupButtonText: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
  },
  setupButtonTextActive: {
    color: '#F6F6F8',
  },
  // Signature Styles
  signatureContainer: {
    position: 'absolute',
    bottom: 20,
    left: 20,
  },
  signature: {
    fontSize: 100,
    fontWeight: 'bold',
    color: '#E0E0E0',
    opacity: 0.5,
  },
});