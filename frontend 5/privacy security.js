import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Platform,
  Animated,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';

// Standard Back Button Component
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

// Custom Toggle Component with smooth animation
const CustomToggle = ({ title, subtitle, value, onValueChange }) => {
  // `Animated.Value` to track the thumb position
  const thumbTranslateX = useRef(new Animated.Value(value ? 17 : 2)).current;

  // Animate the thumb position whenever the `value` prop changes
  useEffect(() => {
    Animated.timing(thumbTranslateX, {
      toValue: value ? 17 : 2,
      duration: 250, // Animation duration in milliseconds
      useNativeDriver: true, // Use native driver for better performance
    }).start();
  }, [value, thumbTranslateX]);

  // Animate the track color change
  const trackColor = thumbTranslateX.interpolate({
    inputRange: [2, 17],
    outputRange: ['rgba(120, 120, 128, 0.16)', '#FFA364'],
  });

  return (
    <View style={styles.toggleContainer}>
      <View style={styles.toggleContent}>
        <View style={styles.toggleTextContainer}>
          <Text style={styles.toggleTitle}>{title}</Text>
          {subtitle && <Text style={styles.toggleSubtitle}>{subtitle}</Text>}
        </View>
        <TouchableOpacity
          style={[
            styles.toggleTrack,
            { backgroundColor: trackColor }
          ]}
          onPress={() => onValueChange(!value)}
        >
          {/* Use `Animated.View` to apply the animation */}
          <Animated.View style={[
            styles.toggleThumb,
            { transform: [{ translateX: thumbTranslateX }] }
          ]} />
        </TouchableOpacity>
      </View>
    </View>
  );
};

// Custom Checkbox Component
const CustomCheckbox = ({ label, checked, onToggle }) => {
  return (
    <TouchableOpacity style={styles.checkboxContainer} onPress={onToggle}>
      <View style={[styles.checkbox, checked && styles.checkboxChecked]}>
        {checked && (
          <Svg width={12} height={9} viewBox="0 0 12 9" fill="none">
            <Path
              d="M1 4.5L4.5 8L11 1"
              stroke="#000000"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        )}
      </View>
      <Text style={styles.checkboxLabel}>{label}</Text>
    </TouchableOpacity>
  );
};

// Custom Dropdown Component
const CustomDropdown = ({ label, value, options, onSelect, subtitle }) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <View style={styles.dropdownContainer}>
      <Text style={styles.dropdownLabel}>{label}</Text>
      <TouchableOpacity
        style={[styles.dropdownButton, isOpen && styles.dropdownButtonOpen]}
        onPress={() => setIsOpen(!isOpen)}
      >
        <Text style={styles.dropdownText}>{value}</Text>
        <Svg
          width={14}
          height={6}
          viewBox="0 0 14 8"
          fill="none"
          style={[styles.dropdownIcon, isOpen && styles.dropdownIconOpen]}
        >
          <Path
            d="M1 1L7 7L13 1"
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
                option === value && styles.dropdownOptionSelected
              ]}
              onPress={() => {
                onSelect(option);
                setIsOpen(false);
              }}
            >
              <Text style={[
                styles.dropdownOptionText,
                option === value && styles.dropdownOptionTextSelected
              ]}>
                {option}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      )}
      {subtitle && <Text style={styles.dropdownSubtitle}>{subtitle}</Text>}
    </View>
  );
};

// List Item Component
const ListItem = ({ title, onPress }) => {
  return (
    <TouchableOpacity style={styles.listItem} onPress={onPress}>
      <Text style={styles.listItemTitle}>{title}</Text>
      <Svg width={8} height={14} viewBox="0 0 8 14" fill="none">
        <Path
          d="M1 13L7 7L1 1"
          stroke="black"
          strokeWidth="1.7"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </Svg>
    </TouchableOpacity>
  );
};

export default function PrivacySecurity() {
  const navigation = useNavigation();

  // State management
  const [endToEndEncryption, setEndToEndEncryption] = useState(true);
  const [usageDataCollection, setUsageDataCollection] = useState(true);
  const [aiPersonalization, setAiPersonalization] = useState(true);
  const [analyticsImprovement, setAnalyticsImprovement] = useState(false);
  const [twoFactorAuth, setTwoFactorAuth] = useState(false);
  const [wipeMemory, setWipeMemory] = useState(false);
  const [sessionExpiry, setSessionExpiry] = useState('5 min');
  const [autoLock, setAutoLock] = useState(false);

  const sessionOptions = ['5 min', '10 min', 'Never'];

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Privacy & Security</Text>
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* End to End Encryption */}
        <CustomToggle
          title="End to End Encryption"
          subtitle="Your messages are secured using AES-256 encryption."
          value={endToEndEncryption}
          onValueChange={setEndToEndEncryption}
        />

        {/* Consent Management */}
        <View style={styles.sectionContainer}>
          <Text style={styles.sectionTitle}>Consent Management</Text>
          <View style={styles.checkboxGroup}>
            <CustomCheckbox
              label="Allow usage data collection"
              checked={usageDataCollection}
              onToggle={() => setUsageDataCollection(!usageDataCollection)}
            />
            <CustomCheckbox
              label="Allow AI personalization"
              checked={aiPersonalization}
              onToggle={() => setAiPersonalization(!aiPersonalization)}
            />
            <CustomCheckbox
              label="Allow analytics for improvement"
              checked={analyticsImprovement}
              onToggle={() => setAnalyticsImprovement(!analyticsImprovement)}
            />
          </View>
        </View>

        {/* Two Factor Authentication */}
        <CustomToggle
          title="Two Factor Authentication"
          subtitle="Enable two-factor authentication for enhanced security."
          value={twoFactorAuth}
          onValueChange={setTwoFactorAuth}
        />

        {/* Wipe Memory */}
        <CustomToggle
          title="Wipe Memory"
          subtitle="This will permanently delete your AI history and memory"
          value={wipeMemory}
          onValueChange={setWipeMemory}
        />

        {/* Session Expiry */}
        <CustomDropdown
          label="Session Expiry"
          value={sessionExpiry}
          options={sessionOptions}
          onSelect={setSessionExpiry}
          subtitle="This will permanently delete your AI history and memory"
        />

        {/* Auto Lock */}
        <CustomToggle
          title="Auto Lock"
          subtitle="Automatically lock the app after a period of inactivity."
          value={autoLock}
          onValueChange={setAutoLock}
        />

        {/* Blockchain Identity */}
        <ListItem
          title="Blockchain Identity"
          onPress={() => navigation.navigate('Blockchain')}
        />
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
    paddingTop: 44,
    paddingHorizontal: 20,
    paddingBottom: 4,
    marginBottom: 20,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
  },
  scrollContent: {
    paddingBottom: 200,
  },

  // Toggle Styles
  toggleContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
  },
  toggleContent: {
    backgroundColor: '#FFFFFF',
  },
  toggleTextContainer: {
    marginBottom: 12,
  },
  toggleTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
    marginBottom: 4,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  toggleSubtitle: {
    fontSize: 10,
    fontWeight: '400',
    color: '#787878',
    fontFamily: 'Poppins',
    lineHeight: 14,
    marginTop: 4,
  },
  toggleTrack: {
    position: 'absolute',
    right: 0,
    top: 0,
    width: 38,
    height: 23,
    borderRadius: 75,
    backgroundColor: 'rgba(120, 120, 128, 0.16)',
    justifyContent: 'center',
  },
  toggleThumb: {
    position: 'absolute',
    left: 2,
    top: 2,
    width: 19,
    height: 19,
    borderRadius: 75,
    backgroundColor: '#FFFFFF',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2.25 },
    shadowOpacity: 0.06,
    shadowRadius: 0.75,
    elevation: 2,
  },

  // Section Styles
  sectionContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
    marginBottom: 16,
  },

  // Checkbox Styles
  checkboxGroup: {
    gap: 12,
  },
  checkboxContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: '#2C2C2C',
    borderRadius: 12,
  },
  checkbox: {
    width: 20,
    height: 20,
    borderWidth: 1,
    borderColor: '#2C2C2C',
    borderRadius: 6,
    marginRight: 8,
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkboxChecked: {
    backgroundColor: '#FF8A3D',
    borderColor: '#FF8A3D'
  },
  checkboxLabel: {
    fontSize: 12,
    fontWeight: '500',
    color: '#2C2C2C',
    fontFamily: 'Poppins',
    flex: 1,
  },

  // Dropdown Styles
  dropdownContainer: {
    paddingHorizontal: 32,
    marginBottom: 24,
  },
  dropdownLabel: {
    fontSize: 16,
    fontWeight: '500',
    color: '#0E0E0E',
    fontFamily: 'Poppins',
    marginBottom: 6,
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
    backgroundColor: '#FFFFFF',
  },
  dropdownOptionSelected: {
    backgroundColor: 'rgba(255, 138, 61, 0.2)',
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

  // Styles for the back button
  navIconsBackContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 36,
    width: 36,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
  },
  vector: {
    position: 'absolute',
    flexShrink: 0,
    top: 12,
    right: 21,
    bottom: 12,
    left: 9,
    overflow: 'visible',
  },
});